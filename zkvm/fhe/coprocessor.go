// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/platformvm/warp"
	"github.com/luxfi/node/vms/platformvm/warp/payload"
)

// OpCode represents an FHE operation code
type OpCode uint8

const (
	OpAdd OpCode = iota
	OpSub
	OpMul
	OpNeg
	OpLt
	OpGt
	OpLte
	OpGte
	OpEq
	OpNe
	OpNot
	OpAnd
	OpOr
	OpXor
	OpSelect
	OpMin
	OpMax
	OpShl
	OpShr
	OpEncrypt
	OpDecrypt
	OpVerifyInput
)

// String returns the operation name
func (op OpCode) String() string {
	names := []string{
		"add", "sub", "mul", "neg",
		"lt", "gt", "lte", "gte", "eq", "ne",
		"not", "and", "or", "xor",
		"select", "min", "max", "shl", "shr",
		"encrypt", "decrypt", "verify_input",
	}
	if int(op) < len(names) {
		return names[op]
	}
	return "unknown"
}

// Task represents an FHE computation task submitted to the coprocessor
type Task struct {
	// ID is a unique task identifier
	ID [32]byte

	// Op is the operation to perform
	Op OpCode

	// Inputs are handles to input ciphertexts
	Inputs [][32]byte

	// ScalarInputs are plaintext scalar inputs (for mul_plain, shl, etc.)
	ScalarInputs []uint64

	// ResultType is the expected result type
	ResultType EncryptedType

	// Requester is the C-Chain contract that submitted this task
	Requester [20]byte

	// SourceChain is the chain that submitted this task
	SourceChain ids.ID

	// Callback is the function to call with the result
	Callback         [20]byte
	CallbackSelector [4]byte

	// Submitted is when the task was created
	Submitted time.Time

	// Status is the current task status
	Status TaskStatus

	// Result is the output handle (set when completed)
	Result [32]byte

	// Error is set if the task failed
	Error string
}

// TaskStatus represents the status of a task
type TaskStatus uint8

const (
	TaskPending TaskStatus = iota
	TaskProcessing
	TaskCompleted
	TaskFailed
)

// WarpCallback handles sending results back via Warp messaging
type WarpCallback struct {
	logger    log.Logger
	networkID uint32
	chainID   ids.ID
	signer    warp.Signer
	onMessage func(context.Context, *warp.Message) error
}

// NewWarpCallback creates a new Warp callback handler
func NewWarpCallback(
	logger log.Logger,
	networkID uint32,
	chainID ids.ID,
	signer warp.Signer,
	onMessage func(context.Context, *warp.Message) error,
) *WarpCallback {
	return &WarpCallback{
		logger:    logger,
		networkID: networkID,
		chainID:   chainID,
		signer:    signer,
		onMessage: onMessage,
	}
}

// SendTaskResult sends a task result back to the source chain
func (w *WarpCallback) SendTaskResult(ctx context.Context, task *Task) error {
	if w.onMessage == nil {
		return nil
	}

	// Encode callback data
	data := encodeTaskCallback(task)

	// Create addressed call to the callback contract
	addressedCall, err := payload.NewAddressedCall(task.Callback[:], data)
	if err != nil {
		return fmt.Errorf("create addressed call: %w", err)
	}

	// Create unsigned warp message
	unsignedMsg, err := warp.NewUnsignedMessage(
		w.networkID,
		w.chainID,
		addressedCall.Bytes(),
	)
	if err != nil {
		return fmt.Errorf("create unsigned message: %w", err)
	}

	// Sign the message
	sigBytes, err := w.signer.Sign(unsignedMsg)
	if err != nil {
		return fmt.Errorf("sign warp message: %w", err)
	}

	// Convert signature bytes to fixed-size array
	var sig [96]byte
	copy(sig[:], sigBytes)

	// Create BitSetSignature
	bitSetSig := &warp.BitSetSignature{
		Signers:   []byte{0x01},
		Signature: sig,
	}

	// Create final signed message
	msg, err := warp.NewMessage(unsignedMsg, bitSetSig)
	if err != nil {
		return fmt.Errorf("create warp message: %w", err)
	}

	// Send via message handler
	if err := w.onMessage(ctx, msg); err != nil {
		return fmt.Errorf("send warp message: %w", err)
	}

	w.logger.Info("Sent task result via Warp",
		"taskID", fmt.Sprintf("%x", task.ID[:8]),
		"callback", fmt.Sprintf("%x", task.Callback),
		"success", task.Status == TaskCompleted,
	)

	return nil
}

// encodeTaskCallback creates ABI-encoded callback data
func encodeTaskCallback(task *Task) []byte {
	// callback(bytes32 taskId, bool success, bytes32 resultHandle)
	// Selector + taskId + success + resultHandle
	data := make([]byte, 4+32+32+32)

	// Copy selector
	copy(data[0:4], task.CallbackSelector[:])

	// Copy task ID
	copy(data[4:36], task.ID[:])

	// Success flag (padded to 32 bytes)
	if task.Status == TaskCompleted {
		data[67] = 1
	}

	// Copy result handle
	copy(data[68:100], task.Result[:])

	return data
}

// Coprocessor is the FHE computation coprocessor
// It receives tasks from C-Chain, computes on Z-Chain, and returns results
type Coprocessor struct {
	processor    *Processor
	warpCallback *WarpCallback
	logger       log.Logger

	// Task queue
	pending   chan *Task
	completed map[[32]byte]*Task
	mu        sync.RWMutex

	// Configuration
	maxQueueSize int
	workerCount  int

	// Metrics
	tasksProcessed uint64
	tasksCompleted uint64
	tasksFailed    uint64

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewCoprocessor creates a new FHE coprocessor
func NewCoprocessor(processor *Processor, logger log.Logger, maxQueueSize, workerCount int) *Coprocessor {
	ctx, cancel := context.WithCancel(context.Background())

	return &Coprocessor{
		processor:    processor,
		logger:       logger,
		pending:      make(chan *Task, maxQueueSize),
		completed:    make(map[[32]byte]*Task),
		maxQueueSize: maxQueueSize,
		workerCount:  workerCount,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// SetWarpCallback sets the Warp callback handler for sending results
func (c *Coprocessor) SetWarpCallback(callback *WarpCallback) {
	c.warpCallback = callback
}

// Start starts the coprocessor workers
func (c *Coprocessor) Start() {
	for i := 0; i < c.workerCount; i++ {
		c.wg.Add(1)
		go c.worker(i)
	}
	c.logger.Info("FHE Coprocessor started", "workers", c.workerCount)
}

// Stop stops the coprocessor
func (c *Coprocessor) Stop() {
	c.cancel()
	c.wg.Wait()
	c.logger.Info("FHE Coprocessor stopped")
}

// SubmitTask submits a task for processing
func (c *Coprocessor) SubmitTask(task *Task) error {
	select {
	case c.pending <- task:
		return nil
	default:
		return errors.New("task queue full")
	}
}

// GetTaskResult retrieves a completed task result
func (c *Coprocessor) GetTaskResult(taskID [32]byte) (*Task, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	task, ok := c.completed[taskID]
	if !ok {
		return nil, errors.New("task not found")
	}
	return task, nil
}

// CreateTask creates a new task with a unique ID
func (c *Coprocessor) CreateTask(op OpCode, inputs [][32]byte, scalars []uint64, resultType EncryptedType) *Task {
	// Generate task ID
	h := sha256.New()
	h.Write([]byte{byte(op)})
	for _, input := range inputs {
		h.Write(input[:])
	}
	for _, scalar := range scalars {
		binary.Write(h, binary.BigEndian, scalar)
	}
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())

	var id [32]byte
	copy(id[:], h.Sum(nil))

	return &Task{
		ID:           id,
		Op:           op,
		Inputs:       inputs,
		ScalarInputs: scalars,
		ResultType:   resultType,
		Submitted:    time.Now(),
		Status:       TaskPending,
	}
}

// worker processes tasks from the queue
func (c *Coprocessor) worker(id int) {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case task := <-c.pending:
			c.processTask(task)
		}
	}
}

// processTask executes a single task
func (c *Coprocessor) processTask(task *Task) {
	task.Status = TaskProcessing
	c.tasksProcessed++

	var result *Ciphertext
	var err error

	// Get input ciphertexts
	inputs := make([]*Ciphertext, len(task.Inputs))
	for i, handle := range task.Inputs {
		inputs[i], err = c.processor.GetCiphertext(handle)
		if err != nil {
			c.completeTask(task, nil, fmt.Errorf("input %d not found: %w", i, err))
			return
		}
	}

	// Execute operation
	switch task.Op {
	case OpAdd:
		if len(inputs) != 2 {
			err = errors.New("add requires 2 inputs")
		} else {
			result, err = c.processor.Add(inputs[0], inputs[1])
		}

	case OpSub:
		if len(inputs) != 2 {
			err = errors.New("sub requires 2 inputs")
		} else {
			result, err = c.processor.Sub(inputs[0], inputs[1])
		}

	case OpMul:
		if len(inputs) == 2 {
			result, err = c.processor.Mul(inputs[0], inputs[1])
		} else if len(inputs) == 1 && len(task.ScalarInputs) == 1 {
			result, err = c.processor.MulPlain(inputs[0], task.ScalarInputs[0])
		} else {
			err = errors.New("mul requires 2 ciphertext inputs or 1 ciphertext + 1 scalar")
		}

	case OpNeg:
		if len(inputs) != 1 {
			err = errors.New("neg requires 1 input")
		} else {
			result, err = c.processor.Neg(inputs[0])
		}

	case OpLt:
		if len(inputs) != 2 {
			err = errors.New("lt requires 2 inputs")
		} else {
			result, err = c.processor.Lt(inputs[0], inputs[1])
		}

	case OpGt:
		if len(inputs) != 2 {
			err = errors.New("gt requires 2 inputs")
		} else {
			result, err = c.processor.Gt(inputs[0], inputs[1])
		}

	case OpLte:
		if len(inputs) != 2 {
			err = errors.New("lte requires 2 inputs")
		} else {
			result, err = c.processor.Lte(inputs[0], inputs[1])
		}

	case OpGte:
		if len(inputs) != 2 {
			err = errors.New("gte requires 2 inputs")
		} else {
			result, err = c.processor.Gte(inputs[0], inputs[1])
		}

	case OpEq:
		if len(inputs) != 2 {
			err = errors.New("eq requires 2 inputs")
		} else {
			result, err = c.processor.Eq(inputs[0], inputs[1])
		}

	case OpNe:
		if len(inputs) != 2 {
			err = errors.New("ne requires 2 inputs")
		} else {
			result, err = c.processor.Ne(inputs[0], inputs[1])
		}

	case OpNot:
		if len(inputs) != 1 {
			err = errors.New("not requires 1 input")
		} else {
			result, err = c.processor.Not(inputs[0])
		}

	case OpAnd:
		if len(inputs) != 2 {
			err = errors.New("and requires 2 inputs")
		} else {
			result, err = c.processor.And(inputs[0], inputs[1])
		}

	case OpOr:
		if len(inputs) != 2 {
			err = errors.New("or requires 2 inputs")
		} else {
			result, err = c.processor.Or(inputs[0], inputs[1])
		}

	case OpXor:
		if len(inputs) != 2 {
			err = errors.New("xor requires 2 inputs")
		} else {
			result, err = c.processor.Xor(inputs[0], inputs[1])
		}

	case OpSelect:
		if len(inputs) != 3 {
			err = errors.New("select requires 3 inputs (condition, ifTrue, ifFalse)")
		} else {
			result, err = c.processor.Select(inputs[0], inputs[1], inputs[2])
		}

	case OpMin:
		if len(inputs) != 2 {
			err = errors.New("min requires 2 inputs")
		} else {
			result, err = c.processor.Min(inputs[0], inputs[1])
		}

	case OpMax:
		if len(inputs) != 2 {
			err = errors.New("max requires 2 inputs")
		} else {
			result, err = c.processor.Max(inputs[0], inputs[1])
		}

	case OpShl:
		if len(inputs) != 1 || len(task.ScalarInputs) != 1 {
			err = errors.New("shl requires 1 ciphertext and 1 scalar")
		} else {
			result, err = c.processor.Shl(inputs[0], uint(task.ScalarInputs[0]))
		}

	case OpShr:
		if len(inputs) != 1 || len(task.ScalarInputs) != 1 {
			err = errors.New("shr requires 1 ciphertext and 1 scalar")
		} else {
			result, err = c.processor.Shr(inputs[0], uint(task.ScalarInputs[0]))
		}

	default:
		err = fmt.Errorf("unknown operation: %d", task.Op)
	}

	c.completeTask(task, result, err)
}

// completeTask marks a task as complete and stores the result
func (c *Coprocessor) completeTask(task *Task, result *Ciphertext, err error) {
	if err != nil {
		task.Status = TaskFailed
		task.Error = err.Error()
		c.tasksFailed++
		c.logger.Error("Task failed",
			"taskID", fmt.Sprintf("%x", task.ID[:8]),
			"op", task.Op.String(),
			"error", err,
		)
	} else {
		task.Status = TaskCompleted
		task.Result = result.Handle
		c.tasksCompleted++
		c.logger.Debug("Task completed",
			"taskID", fmt.Sprintf("%x", task.ID[:8]),
			"op", task.Op.String(),
			"result", fmt.Sprintf("%x", task.Result[:8]),
		)
	}

	c.mu.Lock()
	c.completed[task.ID] = task
	c.mu.Unlock()

	// Send callback to C-Chain via Warp messaging
	if c.warpCallback != nil && task.Callback != [20]byte{} {
		if err := c.warpCallback.SendTaskResult(c.ctx, task); err != nil {
			c.logger.Error("Failed to send Warp callback", "error", err)
		}
	}
}

// Stats returns coprocessor statistics
func (c *Coprocessor) Stats() (processed, completed, failed uint64, queueLen int) {
	return c.tasksProcessed, c.tasksCompleted, c.tasksFailed, len(c.pending)
}

// TaskRequest is the cross-chain message format for submitting tasks
type TaskRequest struct {
	// SourceChain is the chain that submitted the request
	SourceChain ids.ID

	// RequestID is unique within the source chain
	RequestID uint64

	// Op is the FHE operation
	Op OpCode

	// InputHandles are ciphertext handles
	InputHandles [][32]byte

	// ScalarInputs for operations that need them
	ScalarInputs []uint64

	// ResultType is the expected output type
	ResultType EncryptedType

	// Callback information
	CallbackContract [20]byte
	CallbackSelector [4]byte
}

// TaskResponse is the cross-chain response format
type TaskResponse struct {
	// RequestID matches the original request
	RequestID uint64

	// Success indicates if the operation succeeded
	Success bool

	// ResultHandle is the ciphertext handle (if success)
	ResultHandle [32]byte

	// Error message (if not success)
	Error string
}

// HandleCrossChainRequest processes a task request from C-Chain
func (c *Coprocessor) HandleCrossChainRequest(req *TaskRequest) *TaskResponse {
	task := c.CreateTask(req.Op, req.InputHandles, req.ScalarInputs, req.ResultType)
	task.Callback = req.CallbackContract
	task.CallbackSelector = req.CallbackSelector
	task.SourceChain = req.SourceChain

	if err := c.SubmitTask(task); err != nil {
		return &TaskResponse{
			RequestID: req.RequestID,
			Success:   false,
			Error:     err.Error(),
		}
	}

	// Synchronous wait; async Warp callback not yet wired
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return &TaskResponse{
				RequestID: req.RequestID,
				Success:   false,
				Error:     "timeout waiting for task completion",
			}
		case <-ticker.C:
			result, err := c.GetTaskResult(task.ID)
			if err == nil {
				if result.Status == TaskCompleted {
					return &TaskResponse{
						RequestID:    req.RequestID,
						Success:      true,
						ResultHandle: result.Result,
					}
				} else if result.Status == TaskFailed {
					return &TaskResponse{
						RequestID: req.RequestID,
						Success:   false,
						Error:     result.Error,
					}
				}
			}
		}
	}
}
