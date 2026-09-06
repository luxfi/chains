// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Q-Chain Quantum Stamper for C-Chain Block Replay
// Implements Crystal-Dilithium (ML-DSA) and SPHINCS+ (SLH-DSA) for post-quantum security

package stamper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/accel"
	"github.com/luxfi/cache"
	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/log"
)

var (
	ErrStampingDisabled      = errors.New("quantum stamping disabled")
	ErrInvalidBlockHeight    = errors.New("invalid block height")
	ErrStampAlreadyExists    = errors.New("quantum stamp already exists")
	ErrStampVerificationFail = errors.New("quantum stamp verification failed")
	ErrQChainNotSynced       = errors.New("Q-chain not synchronized")
	ErrInvalidSignatureMode  = errors.New("invalid signature mode")
)

// QuantumStampMode defines the post-quantum signature algorithm
type QuantumStampMode uint8

const (
	StampModeMLDSA44 QuantumStampMode = 0 // Crystal-Dilithium Level 2 (fast, smaller)
	StampModeMLDSA65 QuantumStampMode = 1 // Crystal-Dilithium Level 3 (balanced)
	StampModeMLDSA87 QuantumStampMode = 2 // Crystal-Dilithium Level 5 (highest security)
	StampModeSLHDSA  QuantumStampMode = 3 // SPHINCS+ (stateless hash-based)
	StampModeHybrid  QuantumStampMode = 4 // Hybrid ML-DSA + SLH-DSA
)

// QuantumStamp represents a quantum-resistant stamp for a C-Chain block
type QuantumStamp struct {
	// Block identification
	CChainHeight uint64      `json:"cchainHeight"`
	CChainHash   common.Hash `json:"cchainHash"`
	QChainHeight uint64      `json:"qchainHeight"`
	QChainHash   common.Hash `json:"qchainHash"`

	// Quantum signature data
	Mode            QuantumStampMode `json:"mode"`
	Timestamp       time.Time        `json:"timestamp"`
	MLDSASignature  []byte           `json:"mldsaSignature,omitempty"`
	SLHDSASignature []byte           `json:"slhdsaSignature,omitempty"`
	PublicKeyML     []byte           `json:"publicKeyML,omitempty"`
	PublicKeySLH    []byte           `json:"publicKeySLH,omitempty"`

	// Metadata
	StateRoot    common.Hash `json:"stateRoot"`
	ReceiptsRoot common.Hash `json:"receiptsRoot"`
	LogsBloom    []byte      `json:"logsBloom"`
	GasUsed      uint64      `json:"gasUsed"`

	// Cross-chain proof
	MerkleProof []common.Hash `json:"merkleProof,omitempty"`
	Nonce       []byte        `json:"nonce"`
}

// QuantumStamper handles quantum stamping of C-Chain blocks
type QuantumStamper struct {
	log     log.Logger
	enabled atomic.Bool
	mode    QuantumStampMode

	// Quantum signers
	mldsaSigner   *MLDSASigner
	slhdsaSigner  *SLHDSASigner
	quantumSigner *quantum.QuantumSigner

	// Block tracking
	cchainHeight atomic.Uint64
	qchainHeight atomic.Uint64
	stampCache   *cache.LRU[common.Hash, *QuantumStamp]

	// Synchronization
	mu          sync.RWMutex
	stampQueue  chan *stampRequest
	verifyQueue chan *verifyRequest

	// Metrics
	stampsCreated  atomic.Uint64
	stampsVerified atomic.Uint64
	stampsFailed   atomic.Uint64
}

type stampRequest struct {
	block    *types.Block
	response chan *QuantumStamp
	err      chan error
}

type verifyRequest struct {
	stamp    *QuantumStamp
	block    *types.Block
	response chan bool
}

// MLDSASigner wraps ML-DSA operations
type MLDSASigner struct {
	mode    mldsa.Mode
	privKey *mldsa.PrivateKey
	pubKey  *mldsa.PublicKey
}

// SLHDSASigner wraps SLH-DSA operations
type SLHDSASigner struct {
	mode    slhdsa.Mode
	privKey *slhdsa.PrivateKey
	pubKey  *slhdsa.PublicKey
}

// NewQuantumStamper creates a new quantum stamper for C-Chain blocks
func NewQuantumStamper(log log.Logger, mode QuantumStampMode, cacheSize int) (*QuantumStamper, error) {
	qs := &QuantumStamper{
		log:         log,
		mode:        mode,
		stampCache:  &cache.LRU[common.Hash, *QuantumStamp]{Size: cacheSize},
		stampQueue:  make(chan *stampRequest, 100),
		verifyQueue: make(chan *verifyRequest, 100),
	}

	// Initialize quantum signers based on mode
	if err := qs.initializeSigners(); err != nil {
		return nil, fmt.Errorf("failed to initialize signers: %w", err)
	}

	// Initialize Corona quantum signer for additional security
	qs.quantumSigner = quantum.NewQuantumSigner(log, 1, 256, 5*time.Minute, cacheSize)

	// Start worker goroutines
	go qs.stampWorker()
	go qs.verifyWorker()

	qs.enabled.Store(true)
	log.Info("Quantum stamper initialized",
		"mode", mode,
		"cacheSize", cacheSize)

	return qs, nil
}

// initializeSigners creates the cryptographic signers based on mode
// mldsaMode is the ONE statement of which ML-DSA parameter set a stamp mode
// means. The signer and the verifier both read it, so a stamp can only ever be
// checked against the parameter set it was made under. Stating it twice is what
// let the verifier reconstruct every public key as ML-DSA-65 while the signer
// issued 44 and 87 keys, and a node then refused stamps it had just written.
// The second result is false for modes that carry no ML-DSA signature at all.
func (m QuantumStampMode) mldsaMode() (mldsa.Mode, bool) {
	switch m {
	case StampModeMLDSA44:
		return mldsa.MLDSA44, true
	case StampModeMLDSA65, StampModeHybrid:
		return mldsa.MLDSA65, true
	case StampModeMLDSA87:
		return mldsa.MLDSA87, true
	default:
		return 0, false
	}
}

// slhdsaMode is the same statement for the hash-based leg.
func (m QuantumStampMode) slhdsaMode() (slhdsa.Mode, bool) {
	switch m {
	case StampModeSLHDSA, StampModeHybrid:
		return slhdsa.SHA2_128f, true
	default:
		return 0, false
	}
}

func (qs *QuantumStamper) initializeSigners() error {
	ml, hasML := qs.mode.mldsaMode()
	slh, hasSLH := qs.mode.slhdsaMode()
	if !hasML && !hasSLH {
		return ErrInvalidSignatureMode
	}
	if hasML {
		if err := qs.initMLDSA(ml); err != nil {
			return err
		}
	}
	if hasSLH {
		if err := qs.initSLHDSA(slh); err != nil {
			return err
		}
	}
	return nil
}

func (qs *QuantumStamper) initMLDSA(mode mldsa.Mode) error {
	priv, err := mldsa.GenerateKey(rand.Reader, mode)
	if err != nil {
		return fmt.Errorf("failed to generate ML-DSA key: %w", err)
	}

	qs.mldsaSigner = &MLDSASigner{
		mode:    mode,
		privKey: priv,
		pubKey:  priv.PublicKey,
	}

	qs.log.Info("ML-DSA signer initialized", "mode", mode)
	return nil
}

func (qs *QuantumStamper) initSLHDSA(mode slhdsa.Mode) error {
	priv, err := slhdsa.GenerateKey(rand.Reader, mode)
	if err != nil {
		return fmt.Errorf("failed to generate SLH-DSA key: %w", err)
	}

	qs.slhdsaSigner = &SLHDSASigner{
		mode:    mode,
		privKey: priv,
		pubKey:  priv.PublicKey,
	}

	qs.log.Info("SLH-DSA signer initialized", "mode", mode)
	return nil
}

// StampBlock creates a quantum stamp for a C-Chain block during replay
func (qs *QuantumStamper) StampBlock(block *types.Block) (*QuantumStamp, error) {
	if !qs.enabled.Load() {
		return nil, ErrStampingDisabled
	}

	// Check cache first
	blockHash := block.Hash()
	if cached, found := qs.stampCache.Get(blockHash); found {
		return cached, nil
	}

	// Create stamp request
	req := &stampRequest{
		block:    block,
		response: make(chan *QuantumStamp, 1),
		err:      make(chan error, 1),
	}

	select {
	case qs.stampQueue <- req:
		select {
		case stamp := <-req.response:
			return stamp, nil
		case err := <-req.err:
			return nil, err
		case <-time.After(30 * time.Second):
			return nil, errors.New("stamping timeout")
		}
	case <-time.After(5 * time.Second):
		return nil, errors.New("stamp queue full")
	}
}

// stampWorker processes stamp requests
func (qs *QuantumStamper) stampWorker() {
	for req := range qs.stampQueue {
		stamp, err := qs.createStamp(req.block)
		if err != nil {
			req.err <- err
		} else {
			req.response <- stamp
		}
	}
}

// createStamp creates the actual quantum stamp
func (qs *QuantumStamper) createStamp(block *types.Block) (*QuantumStamp, error) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	blockHeight := block.NumberU64()
	blockHash := block.Hash()

	// Update C-Chain height
	qs.cchainHeight.Store(blockHeight)

	// Calculate Q-Chain height (synchronized with C-Chain)
	qHeight := qs.calculateQChainHeight(blockHeight)
	qs.qchainHeight.Store(qHeight)

	// Create stamp data
	stamp := &QuantumStamp{
		CChainHeight: blockHeight,
		CChainHash:   blockHash,
		QChainHeight: qHeight,
		Mode:         qs.mode,
		Timestamp:    time.Now(),
		StateRoot:    block.Root(),
		ReceiptsRoot: block.ReceiptHash(),
		GasUsed:      block.GasUsed(),
		Nonce:        generateNonce(),
	}

	// Set logs bloom (limited to 256 bytes for efficiency)
	bloomBytes := block.Bloom().Bytes()
	if len(bloomBytes) > 256 {
		stamp.LogsBloom = bloomBytes[:256]
	} else {
		stamp.LogsBloom = bloomBytes
	}

	// Generate Q-Chain block hash
	stamp.QChainHash = qs.generateQChainHash(stamp)

	// Create signatures based on mode
	signData := qs.prepareSignatureData(stamp)

	switch qs.mode {
	case StampModeMLDSA44, StampModeMLDSA65, StampModeMLDSA87:
		if err := qs.signWithMLDSA(stamp, signData); err != nil {
			return nil, err
		}
	case StampModeSLHDSA:
		if err := qs.signWithSLHDSA(stamp, signData); err != nil {
			return nil, err
		}
	case StampModeHybrid:
		if err := qs.signWithMLDSA(stamp, signData); err != nil {
			return nil, err
		}
		if err := qs.signWithSLHDSA(stamp, signData); err != nil {
			return nil, err
		}
	}

	// Cache the stamp
	qs.stampCache.Put(blockHash, stamp)
	qs.stampsCreated.Add(1)

	// Log progress every 1000 blocks
	if blockHeight%1000 == 0 {
		qs.log.Info("Quantum stamping progress",
			"cchainHeight", blockHeight,
			"qchainHeight", qHeight,
			"totalStamped", qs.stampsCreated.Load())
	}

	return stamp, nil
}

// calculateQChainHeight determines Q-Chain height based on C-Chain height
func (qs *QuantumStamper) calculateQChainHeight(cchainHeight uint64) uint64 {
	// Q-Chain maintains 1:1 correspondence with C-Chain during replay
	// But starts from block 1 (genesis is block 0)
	return cchainHeight + 1
}

// generateQChainHash creates a quantum-enhanced hash for Q-Chain block
func (qs *QuantumStamper) generateQChainHash(stamp *QuantumStamp) common.Hash {
	hasher := sha256.New()

	// Include C-Chain reference
	hasher.Write(stamp.CChainHash.Bytes())
	binary.Write(hasher, binary.BigEndian, stamp.CChainHeight)

	// Include Q-Chain data
	binary.Write(hasher, binary.BigEndian, stamp.QChainHeight)
	hasher.Write(stamp.StateRoot.Bytes())
	hasher.Write(stamp.ReceiptsRoot.Bytes())
	hasher.Write(stamp.Nonce)

	// Add timestamp for temporal ordering
	binary.Write(hasher, binary.BigEndian, stamp.Timestamp.UnixNano())

	sum := hasher.Sum(nil)
	return common.BytesToHash(sum)
}

// prepareSignatureData creates the data to be signed
func (qs *QuantumStamper) prepareSignatureData(stamp *QuantumStamp) []byte {
	data := make([]byte, 0, 512)

	// Core block data
	data = append(data, stamp.CChainHash.Bytes()...)
	data = append(data, stamp.QChainHash.Bytes()...)

	// Heights
	heightBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(heightBytes[:8], stamp.CChainHeight)
	binary.BigEndian.PutUint64(heightBytes[8:], stamp.QChainHeight)
	data = append(data, heightBytes...)

	// State data
	data = append(data, stamp.StateRoot.Bytes()...)
	data = append(data, stamp.ReceiptsRoot.Bytes()...)

	// Gas and timestamp
	gasBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(gasBytes, stamp.GasUsed)
	data = append(data, gasBytes...)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(stamp.Timestamp.UnixNano()))
	data = append(data, timestampBytes...)

	// Nonce for uniqueness
	data = append(data, stamp.Nonce...)

	return data
}

// signWithMLDSA signs data using Crystal-Dilithium
func (qs *QuantumStamper) signWithMLDSA(stamp *QuantumStamp, data []byte) error {
	if qs.mldsaSigner == nil {
		return errors.New("ML-DSA signer not initialized")
	}

	signature, err := qs.mldsaSigner.privKey.Sign(rand.Reader, data, nil)
	if err != nil {
		return fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	stamp.MLDSASignature = signature
	stamp.PublicKeyML = qs.mldsaSigner.pubKey.Bytes()

	return nil
}

// signWithSLHDSA signs data using SPHINCS+
func (qs *QuantumStamper) signWithSLHDSA(stamp *QuantumStamp, data []byte) error {
	if qs.slhdsaSigner == nil {
		return errors.New("SLH-DSA signer not initialized")
	}

	signature, err := qs.slhdsaSigner.privKey.Sign(rand.Reader, data, nil)
	if err != nil {
		return fmt.Errorf("failed to sign with SLH-DSA: %w", err)
	}
	stamp.SLHDSASignature = signature
	stamp.PublicKeySLH = qs.slhdsaSigner.pubKey.Bytes()

	return nil
}

// VerifyStamp verifies a quantum stamp
func (qs *QuantumStamper) VerifyStamp(stamp *QuantumStamp, block *types.Block) bool {
	if !qs.enabled.Load() {
		return false
	}

	req := &verifyRequest{
		stamp:    stamp,
		block:    block,
		response: make(chan bool, 1),
	}

	select {
	case qs.verifyQueue <- req:
		select {
		case valid := <-req.response:
			return valid
		case <-time.After(10 * time.Second):
			return false
		}
	default:
		// Queue full, verify synchronously
		return qs.verifyStampSync(stamp, block)
	}
}

// verifyWorker processes verification requests
func (qs *QuantumStamper) verifyWorker() {
	for req := range qs.verifyQueue {
		valid := qs.verifyStampSync(req.stamp, req.block)
		req.response <- valid
	}
}

// stampMatchesBlock reports whether a stamp commits to exactly the C-Chain block
// it claims. It is the ONE definition of that correspondence: the sequential and
// the accelerated batch paths both call it, so an accelerated verification can
// never accept a field the sequential one refuses.
func stampMatchesBlock(stamp *QuantumStamp, block *types.Block) bool {
	return stamp.CChainHeight == block.NumberU64() &&
		stamp.CChainHash == block.Hash() &&
		stamp.StateRoot == block.Root() &&
		stamp.ReceiptsRoot == block.ReceiptHash() &&
		stamp.GasUsed == block.GasUsed()
}

// verifyStampSync performs synchronous stamp verification
func (qs *QuantumStamper) verifyStampSync(stamp *QuantumStamp, block *types.Block) bool {
	if !stampMatchesBlock(stamp, block) {
		return false
	}

	// Prepare signature data
	signData := qs.prepareSignatureData(stamp)

	// Verify signatures based on mode
	switch stamp.Mode {
	case StampModeMLDSA44, StampModeMLDSA65, StampModeMLDSA87:
		if !qs.verifyMLDSA(stamp, signData) {
			qs.stampsFailed.Add(1)
			return false
		}
	case StampModeSLHDSA:
		if !qs.verifySLHDSA(stamp, signData) {
			qs.stampsFailed.Add(1)
			return false
		}
	case StampModeHybrid:
		if !qs.verifyMLDSA(stamp, signData) || !qs.verifySLHDSA(stamp, signData) {
			qs.stampsFailed.Add(1)
			return false
		}
	default:
		return false
	}

	qs.stampsVerified.Add(1)
	return true
}

// verifyMLDSA verifies Crystal-Dilithium signature
func (qs *QuantumStamper) verifyMLDSA(stamp *QuantumStamp, data []byte) bool {
	if len(stamp.MLDSASignature) == 0 || len(stamp.PublicKeyML) == 0 {
		return false
	}

	mode, ok := stamp.Mode.mldsaMode()
	if !ok {
		return false
	}

	// Recreate public key from bytes
	pubKey, err := mldsa.PublicKeyFromBytes(stamp.PublicKeyML, mode)
	if err != nil {
		return false
	}

	return pubKey.Verify(data, stamp.MLDSASignature, nil)
}

// verifySLHDSA verifies SPHINCS+ signature
func (qs *QuantumStamper) verifySLHDSA(stamp *QuantumStamp, data []byte) bool {
	if len(stamp.SLHDSASignature) == 0 || len(stamp.PublicKeySLH) == 0 {
		return false
	}

	mode, ok := stamp.Mode.slhdsaMode()
	if !ok {
		return false
	}

	// Recreate public key from bytes
	pubKey, err := slhdsa.PublicKeyFromBytes(stamp.PublicKeySLH, mode)
	if err != nil {
		return false
	}

	return pubKey.Verify(data, stamp.SLHDSASignature, nil)
}

// VerifyStampBatch verifies a batch of quantum stamps using GPU acceleration
// when available, falling back to sequential CPU verification.
func (qs *QuantumStamper) VerifyStampBatch(stamps []*QuantumStamp, blocks []*types.Block) []bool {
	if len(stamps) != len(blocks) || len(stamps) == 0 {
		return nil
	}

	results := make([]bool, len(stamps))

	// Try GPU batch path for ML-DSA stamps
	if accel.Available() && len(stamps) >= accel.DilithiumBatchThreshold && qs.mldsaSigner != nil {
		plan := planBatch(stamps, blocks)
		if len(plan.batched) >= accel.DilithiumBatchThreshold &&
			qs.gpuBatchVerifyStamps(stamps, plan, results) {
			// Whatever the accelerator did not lay out still gets an answer, and
			// it is the same answer the sequential path would give.
			for _, i := range plan.sequential {
				results[i] = qs.verifyStampSync(stamps[i], blocks[i])
			}
			return results
		}
		// GPU failed, fall through to CPU
	}

	// CPU sequential fallback
	for i := range stamps {
		results[i] = qs.verifyStampSync(stamps[i], blocks[i])
	}
	return results
}

// batchPlan assigns every entry of a batch to exactly one decider. An entry the
// accelerator does not lay out is not thereby invalid, which is what the earlier
// shape got wrong: SLH-DSA stamps were skipped and left holding the zero value,
// so a valid hash-based stamp was refused whenever its batch happened to be big
// enough to reach the accelerator, and accepted whenever it was not.
type batchPlan struct {
	batched    []int      // decided by the accelerator, under mode
	sequential []int      // decided by verifyStampSync
	refused    []int      // decided false here: wrong block, or nothing to check
	mode       mldsa.Mode // parameter set the accelerator buffers are laid out for
}

// planBatch decides who verifies what. It takes no accelerator and touches no
// results, so the assignment can be checked on any machine.
//
// The accelerator copies signatures and keys into fixed strides, so one call
// carries one ML-DSA parameter set: the set of the first stamp that has one.
// A stamp under any other set is a stamp whose key does not fit the slot it
// would be written into, and goes to the sequential path instead.
func planBatch(stamps []*QuantumStamp, blocks []*types.Block) batchPlan {
	plan := batchPlan{}
	haveMode := false

	for i, stamp := range stamps {
		mode, carriesML := stamp.Mode.mldsaMode()
		if !carriesML {
			plan.sequential = append(plan.sequential, i)
			continue
		}
		// Block correspondence is the cheap half of the decision and does not
		// depend on which path checks the signature, so it is settled here for
		// both. It runs through the same predicate the sequential path uses.
		if !stampMatchesBlock(stamp, blocks[i]) {
			plan.refused = append(plan.refused, i)
			continue
		}
		if len(stamp.MLDSASignature) == 0 || len(stamp.PublicKeyML) == 0 {
			plan.refused = append(plan.refused, i)
			continue
		}
		if !haveMode {
			plan.mode, haveMode = mode, true
		}
		if mode != plan.mode {
			plan.sequential = append(plan.sequential, i)
			continue
		}
		plan.batched = append(plan.batched, i)
	}
	return plan
}

// gpuBatchVerifyStamps runs ML-DSA batch verification on GPU.
// Returns true if GPU path succeeded (results populated), false to fall back.
func (qs *QuantumStamper) gpuBatchVerifyStamps(stamps []*QuantumStamp, plan batchPlan, results []bool) bool {
	indices := plan.batched
	n := len(indices)

	signDataSlice := make([][]byte, 0, n)
	sigSlice := make([][]byte, 0, n)
	pkSlice := make([][]byte, 0, n)

	for _, i := range indices {
		signDataSlice = append(signDataSlice, qs.prepareSignatureData(stamps[i]))
		sigSlice = append(sigSlice, stamps[i].MLDSASignature)
		pkSlice = append(pkSlice, stamps[i].PublicKeyML)
	}

	sess, err := accel.NewSession()
	if err != nil {
		return false
	}
	defer sess.Close()

	latticeOps := sess.Lattice()

	// Fixed strides, for the one parameter set planBatch admitted into the batch.
	// Reading them off ML-DSA-65 while the batch held 44 or 87 keys wrote each
	// key past its own slot and into the next stamp's.
	sigSize := mldsa.GetSignatureSize(plan.mode)
	pkSize := mldsa.GetPublicKeySize(plan.mode)

	maxMsgLen := 0
	for _, d := range signDataSlice {
		if len(d) > maxMsgLen {
			maxMsgLen = len(d)
		}
	}

	batchN := len(signDataSlice)
	msgBuf := make([]uint8, batchN*maxMsgLen)
	sigBuf := make([]uint8, batchN*sigSize)
	pkBuf := make([]uint8, batchN*pkSize)

	for i := 0; i < batchN; i++ {
		copy(msgBuf[i*maxMsgLen:], signDataSlice[i])
		copy(sigBuf[i*sigSize:], sigSlice[i])
		copy(pkBuf[i*pkSize:], pkSlice[i])
	}

	msgT, err := accel.NewTensorWithData[uint8](sess, []int{batchN, maxMsgLen}, msgBuf)
	if err != nil {
		return false
	}
	defer msgT.Close()

	sigT, err := accel.NewTensorWithData[uint8](sess, []int{batchN, sigSize}, sigBuf)
	if err != nil {
		return false
	}
	defer sigT.Close()

	pkT, err := accel.NewTensorWithData[uint8](sess, []int{batchN, pkSize}, pkBuf)
	if err != nil {
		return false
	}
	defer pkT.Close()

	resT, err := accel.NewTensor[uint8](sess, []int{batchN})
	if err != nil {
		return false
	}
	defer resT.Close()

	if err := latticeOps.DilithiumVerifyBatch(msgT.Untyped(), sigT.Untyped(), pkT.Untyped(), resT.Untyped()); err != nil {
		return false
	}

	gpuResults, err := resT.ToSlice()
	if err != nil {
		return false
	}

	for i, idx := range indices {
		results[idx] = gpuResults[i] == 1
		if results[idx] {
			qs.stampsVerified.Add(1)
		} else {
			qs.stampsFailed.Add(1)
		}
	}

	// Handle hybrid mode: also verify SLH-DSA for hybrid stamps (CPU only)
	qs.verifyHybridSLHDSA(stamps, indices, signDataSlice, results)

	return true
}

// verifyHybridSLHDSA runs the SLH-DSA leg of every hybrid stamp in the batch that
// passed ML-DSA.
//
// signDataSlice is indexed by BATCH POSITION while indices maps position to the
// caller's stamp index; the two must be read together. Reading signDataSlice[0]
// for every stamp verified each hybrid stamp's SLH-DSA signature against the FIRST
// batch entry's signing bytes, so a signature over data the stamp does not commit
// to satisfied its post-quantum leg — and a batch submitter chooses what entry
// zero contains.
func (qs *QuantumStamper) verifyHybridSLHDSA(stamps []*QuantumStamp, indices []int, signDataSlice [][]byte, results []bool) {
	for pos, idx := range indices {
		if stamps[idx].Mode != StampModeHybrid || !results[idx] {
			continue
		}
		if !qs.verifySLHDSA(stamps[idx], signDataSlice[pos]) {
			results[idx] = false
			qs.stampsFailed.Add(1)
		}
	}
}

// GetStampForBlock retrieves a stamp for a specific block
func (qs *QuantumStamper) GetStampForBlock(blockHash common.Hash) (*QuantumStamp, bool) {
	return qs.stampCache.Get(blockHash)
}

// GetCurrentHeights returns current C-Chain and Q-Chain heights
func (qs *QuantumStamper) GetCurrentHeights() (cchainHeight, qchainHeight uint64) {
	return qs.cchainHeight.Load(), qs.qchainHeight.Load()
}

// GetMetrics returns stamping metrics
func (qs *QuantumStamper) GetMetrics() map[string]uint64 {
	return map[string]uint64{
		"stamps_created":  qs.stampsCreated.Load(),
		"stamps_verified": qs.stampsVerified.Load(),
		"stamps_failed":   qs.stampsFailed.Load(),
		"cchain_height":   qs.cchainHeight.Load(),
		"qchain_height":   qs.qchainHeight.Load(),
	}
}

// Enable enables quantum stamping
func (qs *QuantumStamper) Enable() {
	qs.enabled.Store(true)
	qs.log.Info("Quantum stamping enabled")
}

// Disable disables quantum stamping
func (qs *QuantumStamper) Disable() {
	qs.enabled.Store(false)
	qs.log.Info("Quantum stamping disabled")
}

// Close cleanly shuts down the stamper
func (qs *QuantumStamper) Close() {
	qs.Disable()
	close(qs.stampQueue)
	close(qs.verifyQueue)
}

// Helper functions

func generateNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

// ExportStamps exports all stamps for persistence
func (qs *QuantumStamper) ExportStamps() map[common.Hash]*QuantumStamp {
	stamps := make(map[common.Hash]*QuantumStamp)
	// Cache iteration not supported; returns empty map
	return stamps
}

// ImportStamps imports stamps from persistence
func (qs *QuantumStamper) ImportStamps(stamps map[common.Hash]*QuantumStamp) {
	for hash, stamp := range stamps {
		qs.stampCache.Put(hash, stamp)
	}
	qs.log.Info("Imported quantum stamps", "count", len(stamps))
}
