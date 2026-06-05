// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

// BridgeVM GPU substrate — host-side ABI for the five BridgeVM kernels
// (signer_apply, liquidity_apply, message_inbox, message_outbox, transition).
//
// The kernels live in ~/work/lux-private/gpu-kernels under
// ops/bridgevm/<backend>/ + backends/<backend>/src/bridgevm_launchers.{cpp,mm}
// and are shipped inside the plugin shared libraries libluxgpu_backend_<x>.so /
// .dylib. The Go side dlopens whichever plugin is on disk at process start
// and dlsyms the five lux_<backend>_bridgevm_* symbols.
//
// Pattern (mirrors evm/cevm + evm/backend_cgo.go):
//
//   backend.go                — shared types: Backend enum, layout structs,
//                                ErrGPUNotAvailable, GPUBackend interface,
//                                sizeof asserts (build-tag-free; runtime
//                                probe lives in the cgo/nocgo files below).
//   bridgevm_gpu.go       cgo — dlopen + dlsym for libluxgpu_backend_<x>.
//   bridgevm_gpu_nocgo.go !cgo — stub returning ErrGPUNotAvailable.
//
// Layout structs are byte-equal to
// ops/bridgevm/cuda/bridgevm_kernels_common.cuh (and the matching CPU oracle
// at luxcpp/bridgevm/src/bridgevm_cpu_reference.cpp). The init() sizeof
// asserts catch any drift at process start instead of producing silently
// wrong roots.

import (
	"errors"
	"fmt"
	"sync/atomic"
	"unsafe"
)

// Backend identifies which GPU plugin is currently active.
//
// Order matches the dlopen probe order in bridgevm_gpu.go's init():
// cuda → hip → metal → vulkan → webgpu. The first plugin that resolves
// all five lux_<backend>_bridgevm_* symbols wins; remaining probes are
// skipped.
type Backend uint8

const (
	// BackendNone means no GPU plugin is loaded — calls return
	// ErrGPUNotAvailable. This is the value reported by AutoBackend()
	// under !cgo, and under cgo when no libluxgpu_backend_*.so is on
	// the dlopen search path.
	BackendNone Backend = 0
	// BackendCUDA selects libluxgpu_backend_cuda.so (NVIDIA, Linux/Windows).
	BackendCUDA Backend = 1
	// BackendHIP selects libluxgpu_backend_hip.so (AMD, Linux/Windows).
	BackendHIP Backend = 2
	// BackendMetal selects libluxgpu_backend_metal.dylib (Apple, darwin).
	BackendMetal Backend = 3
	// BackendVulkan selects libluxgpu_backend_vulkan.{so,dylib} (portable).
	BackendVulkan Backend = 4
	// BackendWebGPU selects libluxgpu_backend_webgpu.{so,dylib} (portable).
	BackendWebGPU Backend = 5
)

// String returns the human-readable name of the backend — matches the symbol
// prefix component used by the dlsym probe (lux_<name>_bridgevm_*).
func (b Backend) String() string {
	switch b {
	case BackendNone:
		return "none"
	case BackendCUDA:
		return "cuda"
	case BackendHIP:
		return "hip"
	case BackendMetal:
		return "metal"
	case BackendVulkan:
		return "vulkan"
	case BackendWebGPU:
		return "webgpu"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(b))
	}
}

// ErrGPUNotAvailable is returned by every GPUBackend method when no plugin
// is loaded — either because the binary was built without CGo, no
// libluxgpu_backend_*.{so,dylib} was found on the dlopen search path, or
// the loaded plugin doesn't expose the lux_<backend>_bridgevm_* launchers
// (e.g. an older plugin built before the bridgevm op landed).
//
// The error is sentinel-comparable via errors.Is so callers can route a
// CPU-oracle fallback cleanly:
//
//	if errors.Is(err, bridgevm.ErrGPUNotAvailable) {
//	    return cpuOracle.Apply(...)
//	}
var ErrGPUNotAvailable = errors.New("bridgevm: GPU backend not available")

// =============================================================================
// Layout structs — byte-equal to ops/bridgevm/cuda/bridgevm_kernels_common.cuh
// and to luxcpp/bridgevm/include/lux/bridgevm/bridgevm_gpu_layout.hpp.
//
// alignas(16) on the C++ side is honoured here by manual `_pad*` fields and
// by the init() sizeof asserts below. Go's struct layout rule (no implicit
// alignment padding beyond the natural alignment of the largest field) means
// these definitions land at the same byte offsets the GPU kernels read from.
//
// `little-endian lane` ordering for 128-bit values: the C ABI splits each
// 128-bit quantity into (lo, hi) uint64 pairs in the struct — never a single
// 128-bit field — so cross-endianness reproducibility is byte-trivial.
// =============================================================================

// Signer is the on-arena per-signer record (208 bytes).
type Signer struct {
	SignerID         uint64
	LuxAddress       [20]byte
	_                uint32   // _pad_addr
	BondAmountLo     uint64
	BondAmountHi     uint64
	OptInHeight      uint64
	ExitEpoch        uint64
	SignCount        uint64
	BLSPubKey        [48]byte
	CoronaPubKey   [32]byte
	MLDSAPubKey      [32]byte
	Status           uint32
	JailUntilEpoch   uint32
	SlashCount       uint32
	Occupied         uint32
	_                uint64   // _pad_tail
}

// LiquidityEntry is the on-arena per-provider liquidity record (80 bytes).
type LiquidityEntry struct {
	ProviderAddr   [20]byte
	_              uint32   // _pad_addr
	AssetID        uint32
	Status         uint32
	AmountLo       uint64
	AmountHi       uint64
	FeeAccrualLo   uint64
	FeeAccrualHi   uint64
	DepositHeight  uint64
	_              uint64   // _pad0
}

// DailyLimit is the on-arena per-asset daily cap record (64 bytes).
type DailyLimit struct {
	AssetID     uint32
	Status      uint32
	DailyCapLo  uint64
	DailyCapHi  uint64
	UsedTodayLo uint64
	UsedTodayHi uint64
	ResetEpoch  uint64
	_           uint64 // _pad0
	_           uint64 // _pad1
}

// Message is an inbox/outbox cross-chain message record (240 bytes).
type Message struct {
	MsgID           [32]byte
	PayloadRoot     [32]byte
	AggSignature    [96]byte
	SignersBitmapLo uint64
	SignersBitmapHi uint64
	Nonce           uint64
	SrcChain        uint32
	DstChain        uint32
	Kind            uint32
	Status          uint32
	AssetID         uint32
	SignerCount     uint32
	AmountLo        uint64
	AmountHi        uint64
	ArrivalHeight   uint64
	_               uint64 // _pad_tail
}

// BridgeVMEpochState is the epoch summary written by transition (240 bytes).
type BridgeVMEpochState struct {
	CurrentEpoch        uint64
	NextEpochHeight     uint64
	TotalActiveBondLo   uint64
	TotalActiveBondHi   uint64
	ActiveSignerCount   uint32
	PendingDropCount    uint32
	InboxCount          uint32
	OutboxCount         uint32
	SignerSetRoot       [32]byte
	LiquidityRoot       [32]byte
	InboxRoot           [32]byte
	OutboxRoot          [32]byte
	DailyLimitRoot      [32]byte
	BridgeVMStateRoot   [32]byte
}

// BridgeVMRoundDescriptor parameterises one round invocation (112 bytes).
type BridgeVMRoundDescriptor struct {
	ChainID           uint64
	Round             uint64
	TimestampNs       uint64
	Epoch             uint64
	Height            uint64
	Mode              uint32
	InboundMsgCount   uint32
	SignerOpCount     uint32
	LiquidityOpCount  uint32
	OutboundReqCount  uint32
	ClosingFlag       uint32
	_                 uint64 // _pad0
	_                 uint64 // _pad1
	ParentStateRoot   [32]byte
}

// SignerOp is one input to signer_apply (224 bytes).
type SignerOp struct {
	SignerID        uint64
	LuxAddress      [20]byte
	_               uint32   // _pad_addr
	BondAmountLo    uint64
	BondAmountHi    uint64
	OptInHeight     uint64
	BLSPubKey       [48]byte
	CoronaPubKey  [32]byte
	MLDSAPubKey     [32]byte
	Kind            uint32
	JailUntilEpoch  uint32
	Epoch           uint32
	SlashAmountLo   uint32
	SlashAmountHi   uint32
	_               uint32   // _pad0
	EvidenceDigest  [32]byte
}

// LiquidityOp is one input to liquidity_apply (64 bytes).
type LiquidityOp struct {
	ProviderAddr [20]byte
	_            uint32   // _pad_addr
	AssetID      uint32
	Kind         uint32
	AmountLo     uint64
	AmountHi     uint64
	Height       uint64
	_            uint64   // _pad0
}

// OutboundReq is one input to message_outbox (112 bytes).
type OutboundReq struct {
	PayloadRoot [32]byte
	Recipient   [20]byte
	_           uint32   // _pad_addr
	SrcChain    uint32
	DstChain    uint32
	Kind        uint32
	AssetID     uint32
	Nonce       uint64
	AmountLo    uint64
	AmountHi    uint64
	Height      uint64
	_           uint64   // _pad_tail
}

// BridgeVMTransitionResult is the populated result of transition (304 bytes).
type BridgeVMTransitionResult struct {
	Status                  uint32
	InboundApplyCount       uint32
	SignerApplyCount        uint32
	LiquidityApplyCount     uint32
	OutboundApplyCount      uint32
	ActiveSignerCount       uint32
	JailedCount             uint32
	TombstonedCount         uint32
	TotalActiveBondLo       uint64
	TotalActiveBondHi       uint64
	TotalInboundAmountLo    uint64
	TotalInboundAmountHi    uint64
	TotalOutboundAmountLo   uint64
	TotalOutboundAmountHi   uint64
	TotalFeesAccruedLo      uint64
	TotalFeesAccruedHi      uint64
	Epoch                   uint64
	_                       uint64 // _pad0
	SignerSetRoot           [32]byte
	LiquidityRoot           [32]byte
	InboxRoot               [32]byte
	OutboxRoot              [32]byte
	DailyLimitRoot          [32]byte
	BridgeVMStateRoot       [32]byte
}

// =============================================================================
// GPUBackend — the surface the dlopen'd plugin presents to vm.go.
//
// All five methods return ErrGPUNotAvailable when no plugin is loaded. When a
// plugin is loaded, the methods dispatch to the corresponding
// lux_<backend>_bridgevm_* host launcher via dlsym and return a non-nil
// error when the launcher reports a non-zero status code (mapped to a Go
// error including the numeric code).
//
// Buffer ownership: callers own every slice/struct passed in. The host
// launcher does H2D / D2H internally (for discrete-GPU backends like CUDA
// and HIP this means cudaMalloc + cudaMemcpy round-trips; for unified
// backends like Metal, Vulkan, and WebGPU the slice is wrapped in a
// shader-visible buffer and the launcher submits + waits inline). On
// return every output slice has been overwritten with the launcher's
// result; the caller can read them immediately, no further sync needed.
//
// The interface is intentionally narrow — five 1:1 mappings to the host
// launcher signatures in include/lux/gpu/bridgevm.h. We do NOT try to
// express composability here (a "full round" would call all five in
// sequence); composition is the caller's job (vm.go's round-applier),
// matching the orthogonal separation in op.yaml's notes.
type GPUBackend interface {
	// SignerApply runs lux_<bk>_bridgevm_signer_apply over `ops`.
	// `signers` is the in-place arena slice (modified). `applied` returns
	// the count of ops the kernel actually applied (subject to BFT
	// threshold and per-signer status). Returns ErrGPUNotAvailable when
	// no plugin is loaded.
	SignerApply(
		desc *BridgeVMRoundDescriptor,
		ops []SignerOp,
		signers []Signer,
	) (applied uint32, err error)

	// LiquidityApply runs lux_<bk>_bridgevm_liquidity_apply over `ops`.
	// Returns the count applied + the aggregated fee accrual (lo, hi).
	LiquidityApply(
		desc *BridgeVMRoundDescriptor,
		ops []LiquidityOp,
		liquidity []LiquidityEntry,
	) (applied uint32, totalFeesLo uint64, totalFeesHi uint64, err error)

	// MessageInbox runs lux_<bk>_bridgevm_message_inbox over `inMsgs`.
	// Returns the count accepted + the aggregated inbound amount.
	MessageInbox(
		desc *BridgeVMRoundDescriptor,
		inMsgs []Message,
		signers []Signer,
		daily []DailyLimit,
		inbox []Message,
	) (applied uint32, totalInLo uint64, totalInHi uint64, err error)

	// MessageOutbox runs lux_<bk>_bridgevm_message_outbox over `reqs`.
	// Returns the count emitted + the aggregated outbound amount.
	MessageOutbox(
		desc *BridgeVMRoundDescriptor,
		reqs []OutboundReq,
		daily []DailyLimit,
		outbox []Message,
		epoch *BridgeVMEpochState,
	) (applied uint32, totalOutLo uint64, totalOutHi uint64, err error)

	// BridgeTransition runs lux_<bk>_bridgevm_transition. The result is
	// written into `result` and the six roots (signer_set / liquidity /
	// inbox / outbox / daily_limit / bridgevm_state) are populated.
	BridgeTransition(
		desc *BridgeVMRoundDescriptor,
		signers []Signer,
		liquidity []LiquidityEntry,
		daily []DailyLimit,
		inbox []Message,
		outbox []Message,
		epoch *BridgeVMEpochState,
		result *BridgeVMTransitionResult,
	) error

	// Backend reports which plugin is currently loaded.
	Backend() Backend
}

// activeBackend is set by the init() in bridgevm_gpu.go (cgo) or
// bridgevm_gpu_nocgo.go (!cgo). Read via AutoBackend(). Stored as atomic
// uint32 so concurrent reads in vm.go (the round applier picks the backend
// per call) don't race with the init() store.
var activeBackend atomic.Uint32

// AutoBackend returns the GPU plugin chosen by the dlopen probe at process
// start. BackendNone means no plugin is loaded — every GPUBackend method
// returns ErrGPUNotAvailable; callers should route to the CPU oracle.
//
// The probe runs once at init time; this getter is cheap (single atomic
// load) and safe to call from any goroutine. Use ActiveGPUBackend() to
// get an invocable GPUBackend handle.
func AutoBackend() Backend {
	return Backend(uint8(activeBackend.Load()))
}

// setActiveBackend records the probe result. Called by init() in the
// cgo/nocgo files. Not exported — there is one and only one way to load
// the plugin (the init probe).
func setActiveBackend(b Backend) {
	activeBackend.Store(uint32(uint8(b)))
}

// =============================================================================
// Sizeof asserts — fail fast at process start if any layout struct above
// drifts from the GPU header. A drift here would silently corrupt every
// round's state root, so a panic at startup is the correct behaviour.
// =============================================================================

func init() {
	// Each entry is (name, got, want) so the panic message names the
	// offending struct instead of just "drift".
	type szCheck struct {
		name string
		got  uintptr
		want uintptr
	}
	checks := []szCheck{
		{"Signer", unsafe.Sizeof(Signer{}), 208},
		{"LiquidityEntry", unsafe.Sizeof(LiquidityEntry{}), 80},
		{"DailyLimit", unsafe.Sizeof(DailyLimit{}), 64},
		{"Message", unsafe.Sizeof(Message{}), 240},
		{"BridgeVMEpochState", unsafe.Sizeof(BridgeVMEpochState{}), 240},
		{"BridgeVMRoundDescriptor", unsafe.Sizeof(BridgeVMRoundDescriptor{}), 112},
		{"SignerOp", unsafe.Sizeof(SignerOp{}), 224},
		{"LiquidityOp", unsafe.Sizeof(LiquidityOp{}), 64},
		{"OutboundReq", unsafe.Sizeof(OutboundReq{}), 112},
		{"BridgeVMTransitionResult", unsafe.Sizeof(BridgeVMTransitionResult{}), 304},
	}
	for _, c := range checks {
		if c.got != c.want {
			panic(fmt.Sprintf(
				"bridgevm: %s layout drift — Go sizeof=%d, GPU header expects %d. "+
					"Update backend.go to match ops/bridgevm/cuda/bridgevm_kernels_common.cuh.",
				c.name, c.got, c.want))
		}
	}
}
