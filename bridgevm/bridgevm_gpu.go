// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package bridgevm

// CGo-backed BridgeVM GPU substrate. Loads the per-backend plugin
// libluxgpu_backend_<bk>.{so,dylib} at process start via dlopen(3) and
// resolves the five lux_<bk>_bridgevm_* host launcher symbols via dlsym(3).
//
// Direct dlopen — NOT pkg-config. The plugin lives in
// the GPU plugin install tree (a private repo); the public chains module
// must build without it present. Linking via pkg-config would couple the
// public build to a private dep; dlopen + dlsym lets us probe at runtime
// and degrade cleanly to ErrGPUNotAvailable when the plugin is absent.
//
// Search path for the plugin:
//
//   1. $LUX_GPU_PLUGIN_DIR (explicit override, useful in tests / CI).
//   2. $LUXCPP_PREFIX/lib/lux-gpu/         (the install tree).
//   3. $LUXCPP_PREFIX/lib/                 (legacy install tree).
//   4. $HOME/work/the lux GPU plugin build/backends/<bk>/  (dev tree).
//   5. The current working directory.
//   6. The system loader's default path (dlopen with bare name).
//
// Probe order — cuda → hip → metal → vulkan → webgpu. The first plugin that
// resolves all five symbols wins and sets activeBackend. Subsequent probes
// are skipped (one and only one plugin loaded per process).
//
// Thread safety: the init() probe runs once before main(). Post-init, the
// pluginHandle and the five fnPtr_* package vars are read-only — concurrent
// SignerApply / LiquidityApply / etc. calls from many goroutines are safe.
// Each launcher allocates its own scratch buffers; there are no shared
// mutables on the Go side. The C launchers themselves are documented as
// concurrent-safe (per backends/<bk>/src/bridgevm_launchers.{mm,cpp}).

/*
#cgo LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Trampolines — we cannot call function pointers from Go directly through cgo.
// The trampoline takes the function pointer (resolved via dlsym from Go) and
// the launcher args and calls the launcher. One trampoline per launcher
// signature.

typedef int (*bvm_signer_fn)(
    const void* desc, const void* ops, void* signers, void* applied_out,
    uint32_t signer_count, void* stream);

typedef int (*bvm_liquidity_fn)(
    const void* desc, const void* ops, void* liquidity, void* applied_out,
    void* total_fees_lo_out, void* total_fees_hi_out,
    uint32_t liquidity_count, void* stream);

typedef int (*bvm_inbox_fn)(
    const void* desc, const void* in_msgs, void* signers, void* daily,
    void* inbox, void* applied_out, void* total_in_lo_out, void* total_in_hi_out,
    uint32_t signer_count, uint32_t daily_count, uint32_t inbox_count,
    void* stream);

typedef int (*bvm_outbox_fn)(
    const void* desc, const void* reqs, void* daily, void* outbox, void* epoch,
    void* applied_out, void* total_out_lo_out, void* total_out_hi_out,
    uint32_t daily_count, uint32_t outbox_count, void* stream);

typedef int (*bvm_transition_fn)(
    const void* desc, void* signers, void* liquidity, void* daily,
    void* inbox, void* outbox, void* epoch, void* result,
    uint32_t signer_count, uint32_t liquidity_count, uint32_t daily_count,
    uint32_t inbox_count, uint32_t outbox_count,
    void* stream);

static int call_signer(void* fn,
    const void* desc, const void* ops, void* signers, void* applied_out,
    uint32_t signer_count) {
    return ((bvm_signer_fn)fn)(desc, ops, signers, applied_out,
                                signer_count, (void*)0);
}

static int call_liquidity(void* fn,
    const void* desc, const void* ops, void* liquidity, void* applied_out,
    void* total_fees_lo_out, void* total_fees_hi_out,
    uint32_t liquidity_count) {
    return ((bvm_liquidity_fn)fn)(desc, ops, liquidity, applied_out,
                                   total_fees_lo_out, total_fees_hi_out,
                                   liquidity_count, (void*)0);
}

static int call_inbox(void* fn,
    const void* desc, const void* in_msgs, void* signers, void* daily,
    void* inbox, void* applied_out, void* total_in_lo_out, void* total_in_hi_out,
    uint32_t signer_count, uint32_t daily_count, uint32_t inbox_count) {
    return ((bvm_inbox_fn)fn)(desc, in_msgs, signers, daily, inbox,
                               applied_out, total_in_lo_out, total_in_hi_out,
                               signer_count, daily_count, inbox_count,
                               (void*)0);
}

static int call_outbox(void* fn,
    const void* desc, const void* reqs, void* daily, void* outbox, void* epoch,
    void* applied_out, void* total_out_lo_out, void* total_out_hi_out,
    uint32_t daily_count, uint32_t outbox_count) {
    return ((bvm_outbox_fn)fn)(desc, reqs, daily, outbox, epoch,
                                applied_out, total_out_lo_out, total_out_hi_out,
                                daily_count, outbox_count, (void*)0);
}

static int call_transition(void* fn,
    const void* desc, void* signers, void* liquidity, void* daily,
    void* inbox, void* outbox, void* epoch, void* result,
    uint32_t signer_count, uint32_t liquidity_count, uint32_t daily_count,
    uint32_t inbox_count, uint32_t outbox_count) {
    return ((bvm_transition_fn)fn)(desc, signers, liquidity, daily,
                                    inbox, outbox, epoch, result,
                                    signer_count, liquidity_count,
                                    daily_count, inbox_count, outbox_count,
                                    (void*)0);
}

// dl helpers — wrap dlopen / dlsym / dlerror so the Go side doesn't have to
// deal with the C string lifetimes.

static void* dl_open(const char* path) {
    return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
}

static void* dl_sym(void* h, const char* name) {
    return dlsym(h, name);
}

static const char* dl_err(void) {
    const char* e = dlerror();
    return e ? e : "";
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// pluginHandle is the dlopen()'d handle to libluxgpu_backend_<bk>.{so,dylib}.
// Held for the lifetime of the process (we never dlclose — the plugin's
// runtime state, GPU contexts, kernel caches, etc., would all be invalidated
// and any in-flight goroutine call would crash).
var pluginHandle unsafe.Pointer

// fnPtr_<launcher> are the dlsym'd entry points. Read-only after init(); a
// nil entry means the loaded plugin doesn't export that symbol (which fails
// the probe — we require all five).
var (
	fnSignerApply     unsafe.Pointer
	fnLiquidityApply  unsafe.Pointer
	fnMessageInbox    unsafe.Pointer
	fnMessageOutbox   unsafe.Pointer
	fnBridgeTransit   unsafe.Pointer
)

// initOnce guards the probe — even though init() runs at most once, this
// belt-and-braces guard makes the contract explicit and lets the test files
// re-trigger the probe deterministically (via a debug entry, not yet wired).
var initOnce sync.Once

func init() {
	initOnce.Do(probePlugin)
}

// probePlugin walks the dlopen search path × backend probe order looking
// for the first libluxgpu_backend_<bk>.{so,dylib} that exposes all five
// lux_<bk>_bridgevm_* launchers. First match wins; activeBackend is set
// and pluginHandle + fnPtr_* are populated.
//
// On no match: activeBackend stays at BackendNone, every GPUBackend method
// returns ErrGPUNotAvailable. We do NOT log here — process start in the
// chains binary is noisy enough; vm.go (the consumer) can log AutoBackend()
// at the level it wants.
func probePlugin() {
	for _, bk := range []Backend{
		BackendCUDA, BackendHIP, BackendMetal, BackendVulkan, BackendWebGPU,
	} {
		for _, path := range candidatePluginPaths(bk) {
			if !plausiblePath(path) {
				continue
			}
			if !tryLoad(bk, path) {
				continue
			}
			setActiveBackend(bk)
			return
		}
		// Bare-name fallback — let the dynamic loader use its default path.
		if tryLoad(bk, dsoBareName(bk)) {
			setActiveBackend(bk)
			return
		}
	}
}

// candidatePluginPaths returns the search list for one backend, in priority
// order. The list is small (≤6) so we don't bother deduping — a duplicate
// dlopen on a path that doesn't exist is cheap (immediate ENOENT).
func candidatePluginPaths(bk Backend) []string {
	name := dsoBareName(bk)
	var paths []string

	// 1) Explicit override — useful in tests / CI to pin a specific build.
	if env := os.Getenv("LUX_GPU_PLUGIN_DIR"); env != "" {
		paths = append(paths, filepath.Join(env, name))
		paths = append(paths, filepath.Join(env, bk.String(), name))
	}

	// 2/3) Install tree (set by `cmake --install`).
	if prefix := os.Getenv("LUXCPP_PREFIX"); prefix != "" {
		paths = append(paths, filepath.Join(prefix, "lib", "lux-gpu", name))
		paths = append(paths, filepath.Join(prefix, "lib", name))
	}

	// 4) CWD — last resort before falling back to the loader default.
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, name))
	}

	return paths
}

// dsoBareName returns the platform-correct shared object name for a backend.
// macOS uses .dylib; everything else (linux, *bsd, windows) uses .so —
// Windows builds are produced from the WSL/MinGW toolchain in the gpu-kernels
// CI matrix and ship .so as well per the gpu-kernels CMake convention.
func dsoBareName(bk Backend) string {
	ext := ".so"
	if runtime.GOOS == "darwin" {
		ext = ".dylib"
	}
	return "libluxgpu_backend_" + bk.String() + ext
}

// plausiblePath returns false for an absolute path that doesn't exist, so we
// skip wasted dlopen calls (each one allocates inside libc's dlerror buffer).
// Bare names (without a slash) are always "plausible" — the loader handles
// the search.
func plausiblePath(p string) bool {
	if filepath.IsAbs(p) {
		_, err := os.Stat(p)
		return err == nil
	}
	return true
}

// tryLoad dlopens `path`, then dlsyms the five lux_<bk>_bridgevm_* symbols.
// All-or-nothing — if any symbol is missing the handle is left open (it's
// global and the next backend's dlsym calls may benefit) but pluginHandle
// stays nil. Returns true iff every symbol resolved and we've committed to
// this backend.
func tryLoad(bk Backend, path string) bool {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	// Clear any prior dlerror state so dl_err() reports THIS call's error.
	C.dl_err()

	h := C.dl_open(cpath)
	if h == nil {
		return false
	}

	prefix := "lux_" + bk.String() + "_bridgevm_"
	syms := map[string]*unsafe.Pointer{
		prefix + "signer_apply":    &fnSignerApply,
		prefix + "liquidity_apply": &fnLiquidityApply,
		prefix + "message_inbox":   &fnMessageInbox,
		prefix + "message_outbox":  &fnMessageOutbox,
		prefix + "transition":      &fnBridgeTransit,
	}

	staging := make(map[string]unsafe.Pointer, 5)
	for name := range syms {
		cname := C.CString(name)
		p := C.dl_sym(h, cname)
		C.free(unsafe.Pointer(cname))
		if p == nil {
			// Missing symbol — backend's plugin doesn't expose bridgevm.
			// Don't dlclose: the same .so may carry useful symbols for the
			// next probe. Yes this leaks a handle on miss, but probes are
			// bounded (5 max) and run once at init.
			return false
		}
		staging[name] = unsafe.Pointer(p)
	}

	// All five resolved — commit.
	pluginHandle = unsafe.Pointer(h)
	for name, slot := range syms {
		*slot = staging[name]
	}
	return true
}

// =============================================================================
// GPUBackend implementation — one struct, one method per launcher. The struct
// is stateless (just a Backend tag); the real state lives in the package-level
// fnPtr_* and pluginHandle variables. We expose it as an interface (not a
// concrete struct) so the !cgo stub can satisfy the same surface.
// =============================================================================

// ActiveGPUBackend returns an invocable GPUBackend. It tries the dlopen'd GPU
// plugin first and falls through to the pure-Go CPU oracle in
// bridgevm_gpu_cpu.go on ErrGPUNotAvailable. The returned backend therefore
// always executes the transition — there is no "GPU unavailable" path the
// caller has to handle, only a "did the GPU or the CPU run it" introspection
// question answered by Backend().
//
// The internal cgoBackend type is still exported via the same interface so
// existing call-sites and tests that probe the GPU layer directly (e.g.
// TestStubReturnsErrGPUNotAvailable, which constructs cgoBackend{tag:
// BackendNone} to assert the ErrGPUNotAvailable contract on the bare GPU
// layer) keep working unchanged.
func ActiveGPUBackend() GPUBackend {
	return gpuOrCPU{gpu: cgoBackend{tag: AutoBackend()}, cpu: cpuBackend{}}
}

// gpuOrCPU is the composite backend returned by ActiveGPUBackend() under
// cgo. Each method tries the cgoBackend first and, on ErrGPUNotAvailable,
// dispatches to the cpuBackend in bridgevm_gpu_cpu.go. The CPU oracle is
// byte-equal to the GPU plugin (non-strict mode) — same descriptors, same
// arenas, same outputs — so the caller sees a single, deterministic
// state transition regardless of which side actually ran it.
//
// Backend() reports whichever path is currently live: the GPU plugin's
// tag when a plugin is loaded, BackendNone when only the CPU oracle is.
type gpuOrCPU struct {
	gpu cgoBackend
	cpu cpuBackend
}

func (b gpuOrCPU) Backend() Backend {
	if b.gpu.tag != BackendNone {
		return b.gpu.tag
	}
	return BackendNone
}

func (b gpuOrCPU) SignerApply(
	desc *BridgeVMRoundDescriptor,
	ops []SignerOp,
	signers []Signer,
) (uint32, error) {
	applied, err := b.gpu.SignerApply(desc, ops, signers)
	if errors.Is(err, ErrGPUNotAvailable) {
		return b.cpu.SignerApply(desc, ops, signers)
	}
	return applied, err
}

func (b gpuOrCPU) LiquidityApply(
	desc *BridgeVMRoundDescriptor,
	ops []LiquidityOp,
	liquidity []LiquidityEntry,
) (uint32, uint64, uint64, error) {
	applied, lo, hi, err := b.gpu.LiquidityApply(desc, ops, liquidity)
	if errors.Is(err, ErrGPUNotAvailable) {
		return b.cpu.LiquidityApply(desc, ops, liquidity)
	}
	return applied, lo, hi, err
}

func (b gpuOrCPU) MessageInbox(
	desc *BridgeVMRoundDescriptor,
	inMsgs []Message,
	signers []Signer,
	daily []DailyLimit,
	inbox []Message,
) (uint32, uint64, uint64, error) {
	applied, lo, hi, err := b.gpu.MessageInbox(desc, inMsgs, signers, daily, inbox)
	if errors.Is(err, ErrGPUNotAvailable) {
		return b.cpu.MessageInbox(desc, inMsgs, signers, daily, inbox)
	}
	return applied, lo, hi, err
}

func (b gpuOrCPU) MessageOutbox(
	desc *BridgeVMRoundDescriptor,
	reqs []OutboundReq,
	daily []DailyLimit,
	outbox []Message,
	epoch *BridgeVMEpochState,
) (uint32, uint64, uint64, error) {
	applied, lo, hi, err := b.gpu.MessageOutbox(desc, reqs, daily, outbox, epoch)
	if errors.Is(err, ErrGPUNotAvailable) {
		return b.cpu.MessageOutbox(desc, reqs, daily, outbox, epoch)
	}
	return applied, lo, hi, err
}

func (b gpuOrCPU) BridgeTransition(
	desc *BridgeVMRoundDescriptor,
	signers []Signer,
	liquidity []LiquidityEntry,
	daily []DailyLimit,
	inbox []Message,
	outbox []Message,
	epoch *BridgeVMEpochState,
	result *BridgeVMTransitionResult,
) error {
	err := b.gpu.BridgeTransition(desc, signers, liquidity, daily, inbox, outbox, epoch, result)
	if errors.Is(err, ErrGPUNotAvailable) {
		return b.cpu.BridgeTransition(desc, signers, liquidity, daily, inbox, outbox, epoch, result)
	}
	return err
}

type cgoBackend struct {
	tag Backend
}

func (b cgoBackend) Backend() Backend { return b.tag }

// errFromCode wraps a non-zero launcher return as a Go error tagged with the
// op name + numeric status. The launcher contract is `0 = success`,
// non-zero = error code with meanings documented per-launcher (1 = null
// pointer, 2 = device unavailable, 3 = pipeline compile failure, etc.).
func errFromCode(op string, code C.int) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("bridgevm: %s launcher returned code %d", op, int(code))
}

// guardOrErr returns ErrGPUNotAvailable when the plugin isn't loaded.
// Centralised so each method has the same gate without scattering branches.
func (b cgoBackend) guard(fn unsafe.Pointer) error {
	if pluginHandle == nil || fn == nil || b.tag == BackendNone {
		return ErrGPUNotAvailable
	}
	return nil
}

func (b cgoBackend) SignerApply(
	desc *BridgeVMRoundDescriptor,
	ops []SignerOp,
	signers []Signer,
) (uint32, error) {
	if err := b.guard(fnSignerApply); err != nil {
		return 0, err
	}
	if desc == nil || len(signers) == 0 {
		return 0, fmt.Errorf("bridgevm: SignerApply requires non-nil desc + non-empty signers")
	}
	var applied uint32
	descP := unsafe.Pointer(desc)
	var opsP unsafe.Pointer
	if len(ops) > 0 {
		opsP = unsafe.Pointer(&ops[0])
	}
	signersP := unsafe.Pointer(&signers[0])
	appliedP := unsafe.Pointer(&applied)

	code := C.call_signer(
		fnSignerApply,
		descP, opsP, signersP, appliedP,
		C.uint32_t(len(signers)),
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(ops)
	runtime.KeepAlive(signers)
	return applied, errFromCode("signer_apply", code)
}

func (b cgoBackend) LiquidityApply(
	desc *BridgeVMRoundDescriptor,
	ops []LiquidityOp,
	liquidity []LiquidityEntry,
) (uint32, uint64, uint64, error) {
	if err := b.guard(fnLiquidityApply); err != nil {
		return 0, 0, 0, err
	}
	if desc == nil || len(liquidity) == 0 {
		return 0, 0, 0, fmt.Errorf(
			"bridgevm: LiquidityApply requires non-nil desc + non-empty liquidity")
	}
	var (
		applied      uint32
		totalFeesLo  uint64
		totalFeesHi  uint64
	)
	var opsP unsafe.Pointer
	if len(ops) > 0 {
		opsP = unsafe.Pointer(&ops[0])
	}

	code := C.call_liquidity(
		fnLiquidityApply,
		unsafe.Pointer(desc),
		opsP,
		unsafe.Pointer(&liquidity[0]),
		unsafe.Pointer(&applied),
		unsafe.Pointer(&totalFeesLo),
		unsafe.Pointer(&totalFeesHi),
		C.uint32_t(len(liquidity)),
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(ops)
	runtime.KeepAlive(liquidity)
	return applied, totalFeesLo, totalFeesHi, errFromCode("liquidity_apply", code)
}

func (b cgoBackend) MessageInbox(
	desc *BridgeVMRoundDescriptor,
	inMsgs []Message,
	signers []Signer,
	daily []DailyLimit,
	inbox []Message,
) (uint32, uint64, uint64, error) {
	if err := b.guard(fnMessageInbox); err != nil {
		return 0, 0, 0, err
	}
	if desc == nil || len(signers) == 0 || len(daily) == 0 || len(inbox) == 0 {
		return 0, 0, 0, fmt.Errorf(
			"bridgevm: MessageInbox requires non-nil desc + non-empty signers/daily/inbox")
	}
	var (
		applied     uint32
		totalInLo   uint64
		totalInHi   uint64
	)
	var inMsgsP unsafe.Pointer
	if len(inMsgs) > 0 {
		inMsgsP = unsafe.Pointer(&inMsgs[0])
	}

	code := C.call_inbox(
		fnMessageInbox,
		unsafe.Pointer(desc),
		inMsgsP,
		unsafe.Pointer(&signers[0]),
		unsafe.Pointer(&daily[0]),
		unsafe.Pointer(&inbox[0]),
		unsafe.Pointer(&applied),
		unsafe.Pointer(&totalInLo),
		unsafe.Pointer(&totalInHi),
		C.uint32_t(len(signers)),
		C.uint32_t(len(daily)),
		C.uint32_t(len(inbox)),
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(inMsgs)
	runtime.KeepAlive(signers)
	runtime.KeepAlive(daily)
	runtime.KeepAlive(inbox)
	return applied, totalInLo, totalInHi, errFromCode("message_inbox", code)
}

func (b cgoBackend) MessageOutbox(
	desc *BridgeVMRoundDescriptor,
	reqs []OutboundReq,
	daily []DailyLimit,
	outbox []Message,
	epoch *BridgeVMEpochState,
) (uint32, uint64, uint64, error) {
	if err := b.guard(fnMessageOutbox); err != nil {
		return 0, 0, 0, err
	}
	if desc == nil || epoch == nil || len(daily) == 0 || len(outbox) == 0 {
		return 0, 0, 0, fmt.Errorf(
			"bridgevm: MessageOutbox requires non-nil desc/epoch + non-empty daily/outbox")
	}
	var (
		applied     uint32
		totalOutLo  uint64
		totalOutHi  uint64
	)
	var reqsP unsafe.Pointer
	if len(reqs) > 0 {
		reqsP = unsafe.Pointer(&reqs[0])
	}

	code := C.call_outbox(
		fnMessageOutbox,
		unsafe.Pointer(desc),
		reqsP,
		unsafe.Pointer(&daily[0]),
		unsafe.Pointer(&outbox[0]),
		unsafe.Pointer(epoch),
		unsafe.Pointer(&applied),
		unsafe.Pointer(&totalOutLo),
		unsafe.Pointer(&totalOutHi),
		C.uint32_t(len(daily)),
		C.uint32_t(len(outbox)),
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(reqs)
	runtime.KeepAlive(daily)
	runtime.KeepAlive(outbox)
	runtime.KeepAlive(epoch)
	return applied, totalOutLo, totalOutHi, errFromCode("message_outbox", code)
}

func (b cgoBackend) BridgeTransition(
	desc *BridgeVMRoundDescriptor,
	signers []Signer,
	liquidity []LiquidityEntry,
	daily []DailyLimit,
	inbox []Message,
	outbox []Message,
	epoch *BridgeVMEpochState,
	result *BridgeVMTransitionResult,
) error {
	if err := b.guard(fnBridgeTransit); err != nil {
		return err
	}
	if desc == nil || epoch == nil || result == nil ||
		len(signers) == 0 || len(liquidity) == 0 || len(daily) == 0 ||
		len(inbox) == 0 || len(outbox) == 0 {
		return fmt.Errorf(
			"bridgevm: BridgeTransition requires non-nil desc/epoch/result + non-empty arrays")
	}

	code := C.call_transition(
		fnBridgeTransit,
		unsafe.Pointer(desc),
		unsafe.Pointer(&signers[0]),
		unsafe.Pointer(&liquidity[0]),
		unsafe.Pointer(&daily[0]),
		unsafe.Pointer(&inbox[0]),
		unsafe.Pointer(&outbox[0]),
		unsafe.Pointer(epoch),
		unsafe.Pointer(result),
		C.uint32_t(len(signers)),
		C.uint32_t(len(liquidity)),
		C.uint32_t(len(daily)),
		C.uint32_t(len(inbox)),
		C.uint32_t(len(outbox)),
	)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(signers)
	runtime.KeepAlive(liquidity)
	runtime.KeepAlive(daily)
	runtime.KeepAlive(inbox)
	runtime.KeepAlive(outbox)
	runtime.KeepAlive(epoch)
	runtime.KeepAlive(result)
	return errFromCode("transition", code)
}
