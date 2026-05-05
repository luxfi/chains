# chains/evm — AI Assistant Context

C-Chain VM plugin entry point. Spawns `luxfi/evm.VM{}` over rpcchainvm and
imports every precompile package by side effect (registry pattern).

## Execution backend

Backend selection lives in `backend_cgo.go` / `backend_nocgo.go` (single
cgo-tag pair, no other build flags). `main.go` calls `selectExecutionBackend`
once at startup, before serving rpcchainvm.

- `cgo`: imports `github.com/luxfi/chains/evm/cevm` to link luxcpp shared libs
  (`libevm`, `libevm-gpu`, `libluxgpu`, `libcevm_precompiles`), runs
  `cevm.Health()` probes, and calls `parallel.SetBackend(AutoEVM)`. Active
  backend is CppEVM iff luxfi/evm is built with `-tags cevm`; otherwise
  GoEVM (geth) — without losing the GPU ecrecover bridge that registers
  itself under `cgo && darwin` in `luxfi/evm/core/parallel/gpu_bridge.go`.
- `!cgo`: `parallel.SetBackend(GoEVM)`. Pure-Go fallback.

## Block STM

Implemented upstream in `~/work/luxcpp/cevm/lib/evm/gpu/`. Reachable from Go
via `cevm.ExecuteBlockV3(backend=CPUParallel|GPUMetal|GPUCUDA, ...)`. The
luxfi/evm tx-executor stub currently does NOT dispatch into ExecuteBlockV3 —
that wire-up is a luxfi/evm-repo change.

## PQ finality

Out of scope. Blocks become PQ-final via P-Chain inclusion (Quasar). See
`~/work/lux/consensus/LLM.md`.

## Build verification

```
GOWORK=off CGO_ENABLED=0 go build ./...   # nocgo path
GOWORK=off CGO_ENABLED=1 go build ./...   # cgo path (links luxcpp libs)
```
