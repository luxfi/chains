# cevm — AI Assistant Context

Go FFI shim around the C++ EVM (`~/work/luxcpp/cevm`).

## Build modes

- `cgo`: links `libevm`, `libevm-gpu`, `libluxgpu`, `libcevm_precompiles`. Exposes
  CPUSequential, CPUParallel (Block-STM), GPUMetal (darwin), GPUCUDA (linux).
- `!cgo`: returns CPUSequential only; ExecuteBlock* return errors.

API surface is identical across modes (`cevm.go` is shared, `cevm_cgo.go` /
`cevm_nocgo.go` provide the implementation).

## Block STM status

Real, present in `~/work/luxcpp/cevm/lib/evm/gpu/`:
- CPU: `parallel_engine.cpp`, `parallel_host.hpp`, `mv_memory.{cpp,hpp}` (MVHashMap)
- Metal: `metal/block_stm.metal`, `metal/block_stm_host.{mm,hpp}`
- CUDA: `cuda/block_stm.cu`, `cuda/block_stm_host.{cpp,hpp}`

Driven from Go via `ExecuteBlockV3(backend=CPUParallel|GPU{Metal,CUDA}, ...)`.

## C-Chain wiring

Default execution path on the C-Chain plugin (`~/work/lux/chains/evm`) uses the
`luxfi/evm/core/parallel` registry. Under cgo, importing `luxfi/cevm` links the
luxcpp libs and `parallel.SetBackend(AutoEVM)` resolves to CppEVM iff luxfi/evm
itself is built with `-tags cevm`. Under `!cgo`, GoEVM (geth) is the only path.

The luxfi/evm-side `cevmExecutor.ExecuteTransaction` is currently a stub
(returns nil → falls back to geth interpreter); completing it to dispatch into
`cevm.ExecuteBlockV3` is a luxfi/evm-repo change, not done here.

## PQ finality

C-Chain blocks become PQ-final via P-Chain inclusion (Quasar = BLS + Ringtail
lattice). This package does not sign anything itself. See
`~/work/lux/consensus/LLM.md`.
