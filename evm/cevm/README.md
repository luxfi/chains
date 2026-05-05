# cevm — C++ EVM execution backend

The CGO bridge to the C++ EVM in `~/work/luxcpp/cevm`. Selected at link time
via build tags from `chains/evm/backend_{cgo,nocgo}.go`.

This is **not** a standalone VM. It is the GPU-accelerated execution backend
for C-Chain when built with `LUX_CGO=1`. The pure-Go fallback (`luxfi/geth`)
is used when `LUX_CGO=0`.

## Layout

```
chains/evm/
├── main.go                 # luxd plugin entry
├── backend_cgo.go          # cgo backend selector (LUX_CGO=1)
├── backend_nocgo.go        # pure-Go selector (LUX_CGO=0)
└── cevm/                   # this package — C++ FFI shim
    ├── cevm.go             # Go API
    ├── cevm_cgo.go         # cgo bindings (linked against luxcpp libs)
    ├── cevm_nocgo.go       # no-op stubs for !cgo builds
    └── plugin.go           # plugin registration glue
```

## Linking

`cevm_cgo.go` references `${SRCDIR}/../../../../luxcpp/...` for headers and
libs. From `~/work/lux/chains/evm/cevm/` that resolves to `~/work/luxcpp/`.
For module-cache builds, see `accel`'s `fetch-luxcpp.sh` pattern (TODO: port
the same approach here).

## Performance

When CGO is enabled and luxcpp libs are available:
- ~3–5× the throughput of pure-Go EVM
- SIMD opcode dispatch (AVX2/NEON)
- GPU batch operations via Block-STM (CUDA/Metal)

## Provenance

Folded into `chains/evm` from the previously-standalone `luxfi/cevm` repo on
2026-04-30. cevm is internal-only — no operator daemon. C-Chain runs in luxd.
See `~/work/lux/chains/PLUGGABLE.md` for the canonicalization pattern that
governs the rest of the chain VMs.
