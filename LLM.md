# LLM context — `luxfi/chains`

Independent VM plugin binaries for the Lux Network. Each top-level
subdirectory builds a standalone binary that `luxd` loads at runtime via
`--plugin-dir`, with the actual VM implementation either inlined or
re-exported from a canonical sibling repo.

## What lives here

- A flat set of VM packages (one per chain), each producing its own plugin
  binary. There is no umbrella `vms/` directory — VMs are top-level.
- A uniform shim pattern: many subdirectories are thin re-exports of a
  canonical `luxfi/<repo>/vm` package so external imports of
  `github.com/luxfi/chains/<name>vm` stay stable even when the impl moves.
- A single `Makefile` that discovers VMs by listing top-level dirs and
  builds each via `./<vm>` (when `main.go` is at the root, as in `evm/`) or
  `./<vm>/cmd/plugin` (the default for every other VM).
- A scratch-based `Dockerfile.plugin` that packages a pre-built plugin
  binary as a stateless container; the build happens on a native-arch
  runner and the artifact is copied into `/plugin`.

## Key directories

- `evm/` — C-Chain EVM plugin. Build-tag dispatch between a CGO backend
  (`backend_cgo.go`, links luxcpp shared libs through `evm/cevm/`) and a
  pure-Go fallback (`backend_nocgo.go`). See `evm/LLM.md` for the
  backend-selection flow and the GPU ecrecover bridge.
- `evm/cevm/` — FFI shim around the C++/GPU EVM in `luxcpp`. Not a
  separate VM; lives inside the EVM plugin and is gated by `//go:build cgo`
  / `//go:build !cgo` pairs (e.g. `cevm_cgo.go` vs `cevm_nocgo.go`).
- `thresholdvm/` — substrate that powers both M-Chain (MPC) and F-Chain
  (FHE) modes. See `thresholdvm/LLM.md` and `thresholdvm/DESIGN.md`.
- `aivm/`, `bridgevm/`, `dexvm/`, `graphvm/`, `identityvm/`, `keyvm/`,
  `oraclevm/`, `quantumvm/`, `relayvm/`, `zkvm/` — one VM per directory;
  each ships `factory.go`, `vm.go`, and `cmd/plugin/main.go`.
- `oraclevm/` and `relayvm/` are shim re-exports of `luxfi/oracle/vm` and
  `luxfi/relay/vm` respectively; the standalone operator daemons
  (`oracled`, `relayd`) live in those canonical repos.

## VM-to-chain mapping

The canonical table is in `README.md`. Highlights:

| VM directory | Chain | Notes |
|---|---|---|
| `evm/` | C-Chain | EVM; CGO vs pure-Go via build tags |
| `thresholdvm/` (MPC mode) | M-Chain | CGGMP21 / FROST / Ringtail-general — bridge custody |
| `thresholdvm/` (FHE mode) | F-Chain | TFHE bootstrap + encrypted EVM compute |
| `quantumvm/` | Q-Chain | Post-quantum consensus signing (Pulsar) |
| `zkvm/` | Z-Chain | Groth16 over BLS12-381 — rolls ML-DSA-65 sigs into one proof |
| `bridgevm/` | B-Chain | Cross-chain bridge |
| `dexvm/` | D-Chain | DEX |
| `aivm/`, `graphvm/`, `identityvm/`, `keyvm/`, `oraclevm/`, `relayvm/` | A/G/I/K/O/R | one-line purpose each in README |

## Build tags in evm/cevm

Two implementations behind Go's standard CGO toggle (no custom tag names):

| Tag | File | Implementation |
|---|---|---|
| `cgo` (default with cgo enabled) | `evm/cevm/cevm_cgo.go`, `evm/backend_cgo.go` | C++ / GPU EVM via luxcpp FFI |
| `!cgo` (`CGO_ENABLED=0`) | `evm/cevm/cevm_nocgo.go`, `evm/backend_nocgo.go` | Pure-Go fallback (luxfi/geth) |

Operators select at build time:

```sh
go build -o luxd ./cmd/luxd                  # CGO path (production validators)
CGO_ENABLED=0 go build -o luxd ./cmd/luxd    # Pure-Go path (small footprint)
```

The plugin contract (`chain.ChainVM` from `luxfi/vm/chain`) is shared, so
any EVM kernel can drop in behind the same import as long as state roots
match the EVM spec. See `PLUGGABLE.md` for the cross-kernel design.

## How to extend — adding a new pluggable chain VM

1. Create the canonical repo `luxfi/<name>` with a `vm/` package and a
   `cmd/<name>d` operator daemon (if the chain needs an off-chain courier).
2. Add `chains/<name>vm/<name>vm.go` that re-exports
   `github.com/luxfi/<name>/vm` types via type aliases (Factory, VM,
   block / state types).
3. Update `chains/<name>vm/go.mod` to require the canonical repo.
4. Add `chains/<name>vm/cmd/plugin/main.go` following the existing pattern
   (rpcchainvm server over the re-exported Factory).
5. The root `Makefile` auto-discovers the directory; no Makefile edit is
   needed unless the VM has a non-standard layout.

## thresholdvm — design context

`thresholdvm/` is a **substrate**, not a chain. It hosts the ceremony state
machine, share envelope, QuasarCertLane registration, and
certificate-subject binding logic that **both** M-Chain (MPC custody for
external wallets) and F-Chain (FHE compute + TFHE bootstrap-key generation)
import. The legacy T-Chain shim (LP-5013) is deprecated by LP-134 — see
`thresholdvm/LLM.md` for the do-not-touch list and lane enum invariants.

The dependency graph is one-way: `mchain → thresholdvm` and
`fchain → thresholdvm`. Reverse edges are forbidden.

## Cross-refs

- `README.md` — canonical VM-to-chain table, build/install quickstart.
- `PLUGGABLE.md` — shim pattern, kernel-portability rationale, `relayd` /
  `oracled` operator-daemon shape.
- `evm/LLM.md` — backend selection, GPU ecrecover bridge, Block STM
  wire-up status.
- `thresholdvm/LLM.md` — substrate constraints, lane enums, what NOT to
  add back to T-Chain.
- `thresholdvm/DESIGN.md`, `thresholdvm/docs/ARCHITECTURE.md` — deep dive
  on the ceremony substrate.
