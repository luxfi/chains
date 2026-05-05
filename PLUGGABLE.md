# Pluggable chain VMs

`luxfi/chains` hosts the **luxd plugin shells** — each subdirectory's
`cmd/plugin/main.go` is the binary that luxd loads. The actual VM
implementations live in dedicated repos so they can also run as standalone
operator daemons (no luxd validator required), the same way `mpcd` and
`kms` do.

## Repository ownership

| chain VM | luxd plugin (this repo) | canonical implementation | standalone daemon |
|---|---|---|---|
| R-Chain (relay) | `chains/relayvm/` (shim) | `luxfi/relay/vm/` | `luxfi/relay/cmd/relayd` |
| O-Chain (oracle) | `chains/oraclevm/` (shim) | `luxfi/oracle/vm/` | `luxfi/oracle/cmd/oracled` |
| M-Chain (MPC threshold) | `luxfi/chains/thresholdvm/` (canonical, MPC mode) | (same) | n/a — runs in luxd |
| F-Chain (FHE) | `luxfi/chains/thresholdvm/` (canonical, FHE mode) | (same) | `luxfi/fhe/cmd/fhed` (standalone FHE daemon) |
| C-Chain (EVM) | `chains/evm/` | uses `chains/evm/cevm` (C++/GPU FFI shim) or pure-Go (default) via build tags | n/a — runs in luxd |
| A-Chain (AI) | `chains/aivm/` | `luxfi/ai` | n/a |
| I-Chain (identity) | `chains/identityvm/` | `luxfi/id` | n/a |

The shim pattern is uniform:

```go
// chains/<name>vm/<name>vm.go
package <name>vm

import canon "github.com/luxfi/<repo>/vm"

type Factory = canon.Factory
type VM = canon.VM
// … type aliases for every public type
```

External imports of `github.com/luxfi/chains/<name>vm` keep working
unchanged. The plugin's `cmd/plugin/main.go` doesn't need to be touched.

## Pluggable EVM (cevm vs Go-evm)

`chains/evm/cevm` is an FFI shim around `~/work/luxcpp/cevm` (C++ / GPU EVM),
not a standalone VM — it has no operator daemon, it lives in luxd. It folds
into this module rather than shipping as a separate `luxfi/cevm` repo. Two
implementations behind build tags:

| Tag | File | Implementation |
|---|---|---|
| `cgo` (default if cgo enabled) | `cevm/cevm_cgo.go` | C++ / GPU-accelerated EVM via CGO |
| `!cgo` (CGO_ENABLED=0) | `cevm/cevm_nocgo.go` | Pure-Go fallback (drops back to luxfi/geth) |

Operators choose at build time:

```sh
# C++/GPU EVM (default for production validators with cgo + GPU)
go build -o luxd ./cmd/luxd

# Pure-Go EVM (small footprint, no cgo dependency)
CGO_ENABLED=0 go build -o luxd ./cmd/luxd

# Hanzo node uses revm via the same plugin contract
# (separate luxd build flag; uses chains/evm/cevm at the API layer, REVM under the hood)
```

The plugin contract (`chain.ChainVM` from `luxfi/vm/chain`) is shared, so
ANY of these EVM kernels drops in behind the same import. Different
operators can run different kernels in the same network as long as state
roots match — which they do, because all kernels are EVM-spec compliant.

## Standalone daemons (operator side)

`relayd` and `oracled` are operator-side processes — they observe source
data (chain logs / Bitcoin RPC / OP_NET indexer / external feeds), sign
with the operator key, and submit to the chain VM via JSON-RPC. The chain
VM is the security boundary; the daemons are couriers.

Same shape as `mpcd` (FROST/CGGMP21 threshold signing) and `kms`
(Hashicorp-style secret management): single binary, HTTP API, NATS
subscription, persistent local state.

## Adding a new pluggable chain VM

1. Create `luxfi/<name>` repo with `vm/` package + `cmd/<name>d` daemon.
2. Make `chains/<name>vm/<name>vm.go` re-export `luxfi/<name>/vm` types.
3. Update `chains/<name>vm/go.mod` to require the canonical repo.
4. Plugin `cmd/plugin/main.go` keeps its existing import path unchanged.
