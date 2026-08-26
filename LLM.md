# chains

**Org:** luxfi  ·  **Ecosystem:** lux  ·  **Path:** `/Users/a/work/lux/luxfi/chains`
**Origin:** https://github.com/luxfi/chains.git

## Discovery

This file (`CLAUDE.md`) is the canonical agent-facing readme; `LLM.md` is a symlink to it. Update either name and both stay in sync.

## Where to look first

- `README.md` — human-facing overview (if present)
- `package.json` / `Cargo.toml` / `pyproject.toml` / `go.mod` — language & deps
- `.github/workflows/` — CI surface
- `docs/` — extended docs (if present)

## Canonical chain roster (LP-0130)

The topology, UTXO ownership rule, and cross-chain fee model are
normatively specified by
[**LP-0130** (Chain Topology, UTXO Ownership, and Fee Model)](https://github.com/luxfi/lps/blob/main/LPs/lp-0130-chain-topology-utxo-ownership-and-fee-model.md).
Read that LP before touching any VM's fee/settlement path.

Only **P** (in `node/vms/platformvm`) and **X** (in `node/vms/xvm`) are
canonical UTXO state machines. Every VM in THIS repo is a
domain-execution chain that MUST consume UTXO settlement via the
`chains/fee` primitive funded from X.

| Dir | Letter | Role | LP |
|---|---|---|---|
| `evm/` | **C** | Contract / EVM account state | LP-1200 |
| `dexvm/` | **D** | DEX matching + settlement receipts | LP-9000 |
| `quantumvm/` | **Q** | Finality-cert / Quasar aggregation. **No user-payable blockspace** (validator obligation, LP-0130 §6) | LP-1300 |
| `zkvm/` | **Z** | Rollup / private commitment + nullifier. Shielded supply is an X-escrow wrapper (LP-0130 §2, I-5) | LP-8000 |
| `aivm/` | **A** | Inference receipt + attestation. Rides B's settlement engine (LP-0130 §9) | LP-5000 |
| `bridgevm/` | **B** | Cross-chain message lifecycle. Fees deducted from bridged amount (LP-0130 §8) | LP-6000 |
| `mpcvm/` | **M** | MPC signing / custody. Service fees paid by originating chain (LP-0130 §7); no user M-balance | LP-7100 |
| `mpcvm/fhe/` | **F** | FHE runtime **library** — a package inside `mpcvm`, not a chain. See the deployment note below. | LP-8200 |

**Deployment reality (probed on mainnet 96369, `platform.getBlockchains`).** Ten
chains are live: P X + C D Q Z A B G K. **M and F are NOT deployed**, and the
two are not equally close to shipping:

- **M** has a full VM (`mpcvm/`, `mpcvm/cmd/plugin`) — it builds, it just has no
  chain registered on any network.
- **F** has **no VM at all**. `luxfi/constants` reserves
  `FHEVMID = {'f','h','e','v','m'}` and `luxfi/node/node/vms.go` lists it in
  `OptionalVMs` as plugin `fhevm`, so luxd scans `--plugin-dir` for a binary
  that this repo never produces (no `fhevm/` directory ⇒ no `make` target ⇒ no
  binary). `mpcvm/fhe/` above is the FHE runtime library, not a standalone
  F-Chain. **F-Chain is a spec (LP-8200, LP-167) with no shipping VM.**

T-Chain is gone entirely — LP-134 dissolves it with zero remainder (threshold
signing → M, FHE → F, cross-chain messaging/teleport → B). There is no
`teleportvm` here and no `teleportvm` VM ID in `luxfi/constants`.

**Service VMs** (not canonical primary chains under LP-0130):

| Dir | Letter | Purpose |
|---|---|---|
| `schain/` | S | S3-style object storage (on-chain metadata, off-chain blob) |
| `keyvm/` | K | Key registry / cryptographic algorithm addressing |
| `identityvm/` | I | DID / identity |
| `graphvm/` | G | Graph indexing / GraphQL surface |
| `relayvm/` | R | Relay message queue |
| `oraclevm/` | O | Oracle price / data feed |

Service VMs MAY have domain state and MAY charge fees, but MUST fund
their fee balance from X and MUST NOT hold canonical UTXO asset
supply.

### Fee settlement primitive — `chains/fee`

`chains/fee/{balance,meter,settle,ledger}.go` is the shared
admission → meter → burn primitive every non-P/X VM in this repo
uses. Its `Burn` is a native LUX burn (no coinbase credit) that
reconciles against X-side fee escrow at the epoch fee root ([LP-0130
§4](https://github.com/luxfi/lps/blob/main/LPs/lp-0130-chain-topology-utxo-ownership-and-fee-model.md#4-fee-model-hybrid)).
`chains/fee/doc.go` is the design intent.

### Σ-escrow invariant

At every Q checkpoint (LP-0130 I-8):

```
Σ (non-P/X fee balances)  ==  Σ (X-side fee escrow)
```

Drift is a finality-blocking fault. This is the audit invariant every
VM's epoch-fee-root emission and reconciliation path exists to
satisfy.

## VMs in this repo

Each `*vm/` dir is a self-contained `block.ChainVM` plugin. `dexvm` is the
reference for VM structure + commit discipline (dual-DB: durable `baseDB` +
per-block `versiondb`; one `db.CommitBatch()` at block Accept).

- **schain** (`schain/`) — the Lux **S-Chain storage VM**, forked from `dexvm`'s
  structure. VMID = `ids.ID{'s','c','h','a','i','n'}` (dexvm's byte pattern).
  **M0 (DONE):** one mutation `PutManifest{bucket,object,fileIds,size,etag}`
  round-trips through a real Lux block (BuildBlock→Verify→Accept) and commits the
  manifest to a real on-disk zapdb in ONE atomic batch at Accept; `GetManifest`
  returns it only after Accept. Commit discipline copied verbatim from
  `dexvm/vm.go:1194` (acceptBlock), minus the cross-chain shared-memory leg a
  storage VM does not have — accept reduces to `CommitBatch()` + `batch.Write()` +
  `db.Abort()`. State = typed manifest accessors over `versiondb` (no protobuf;
  JSON value bodies, prefix keys), mirroring `dexvm/state/state.go`. Tx wire =
  type-byte + JSON, one codec (mirror `dexvm/txs/tx.go`). No blobs/pinning/
  networking yet — that is M1+. Test: `schain/schain_test.go` drives the genuine
  VM↔engine contract (SubmitTx→ToEngine PendingTxs→BuildBlock→Verify→Accept) over
  a REAL `zapdb.New(t.TempDir(),…)`; proves staged-not-durable before Accept,
  durable after, and Reject→Abort discards.
  **M1 (DONE):** TWO parts.
  *PART A — manifest STATE ROOT* (the multi-validator safety prerequisite M0
  omitted): `state.Root()` hashes the committed manifest keyspace deterministically
  via the zapdb prefix iterator `NewIteratorWithStartAndPrefix(nil, prefixManifest)`,
  folding each entry length-prefixed (`len(k)||k||len(v)||v`) in lexicographic key
  order (mirror of `dexvm/state/state.go:395` `StateHash`, narrowed to the one
  keyspace; last-block pointer excluded — it is consensus binding folded via
  blockHash/height, not object state). `VM.computeStateRoot` folds blockHash+height
  with `state.Root()` (mirror `dexvm/vm.go:1260`); `ProcessBlock` stamps it into
  `BlockResult.StateRoot` (mirror `dexvm/vm.go:584`). The root travels in the block
  HEADER (new 32-byte field after parentID; block id commits to it) and
  `Block.Verify` recomputes it and REJECTS a mismatch (`errStateRootMismatch`) +
  Aborts staged writes — this is the >1-validator safety gate dexvm computed but
  never compared. Tests (`schain/stateroot_test.go`): determinism across write
  order, change-sensitivity (object set / etag / size / fileIds each move the root),
  and Verify-rejects-tampered-root.
  *PART B — S3 OBJECT path, on-chain-metadata / off-chain-blob split* proven end to
  end (`schain/object/`): `Store.PutObject` streams the blob to a `Volume` (OFF
  chain) → fid, then commits only `PutManifest{bucket,object,[fid],size,etag}` to
  the VM through a real block (ON chain); `GetObject` reads the manifest back and
  reconstructs the blob from the volume. `object.Volume` is the SEAM (Write(blob)→fid,
  Read(fid)→blob); M1 satisfies it with a faithful in-memory `MemVolume` whose fid
  shape mirrors hanzo/s3's `needle.FileId` (`volumeId,needleIdCookie`) and whose
  etag is `base64(md5(blob))` (= hanzo/s3 `ContentMd5`). **M2 PLUG POINT** (marked
  in `object/volume.go`): swap `MemVolume` for a thin adapter over `github.com/
  hanzoai/s3` `s3/operation.SubmitFiles` (assign volume + stream needle → `.Fid`)
  and a needle GET — nothing in the VM or `object.Store` changes. Kept inside
  chains/schain (not importing the hanzoai/s3 module into luxfi/chains) to respect
  the org/module boundary while proving the exact data model. Test
  (`schain/object_roundtrip_test.go`): asserts the blob bytes appear in NO accepted
  block (`bytes.Contains` over `blk.Bytes()`) and the block stays manifest-small
  (<4KiB for a 68KiB blob), the manifest IS on chain, and GET byte-reconstructs.

### Test/build env gotcha (macOS)

The whole chains test suite links CGO deps that need `-lresolv`; the CLT `cc`
fails with `library 'resolv' not found` unless the macOS SDK syslibroot is set.
Run tests with `SDKROOT="$(xcrun --show-sdk-path)" go test ./schain/...`. This
affects `dexvm` and every other VM here too — it is NOT schain-specific.

## Sibling repos

See the org-level `LLM.md` at `/Users/a/work/lux/luxfi/LLM.md` for the full inventory of sibling repos and inter-repo dependencies.

## Telling consensus there is work

Consensus calls `WaitForEvent` and builds nothing until it returns, so a VM that
accepts work has to report it. There is one way to do that: `vm.Latch` in
`github.com/luxfi/vm`. `Signal()` says there is work, `WaitForEvent(ctx)` blocks
until there is, and signalling twice before the signal is taken is the same as
once — a builder needs to know that there is work, not how much, so a burst
coalesces into one build. The zero value is usable, so whatever owns the pending
work holds one.

**Put the latch on the pool, not the VM.** The pool is what learns work arrived,
whichever path it came by, so it covers internal callers as well as the HTTP
handler and the VM's `WaitForEvent` is one line. zkvm, quantumvm, identityvm,
bridgevm, aivm, keyvm and mpcvm all work this way.

Two chains deliberately do not, and both are correct:

- **schain and dexvm** notify on the `ToEngine` channel they receive in
  `vm.Init` instead, and park on the context. That is the other of the two ways
  a VM can report work, and a VM needs one. Before changing a parked
  `WaitForEvent`, check which: `grep -rn "toEngine <-" <vm>/*.go`.
- **graphvm** builds no blocks at all. G-Chain indexes what other chains have
  already agreed, so it holds no state of its own to agree on; a block there
  would carry a query result, which a peer recomputes, or a schema, which is
  local configuration. `BuildBlock` declines with `errReadOnlyChain`.

## B-Chain: where a bridge request comes from

B learns of a bridge from the source chain's own `Locked` events, not from its
API. `watch.go` polls each configured chain, reads the range it has not read
yet, and turns each lock into a pending request keyed by the transfer's
canonical digest — the same value M signs and the destination gateway keys its
replay guard by, so two chains reusing a nonce cannot collide and the same lock
read twice is the same request.

It reads twelve blocks behind the head, so a lock a reorg takes back never
becomes a request; it bounds one pass, so a backlog is asked for in pieces; and
a chain it cannot reach keeps its cursor rather than skipping that chain's
blocks. The depth a lock is buried at rides along as its confirmation count,
which is what `BuildBlock` gates on.

The bridge's API is the JSON-RPC service in `rpc.go`, and `bridge_health`
reports what the node can do: a node with no chains wired is not a relayer and
is healthy, while one that is configured to relay but cannot attest says so.
