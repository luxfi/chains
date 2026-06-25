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

### Test/build env gotcha (macOS)

The whole chains test suite links CGO deps that need `-lresolv`; the CLT `cc`
fails with `library 'resolv' not found` unless the macOS SDK syslibroot is set.
Run tests with `SDKROOT="$(xcrun --show-sdk-path)" go test ./schain/...`. This
affects `dexvm` and every other VM here too — it is NOT schain-specific.

## Sibling repos

See the org-level `LLM.md` at `/Users/a/work/lux/luxfi/LLM.md` for the full inventory of sibling repos and inter-repo dependencies.
