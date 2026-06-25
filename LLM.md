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
