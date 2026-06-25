# S-Chain: Leaderless + Pinned-Writer Storage Coordination

Replacing the S3 master's raft consensus with deterministic per-range single-writer
assignment, hosted as Lux S-Chain VM state.

Status: DESIGN. One code artifact landed — the pure pinning library
(`schain/pinning/`, 9 tests green). Nothing in `master.go` or raft touched.

---

## 0. Problem statement

The S3 master uses raft to serialize three things through one elected leader:

- **Volume-id allocation** — `Topology.NextVolumeId()` does `RaftServer.Do(NewMaxVolumeIdCommand(...))`
  (`s3/topology/topology.go:373-398`), gated on `IsLeaderAndCanRead()` (line 374).
- **fileId sequence** — `Topology.PickForWrite()` calls `t.Sequence.NextFileId()`
  (`s3/topology/topology.go:423`), a process-local mutex counter
  (`s3/sequence/memory_sequencer.go:18-24`) that is ONLY single-valued because all
  writes funnel through the one raft leader.
- **Topology mutations** — `MaxVolumeIdCommand.Apply` mutates `MaxVolumeId` + `TopologyId`
  on every node via the raft log (`s3/topology/cluster_commands.go:30-49`).

Raft is registered as the last gRPC server in s3 (`s3/command/master.go:271`,
`protobuf.RegisterRaftServer(grpcS, raftServer)`). Everything else in the master
already serves over native ZAP (`master.go:300-316`); raft is the lone holdout.

**The cost of raft here:** ONE writer for the WHOLE namespace. Every assignment —
to any bucket, any volume — serializes through the single leader. Throughput is
leader-bound; a leader failure stalls *all* allocation during election.

**Invariants that must survive any replacement:**

1. **No two writers for the same object.** Two concurrent PUTs to the same
   `(bucket, object)` must not both allocate/commit a manifest.
2. **fileId / volume-id uniqueness.** No two allocations ever yield the same id.
3. **Durable only after agreement.** A manifest/allocation is visible only after
   a supermajority of stake has finalized it (raft today gives this via commit
   index; the replacement gives it via cert-gated block Accept).
4. **Deterministic recovery.** Every node reconstructs identical state from the
   same inputs.

**The owner's directive:** *leaderless; pinned writer; not master/slave raft.*
The win we are buying: **single-writer PER RANGE instead of single-writer GLOBAL.**
Disjoint ranges allocate in parallel; the same object still has exactly one writer.

---

## 1. Pinning function — deterministic single-writer-per-range, no election

### Mechanism

For a storage key-range `R` (the partition key — see "granularity" below), the
owning validator is:

```
owner(R) = argmax_{v ∈ V(h)}  score(R, v.NodeID, v.Weight)
```

where `V(h)` is the **P-Chain validator set frozen at epoch height `h`** and

```
score(R, nodeID, w) = -w / ln( u ),   u = (H(R ‖ nodeID)[:8] + 1) / 2^64,  H = SHA-256
```

This is **weighted rendezvous (HRW) hashing**. Implemented and proven in
`schain/pinning/pinning.go` — `Owner(key, members)` (pinning.go:`Owner`),
`IsOwner(key, self, members)` (pinning.go:`IsOwner`).

### Exact inputs

| Input | Source | Citation |
|---|---|---|
| key-range `R` bytes | the allocation request's partition key (`bucket`, or `bucket/volume-band`) | request-derived |
| validator set `V(h)` = `{(NodeID, Weight)}` | `runtime.ValidatorState.GetValidatorSet(ctx, h, netID)` | `lux/validators/validators.go:16`; `GetValidatorOutput{NodeID, Weight}` at `validators.go:43-49` |
| epoch height `h` | `block.pChainHeight` — frozen per block | consensus `Block.pChainHeight` (`lux/consensus/engine/chain/consensus.go:91-113`), extracted via `pChainHeightOf` (`engine.go:1487-1506`), captured at build (`engine.go:1990`) |
| `self` NodeID | the node's own identity from `runtime.Runtime` | `runtime.go` |

The VM holds `*runtime.Runtime.ValidatorState` (`lux/consensus/runtime/runtime.go:85-86`),
delivered in `vmcore.Init` at `Initialize` (`schain/vm.go:107-111`). It builds
`[]pinning.Member` from `GetValidatorSet(ctx, block.pChainHeight, netID)` — the
projection is id+weight only, so the pure pinning logic carries no validators-pkg
dependency.

### Why this is single-writer-per-range WITHOUT election

- `Owner` is a **pure function** of `(R, V(h))`. No round-trip, no quorum, no
  term, no heartbeat. Every node computes the SAME owner for the same inputs —
  proven by `TestDeterministic` and `TestSingleWriterPerRange` (exactly 1 owner
  across 5000 keys × 7 validators).
- Two different ranges → (usually) two different owners → **parallel writers**.
  Proven by `TestParallelDifferentRanges` (≥70% of key pairs get distinct
  owners with 5 equal validators; theory says 80%).
- Stake-weighted: a 2× validator owns ~2× ranges (`TestWeightedDistribution`,
  within 2% of the stake fraction over 200k draws). Raft's single leader carried
  100% regardless of stake; this aligns write load with stake.

### How a node knows it's the owner

`pinning.IsOwner(rangeKey, self, members)` → bool. The node emits the
Allocate/Put tx **iff** it is the owner. That is the entire admission rule. No
"am I leader" raft query (today `IsLeaderAndCanRead()`, `topology.go:268`); it is
a local pure computation against the epoch-frozen set.

### How non-owners behave

Non-owners **never emit** an Allocate tx for that range. They participate only as
consensus validators: when the owner's Allocate tx arrives in a block, every node
(owner and non-owner alike) runs the same deterministic `ProcessBlock`
(`schain/vm.go:152`) — they **verify and vote**. A non-owner that sees an
Allocate tx for range `R` signed/submitted by a node that is NOT `Owner(R, V(h))`
**rejects the block** (see §3 divergence detection). So non-owners are the
safety net: they cannot write, but they can refuse a write from a non-owner.

### Re-pinning at epoch boundaries

Ownership is a function of `block.pChainHeight`. It changes ONLY when
pChainHeight advances to a new epoch with a changed validator set. Because HRW is
**minimal-disruption**, a validator add/remove moves only the ranges that node
owned-or-now-owns; all other ranges keep their owner. Proven by
`TestMinimalDisruption` (remove 1 of 5 validators: every range NOT owned by the
removed node keeps its owner — 0 spurious moves; the removed node's ~3900/20000
ranges re-pin cleanly). This bounds churn at `O(ranges × Δvalidators / N)`, not a
full reshuffle — the property that makes validator-set change cheap.

The epoch-boundary handoff is the one race that needs care — see §6.

---

## 2. Allocator without raft

### Today (raft-serialized)

```
PickForWrite → t.Sequence.NextFileId(n)          # process-local counter, single-valued ONLY because raft funnels all writes through one leader
NextVolumeId → RaftServer.Do(MaxVolumeIdCommand) # raft-log replicated max-volume-id
```
(`topology.go:404-426`, `:373-398`; `cluster_commands.go:30-49`)

### Replacement (pinned-writer mutation in VM state)

Allocation becomes a **deterministic S-Chain transaction** emitted by the
**owner of the allocation range**, committed as VM state at block Accept.

Add one tx type alongside the existing `PutManifestTx` (`schain/txs/tx.go:86`):

```
AllocateTx {
    Range      string   // the pinned key-range (bucket or bucket/band)
    Count      uint64   // how many fileIds requested
    Epoch      uint64   // block.pChainHeight the owner pinned against
    Owner      ids.NodeID
    Fingerprint ids.ID  // pinning.EpochFingerprint(Epoch, members)
}
```

VM state gains a **per-range monotonic counter** (replacing the global
`MemorySequencer` and the raft `MaxVolumeId`):

```
state key:  alloc/<range>           → uint64 next-id   (per-range, not global)
```

`ProcessBlock` applies an AllocateTx deterministically (mirrors the existing
`processTx`/`PutManifest` discipline at `schain/vm.go:192-210`):

```
applyAllocate(tx):
    members = ValidatorState.GetValidatorSet(ctx, tx.Epoch, netID)        # frozen set
    if pinning.EpochFingerprint(tx.Epoch, members) != tx.Fingerprint: reject  # divergence
    if !pinning.IsOwner(tx.Range, tx.Owner, members):               reject  # non-owner write
    base = state.Get(alloc/<tx.Range>)        # 0 if absent
    state.Put(alloc/<tx.Range>, base + tx.Count)   # stages into versiondb layer
    # allocated ids are [base, base+Count); deterministic from prior committed state
```

The id range `[base, base+Count)` is a **pure function of committed state**, so
every node derives identical ids. Durable only at `acceptBlock`'s single
`CommitBatch` (`schain/vm.go:218-239`) — invariant 3 holds via cert-gated Accept,
not raft commit index.

### Parallel writes to different ranges proceed in parallel

Range `A` is owned by validator `α`; range `B` by `β` (`TestParallelDifferentRanges`).
`α` and `β` each emit their AllocateTx independently — they do NOT serialize
through one leader. Within one S-Chain block both txs apply to **disjoint state
keys** (`alloc/A` vs `alloc/B`), so they commute and commit together. This is the
win over raft: raft forces `A` and `B` through one leader's log; here they are
two independent owners writing two independent counters.

> v1 caveat: on a single linear ChainVM the two txs still land in the same block
> stream (one chain = one total order). The parallelism is in **who computes the
> mutation** (no single leader bottleneck, no election) and in commutativity, not
> yet in concurrent block production. True concurrent commit needs the DAG engine
> — see §4. v1 still removes raft and removes the global-single-writer bottleneck
> at the allocation-decision layer.

### Two writes to the same object are impossible

For range `R`, `Owner(R, V(h))` is a single NodeID (`TestSingleWriterPerRange`:
exactly 1 owner, always). Only that node emits the AllocateTx/PutManifestTx for
`R`. A second node attempting to write `R` is not the owner → it does not emit;
if it maliciously emits anyway, `applyAllocate`'s `IsOwner` check rejects it on
every node. So same-object double-write is impossible by construction
(invariants 1 & 2).

---

## 3. Safety

### Finality stays cert-gated (>2/3 stake)

The pinned writer **proposes**; it does not **finalize**. An AllocateTx/PutManifestTx
enters the mempool (`SubmitTx`, `schain/chainvm.go:106`), the proposer drains it
into a block (`BuildBlock`, `chainvm.go:132`), and the block is accepted only
when Lux consensus collects a finalizing certificate over **>2/3 of stake**. The
owner cannot unilaterally finalize: it has one vote weighted by its own stake.
`acceptBlock`'s commit (`schain/vm.go:218`) runs only after the engine's
cert-gated Accept. So a pinned writer that emits **bad** state still needs 2/3 of
stake to verify-and-vote that state, and §3-divergence makes honest nodes reject
a non-owner or wrong-epoch write. **Liveness is pinned; safety is quorum.**

### Owner failure / partition — CHOOSE CONSISTENCY

When the owner of range `R` is down or partitioned:

- **Within an epoch:** ownership does NOT fail over. `Owner(R, V(h))` is fixed
  for the whole epoch. If the owner is down, range `R` is **unavailable for new
  allocations** until the next epoch re-pins it. Reads and already-committed
  manifests are unaffected (they are durable VM state, served by every node).

- **This is a deliberate AP/CP choice: we pick CONSISTENCY.** We accept a bounded
  **unavailability window** (one epoch, until pChainHeight advances and
  `Owner(R, V(h'))` selects a live validator) in exchange for NEVER having two
  writers for `R`. The alternative — letting a second node take over mid-epoch on
  a suspected failure — reintroduces split-brain (the partitioned owner may still
  be writing). Storage allocation must not double-allocate, so consistency wins.
  This mirrors raft's own behavior (raft is also CP: no leader → no writes), but
  WITHOUT the global blast radius — only range `R` stalls, not the whole namespace.

- **Epoch cadence sets the failover SLA.** Re-pinning is automatic at the next
  epoch boundary; the window is `≤ epoch_duration`. Tune epoch duration to the
  acceptable allocation-stall SLA. (Reads, heartbeats, manifest serving continue
  throughout — only NEW allocations to the dead owner's ranges stall.)

### Manifest state-root divergence detection (M1)

Two layers:

1. **Per-tx epoch fingerprint.** Every AllocateTx carries
   `Fingerprint = pinning.EpochFingerprint(Epoch, members)` (pinning.go:`EpochFingerprint`,
   order-independent digest of the sorted set + height — `TestEpochFingerprintAgreement`).
   `ProcessBlock` recomputes it against its own view of `V(Epoch)` and rejects on
   mismatch. A proposer that pinned against a different validator set produces a
   different fingerprint → honest nodes reject the block. This catches epoch-skew
   and non-owner writes deterministically.

2. **State root in the block (M1).** The S-Chain block commits to a root over the
   manifest+alloc state (the version layer). Because `ProcessBlock` is a pure
   function (`schain/vm.go:152`, no I/O), every honest node computes the same
   root for the same block; a divergent root means a node applied different state
   and the cert simply won't form (the divergent node is in the <1/3). The state
   root is the global divergence detector; the per-tx fingerprint is the
   early, specific one that names the exact failed invariant.

---

## 4. Linear vs DAG — RECOMMENDATION: ship v1 on the linear ChainVM

The S-Chain already runs on the **linear ChainVM** (`schain/chainvm.go`,
`_ chain.ChainVM = (*ChainVM)(nil)` at chainvm.go:23). Block production is
**VM-notification-driven, not leader-gated**: `SubmitTx` → `toEngine <- PendingTxs`
(`chainvm.go:119-124`) → engine `Notify(PendingTxs)` → `buildBlocksLocked` →
`BuildBlock` (`lux/consensus/engine/chain/engine.go:882-889, 1960-1966`). The
ProposerVM leader window is commented out (`lux/node/chains/manager.go:79`). So
**the linear engine is already leaderless at the block-production layer** — there
is no proposer-leader to remove. The only leader in the system is the S3 *raft*
leader, which the pinning function replaces.

The DAG engine (`lux/consensus/engine/dag`, `LinearizableVM` at
`lux/consensus/engine/vertex/vm.go:14-42`) adds true concurrent vertices —
`PendingTxs`/`ParseTx`/`GetTx`/`Linearize`. It would let disjoint-range
allocations commit in **physically concurrent vertices** rather than a single
linearized block stream.

**Recommendation: v1 on linear ChainVM.**

- **Trade-off named:** v1 accepts **linear ordering as the throughput ceiling** —
  all AllocateTxs share one totally-ordered block stream, so peak allocation
  throughput is one chain's block rate, not N-validators-wide. We GIVE UP
  physical write concurrency.
- **What we KEEP, which is the whole point:** we remove raft, remove the global
  single-writer/leader-election bottleneck, and get single-writer-per-range
  *semantics* (parallel decision-making + commutative disjoint mutations) on a
  VM that already exists and already commits with the right discipline
  (`schain/vm.go` M0 is done and tested). The linear engine is leaderless, so no
  consensus rework is needed to land the pinning model.
- **DAG is M2+.** Promote to `LinearizableVM` only when measured allocation
  throughput on the linear chain becomes the bottleneck. The pinning function and
  the AllocateTx state model are **identical** on both engines — the pinning
  library and tx layer do not change when we later linearize a DAG. So choosing
  linear now costs nothing in rework; it only defers physical concurrency.

This is the smallest design that completely solves the stated problem (kill raft,
single-writer-per-range, cert-gated finality) without a consensus-engine swap.

---

## 5. Migration / kill-raft path

The end state: `RegisterRaftServer` (`master.go:271`) is gone, the
`github.com/seaweedfs/raft` + `hashicorp/raft` deps leave `s3/topology` and
`s3/command/master`, and allocation/topology authority lives in S-Chain VM state.

What moves where:

| Today (raft) | Replacement | Where it lives |
|---|---|---|
| `MemorySequencer` global counter (`sequence/memory_sequencer.go`) | per-range `alloc/<range>` counter | S-Chain VM state (`schain/state`) |
| `MaxVolumeIdCommand` raft log (`cluster_commands.go`) | `AllocateTx` / volume-band counter | S-Chain VM state |
| `IsLeaderAndCanRead()` admission (`topology.go:268,374`) | `pinning.IsOwner(range, self, V(h))` | pure, local |
| raft leader election | HRW over P-Chain validator set | `schain/pinning` |
| `RegisterRaftServer` (`master.go:271`) | DELETED | — |

**What the master process becomes:** the s3 master keeps its *topology cache*,
*heartbeat ingestion*, *volume lookup*, and *HTTP/ZAP API* — all the read +
volume-server-coordination surface that is NOT consensus. It LOSES only the
allocation-authority role, which moves to the VM. The volume servers still
heartbeat to the master; the master still serves `LookupVolume`. The master
becomes an **S-Chain client**: when it needs an allocation it asks "am I the
owner?" (`IsOwner`) and if so submits an `AllocateTx`; the committed counter
comes back as VM state. The master does **not disappear** in v1 — it sheds raft
and becomes a stateless-for-allocation cache in front of the S-Chain. (Whether it
eventually merges INTO the VM process is an M3 question, out of scope.)

**Staged plan:**

- **Stage 0 (LANDED):** `schain/pinning` — pure HRW library, 9 tests green.
  Zero behavior change; nothing imports it yet. This is the smallest safe step:
  it proves the core primitive (determinism, single-owner, weight-tracking,
  minimal-disruption, fingerprint agreement) in isolation, with NO risk to raft.
- **Stage 1:** Add `AllocateTx` + per-range counter to the S-Chain VM (`schain/txs`,
  `schain/state`, `schain/vm.go::applyAllocate`). Unit-test allocation determinism
  and the IsOwner/fingerprint reject paths. Still no master change; raft untouched.
- **Stage 2:** Shadow mode. The master computes `IsOwner` and submits AllocateTx
  to the S-Chain **in parallel** with the live raft allocation, comparing the two
  for an agreement window. Raft remains source of truth. This is the
  observe-before-cutover gate.
- **Stage 3:** Cutover. Allocation reads from S-Chain VM state; raft path disabled
  behind a flag. Soak.
- **Stage 4:** Delete `RegisterRaftServer` (`master.go:271`), drop the raft deps,
  remove `cluster_commands.go` + `MemorySequencer`. `grpcS` in `master.go` now
  serves only reflection (or is deleted if nothing else needs gRPC — note the
  master service ALREADY moved to ZAP at `master.go:300`, so raft was the last
  gRPC tenant; removing it may let the whole gRPC server go).

**Smallest safe first code step: DONE — `schain/pinning/`.** It is a standalone
pure library with no behavior change and full unit coverage. Raft and master.go
are untouched (verified: no edits to either file).

---

## 6. Risks / open questions (skeptical-architect mode)

1. **Epoch-boundary race (the sharp edge).** At the instant pChainHeight advances
   from `h`→`h'`, ownership of some ranges moves from validator `α` to `β`. If `α`
   submitted an AllocateTx pinned to `h` that lands in a block whose pChainHeight
   is already `h'`, the `IsOwner(range, α, V(h'))` check fails and the tx is
   rejected — `α` must retry. Mitigation: the AllocateTx carries its `Epoch`, and
   `ProcessBlock` validates the tx's epoch against the **block's** pChainHeight; a
   tx is valid only if pinned to the block's epoch (or an explicit small grace of
   one prior epoch, IF we decide a stale-epoch tx is acceptable — defaulting to
   STRICT: tx.Epoch must equal block.pChainHeight). This turns the race into a
   clean retry, never a double-write. **Open:** decide strict vs one-epoch-grace;
   strict is safer, grace is more available. Recommend strict for v1.

2. **Validator-set churn / flapping.** A validator rapidly joining/leaving
   reshuffles its ranges each epoch. HRW bounds the blast radius (only that
   node's ranges, `TestMinimalDisruption`), but a flapping validator still stalls
   ITS ranges each flap. Mitigation: epoch duration >> validator-set update
   cadence; the P-Chain already damps validator churn. Not a correctness risk,
   only an availability one for the flapping node's ranges.

3. **Off-chain volume replication vs on-chain allocation — the layering hazard.**
   The on-chain AllocateTx assigns the *logical* id; the actual blob lands on
   off-chain volume servers with their OWN replication (the mq pinned-writer
   `PublishFollowMe` precedent, `s3/mq/topic/local_partition.go:79-92`, and volume
   replica placement). On-chain allocation does NOT guarantee the off-chain write
   succeeded. **Open question / HARD design boundary:** the manifest commit (M1
   PutManifestTx) must be emitted only AFTER the off-chain blob write is durably
   replicated, else GetManifest returns a manifest pointing at a blob that does
   not exist. The owner sequences: (a) allocate id on-chain, (b) write+replicate
   blob off-chain, (c) PutManifest on-chain. Step (b) failure must NOT leave a
   committed manifest. This is a two-phase concern the VM state model must respect
   — the AllocateTx reserves the id; the PutManifestTx commits only on confirmed
   durability. M1 design must make this ordering explicit. **This is the place a
   sloppy implementation loses data.**

4. **GetValidatorSet availability inside Verify.** `ProcessBlock` must be able to
   resolve `V(block.pChainHeight)` deterministically and WITHOUT network I/O
   (Verify is pure — `schain/vm.go:152`). `ValidatorState.GetValidatorSet` must be
   served from local, already-synced P-Chain state at the historical height `h`.
   **Open:** confirm `GetValidatorSet(ctx, h, netID)` is a local lookup (no RPC)
   for any `h ≤ current`. If it can block on network, Verify is no longer pure and
   the whole model breaks. This is a HARD prerequisite — verify before Stage 1.

5. **Counter monotonicity across re-pin.** When range `R` re-pins from `α` to `β`,
   `β` must continue the counter from `α`'s last committed value — which it does,
   because the counter is COMMITTED VM STATE (`alloc/<R>`), not owner-local. The
   new owner reads `state.Get(alloc/R)` and continues. No id reuse across handoff.
   Confirmed safe by construction — but only because the counter is on-chain, not
   in the owner's memory. (This is precisely why the global `MemorySequencer` must
   die: an in-memory counter would reset on owner change and reissue ids.)

6. **Range granularity is unspecified and load-bearing.** Too coarse (one range =
   one bucket) → a hot bucket has one owner and no intra-bucket parallelism. Too
   fine (range = object) → per-object owner lookups and no shared counter. **Open:**
   choose the partition key. Recommend `bucket` for v1 (matches S3's natural
   tenancy boundary and the mq topic/partition precedent), with `bucket/volume-band`
   as the escape hatch for hot buckets. The pinning library is granularity-agnostic
   (it hashes whatever bytes you give it), so this is a policy choice deferred to
   Stage 1, not a library change.

7. **Halt condition.** If P-Chain itself stalls (no new pChainHeight), epochs stop
   advancing and dead-owner ranges never re-pin → indefinite allocation stall for
   those ranges. This is inherited from the consensus layer (raft had the same
   class of failure on quorum loss). Acceptable: storage allocation halting on
   consensus halt is correct CP behavior; reads continue.

### HARD blockers flagged

- **#3 (off-chain durability ordering) and #4 (pure local GetValidatorSet)** are
  the two that can make leaderless-pinned-writer UNSAFE if gotten wrong. Neither
  blocks the pinning library (Stage 0, done) or the VM counter (Stage 1), but
  **both MUST be resolved before Stage 2 shadow mode**, and #4 must be confirmed
  before any AllocateTx touches Verify. If `GetValidatorSet` at a historical
  height is not a pure local lookup, STOP — the determinism premise fails and the
  design must move ownership resolution out of Verify (e.g. pin in BuildBlock and
  carry the resolved owner in the tx, with Verify only checking the fingerprint
  against the block's epoch). That fallback exists and is clean, but the decision
  must be made on evidence, not assumed.

---

## Appendix: the one landed artifact

`schain/pinning/pinning.go` — pure weighted-rendezvous owner assignment.
`schain/pinning/pinning_test.go` — 9 tests, all green:

```
TestEmptySet TestDeterministic TestSingleWriterPerRange TestParallelDifferentRanges
TestWeightedDistribution TestZeroWeightNeverOwns TestMinimalDisruption
TestEpochFingerprintAgreement TestSingleMember
ok  github.com/luxfi/chains/schain/pinning
```

No raft code, no `master.go`, no consensus engine touched.
