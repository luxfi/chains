# AgentVM

hanzo.network's VM for attested agentic compute. Built **on** A-Chain
(`luxfi/chains/aivm`), not out of it.

A-Chain is the general attested-compute base: bonded providers, reproducible
selection, commit and reveal, quorum, slashing, settlement, receipts. AgentVM
adds the layer that says *what* was run, *how* it was isolated, *where* its bytes
went, and *which* capability it served.

There is exactly one payout path in this system and it is `aivm.Settle`. AgentVM
expresses the demand and hands it over.

---

## 1. Four values, each with one home

The central design decision is that these are **separate**, and that nothing
compares two of them.

| value | what it is | file |
|---|---|---|
| `Mechanism` | an implementation fact: what ran the workload | `mechanism.go` |
| `Property` | one atomic guarantee on one axis | `mechanism.go` |
| `Placement` | where a mechanism runs | `mechanism.go` |
| `Duplication` | how many independent operators run it | `workload.go` |

There is **no ordered assurance level**. gVisor and Firecracker are not
comparable: gVisor shrinks the host-kernel surface a guest can reach, Firecracker
gives the guest its own kernel, and which matters is a question about the
adversary. A total order would make the code state something untrue and every
caller would inherit it.

### The property axes

```
Kernel        Shared | Guest              whose kernel executes the workload
Syscall       Direct | Filtered | Mediated
Memory        Plain  | Encrypted
Attestation   None   | Software | Hardware
Replication   One    | Many     | Erasure    how the bytes were stored
```

`Properties` is a 13-bit set. A bit outside those 13 makes a demand malformed
rather than waived: `Each` walks only the properties this build defines, so an
undefined bit would otherwise be invisible to the proof walk and silently met.

A demand names properties; it never names a mechanism and never names a level.

### The grants table — the single source of truth

`mechanism.go`, `var grants`. Nothing else in the package may assert what a
mechanism guarantees, and every property check reads this array.

| mechanism | kernel | syscall | memory | attestation |
|---|---|---|---|---|
| `plain` | shared | direct | plain | none |
| `runc` | shared | filtered | plain | software |
| `gvisor` | shared | **mediated** | plain | software |
| `firecracker` | **guest** | filtered | plain | software |
| `tee` | guest | filtered | **encrypted** | **hardware** |

Read the rows: `gvisor` is alone in mediating syscalls, `firecracker` is alone
(below `tee`) in giving the workload its own kernel. Neither row contains the
other. That is the truth an ordering was hiding, and it is now data.

An unknown mechanism grants the empty set, so a mechanism byte off the wire can
satisfy nothing.

### The match predicate

```go
func (m Mechanism) Satisfies(d Properties) bool { return Grants(m).Contains(d) }
```

That is the whole selection rule. A mechanism serves a demand or it does not.
There is no ordering to slide down, so there is no downgrade to defend against:
an unavailable mechanism simply never enters the match.

Storage properties are not a mechanism's to grant, so `Engine.Runs` asks a
provider's mechanisms only about the execution half of a demand. What durability
an object gets is the object store's answer, and it is checked when a run is
attested rather than when an operator is chosen.

---

## 2. Evidence, keyed by property

`evidence.go`. Verification walks the demanded set and asks, for each property in
turn, what proving *that* property requires.

| property | what it costs to prove |
|---|---|
| `kernel.shared` | nothing — sharing the host kernel is not a claim |
| `kernel.guest` | a guest kernel measurement, a rootfs measurement, and a witness whose observed kernel **is** that measurement |
| `syscall.direct` | nothing |
| `syscall.filtered` | the digest of the filter actually applied |
| `syscall.mediated` | a witnessed identity for the user-space kernel that served the syscalls |
| `memory.plain` | nothing |
| `memory.encrypted` | a verified hardware quote |
| `attest.none` | nothing |
| `attest.software` | a signature recovering to the selected operator, over the run **and every evidence fact** |
| `attest.hardware` | a verified quote bound to this exact run |
| `replica.one` | a pin on an admitted root, and one copy read back in full whose digest is the object's |
| `replica.many` | the same, at two or more of the store addresses the pin names |
| `replica.erasure` | shards covering every index whose digests rebuild the handle's shard commitment |

### `Witness.Serves` is a claimed mechanism, and the chain cannot check it

`Evidence.Witness.Serves` is a `Mechanism` the operator supplies, and
`evidence.go` keys the whole `Grants` lookup on it. **An operator can put
`MechanismGVisor` there having run the workload bare on the host.** The digest
beside it is bound to nothing — any non-zero 32 bytes passes.

The consequence is worth stating plainly, because it is the opposite of
comfortable: an operator that ran under runc and reports that **truthfully** is
refused for a `syscall.mediated` demand, while the same operator reporting
`MechanismGVisor` falsely is accepted. Below hardware attestation the chain
refuses honesty and accepts a well-formed lie. Nothing in the type system
changes that, and an earlier version of this document claimed otherwise.

**Why it is not fixable here.** The chain sees a struct, not a machine. A
remote verifier cannot distinguish a sentry's `/proc/version` that a runner
genuinely read from inside a sandbox from the same bytes typed into a field —
that gap is precisely what confidential computing exists to close, and closing
it is what `attest.hardware` costs.

**The honest runner path is sound and is not the weak link.**
`gvisor.go:225-246` runs the probe *inside* the sandbox through the same argv
builder the workload uses, and refuses with `ErrNotMediated` when the reply does
not name a sentry. An operator running the shipped runner cannot accidentally
over-claim. The gap is that the chain cannot tell that operator from one who
skipped the runner.

### What is proven and what is attributed

Below `attest.hardware` the guarantee is **attribution, divergence and bond**,
not proof:

- **attribution** — every attestation carries a signature recovering to the
  selected operator, required by `Attest` whatever the demand says, so a false
  statement is non-repudiably somebody's.
- **divergence** — the task draws N operators in N declared domains and pays only
  the group that agreed. A liar must out-number the honest majority, not merely
  lie well.
- **bond** — `MinProviderBond` is at stake for a withholder, and the forgery
  floor is `threshold × MinProviderBond` regardless of how well-formed the lie is.

At `attest.hardware` the guarantee is cryptographic: a quote signed on the
vendor's curve by a key the chain admitted, whose report binds this run. That is
the only property here that does not rest on an operator's bond — and it rests
instead on whoever may call `AdmitAttestingKey` (see §11).

---

## 3. The hardware quote

`quote.go`. The quote carries the vendor's report bytes **verbatim** — exactly
the span the hardware signature covers — and nothing beside them. The binding and
the measurement are read out of those bytes at the vendor's own offsets. Carrying
them as separate fields would let an operator present a report that says one
thing and fields that say another.

| | SEV-SNP | TDX |
|---|---|---|
| signed span | `[0, 0x2A0)` of ATTESTATION_REPORT | 48-byte header + 584-byte TD quote body |
| `REPORT_DATA` | `0x050`, 64 bytes | `0x208` in the body (568 from span start) |
| measurement | `0x090`, 48 bytes | `MRTD` at `0x088` (184 from span start) |
| curve / hash | ECDSA P-384 / SHA-384 | ECDSA P-256 / SHA-256 |

Three checks, all of which must pass: the key digest is admitted, the signature
verifies, the report's binding equals the run's claim. An empty root set admits
nothing, so hardware attestation is refused until a root exists.

**The certificate chain is validated off-chain, at admission.** What the chain
keeps is the resulting key digest. Signature and key ride in the one encoding
every verifier wants — `r||s` big-endian at the field width, uncompressed SEC1
point — and a device emitting another encoding normalises at its own edge.

---

## 4. Data plane: S-Chain claim, S3 substance

`handle.go`. A workload's input and a run's output are content-addressed
`Handle`s: a digest, a size, and where on S-Chain the object's manifest is
committed. Bytes never ride on chain.

The digest is AgentVM's own keccak over the full object. It is **not** the
manifest's ETag: `schain/object` computes that as `base64(md5(blob))` for S3 wire
compatibility, and MD5 has been collision-broken for two decades.

### Durability has two homes, and this is not the one that owns it

`hanzoai/s3` already owns durability: 218 files with replication, 186 with
erasure coding, 62 `ec_`, 99 with checksums, and it answers placement directly
from its volume index — `GetVolumeLocations(volumeID, collection)` in O(1), plus
`GetECShardLocations` with per-disk `ShardIds`. That index **sees disks**.

So AgentVM does not model replica counts, erasure coding or placement. An
earlier version of this file counted copies over `(Cluster, Host)` pairs an
operator filled in, which was a weaker answer wearing a stronger one's clothes.
It is deleted.

What AgentVM keeps is the half no storage layer can supply: **the object that
came back hashes to the object the handle names.**

- A `Replica.Witness` is the digest of the bytes read **in full**. Not a length,
  not a successful open — a short read in this estate turned out to be a dead
  volume server's stale address behind a good `Stat`.
- A witness that does not match is not a weaker copy, it is a **different
  object**, and it is not counted (`TestAWrongObjectIsNotAWeakCopy`).
- Copies are counted against **the store's own addresses** — `Replica.Shard`
  indexes the file list the pin carries — so one blob read four times is one copy
  (`TestOneAddressReadTwiceIsOneCopy`), and whether those addresses sit on
  independent hardware is the volume index's answer, not a field here.

### What a pin does and does not establish — measured

`schain/state.Root` is a **SHAKE256 fold** over the whole committed keyspace
(domain `SCHAIN_STATE_ROOT_V2`, SP 800-185 `left_encode` framing). A fold has
**no membership proof**: establishing that one manifest is under a root means
recomputing the fold over the entire keyspace, which a verifier on another chain
cannot do.

So a `Pin` names a root this chain has **admitted** and binds the handle to it,
and the operator signs that statement. It is **attributable, not
proven-included**. Proving inclusion needs a commitment with membership proofs on
S-Chain's side; that is S-Chain's change to make.

Nor does a pin make bytes available. `schain/SECURITY_review.md` §4 names data
availability as S-Chain's deepest unsolved blocker — no erasure-coded redundancy,
no availability sampling — so a committed manifest can point at bytes no honest
node holds. **AgentVM cannot close that and does not claim to.** What it does is
refuse to believe a durability claim that shows nothing.

---

## 5. Parallelism: capacity, identity, domain

`scheduler.go`. Three things a "node" braids together, kept apart:

| | | |
|---|---|---|
| **capacity** | how much runs at once | a number one operator advertises |
| **identity** | who is accountable | one address, one bond |
| **domain** | what fails together | a claim about independence |

A-Chain's `eligibleSet` filters on registration, bond and model spec — there is
no capacity field and no failure-domain field. So N processes on one machine, each
with its own address and bond, form an eligible set of N and pass the margin
guard, because **the guard counts addresses**. Every replica shares a kernel, a
disk and a power supply. The bond makes that accountable, not independent.

AgentVM's answer:

- **Capacity** is why a many-core machine should be *one* operator with many
  slots. `Engine.Capacity` / `hold` / `release`; a slot is occupied for exactly as
  long as the operator owes an answer.
- **Domain** is what makes duplication mean something. `Engine.Pool` groups
  candidates by declared domain and lets **one operator per domain** into the
  pool, so a draw of N selects N distinct domains.

Because the pool handed to A-Chain has one entry per domain, **A-Chain's existing
margin guard now applies to domains** — strictly stronger than the guard it rides
on, and weakening nothing.

```
requiredMargin(n) = max(2, n/2)      pool must be >= n + requiredMargin(n)
N=1 -> 3 domains   N=2 -> 4   N=3 -> 5   N=5 -> 7   N=10 -> 15
```

There is **no bootstrap flag, no development mode, no configurable floor**. A
network that cannot field enough independent domains does not open the task
(`TestMarginIsNotWeakened`, `TestDuplicationDrawsDistinctDomains`).

**An advertisement is the operator's own.** `Advertise` requires a signature
recovering to the operator it speaks for, and a `Nonce` that exceeds the last one
accepted. Without the signature anyone could rewrite a victim's advertisement and
collapse it out of the pool; without the nonce the victim's *own* older
advertisement could be replayed to the same effect
(`TestAdvertiseIsTheOperatorsOwn`, `TestAdvertiseRefusesAReplay`).

**A domain is a CLAIM.** Nothing here proves two operators are independent, and a
dishonest operator can declare as many domains as it likes. What the claim buys
is a policy duplication can be written against and a statement the bond is behind.
Proving independence needs evidence from outside this chain — distinct attestation
roots, distinct network provenance — and none of that is claimed.

---

## 6. Capability catalog: identity separate from routing

`catalog.go` says **what exists**. `scheduler.go` says **who serves it**. They
have different lifecycles: a surface changes rarely and deliberately, a fleet
changes constantly.

The catalog is versioned and content-addressed. A measured surface of 1,612 paths
and 2,253 operations is one 32-byte commitment plus a digest per group. Adding the
2,254th operation is a **version bump**, not a code change.

The catalog is **derived, never transcribed**: `cmd/catalog` reads an OpenAPI 3
JSON document and emits it.

```
catalog -in openapi.json -version 7 -out catalog.json
```

Groups are the first path segment after the version prefix — `/v1/ai/…` is `ai`,
`/v1/iam/…` is `iam` — which is how the surface is already organised. Operation
identifiers are sorted before folding, so the digest does not depend on the order
the document listed them (`TestDeriveIsStable`).

A version is written once. Re-registering a *different* surface under a number
that already means something would change what every workload written against it
asked for (`TestCatalogVersionIsWrittenOnce`).

---

## 7. Lifecycle

```
Open  ──▶ Commit ──▶ Attest ──▶ Reveal ──▶ Settle
 │          │          │          │          │
 │          │          │          │          └─ aivm.SettleDue: compare, pay,
 │          │          │          │             slash, emit receipt; then give
 │          │          │          │             back the slots
 │          │          │          └─ refuses an answer the operator has not
 │          │          │             attested
 │          │          └─ checks the evidence against the task's demand
 │          └─ aivm.CommitResponse, operator-bound
 └─ validate, capability, replay, price, one-per-domain pool, aivm.OpenTask
```

### Evidence stops work at reveal, not at settlement

**Unconditionally.** No operator answers a task without first attesting the
answer, whatever the workload asked for. A receipt failing its evidence check
never becomes a reveal, so it never reaches the tally and **can never settle**
(`TestRevealRefusedWithoutEvidence`).

The gate used to be guarded on a non-empty demand, which made the safe path the
one a workload had to opt into: `Demand` is a bitset in a struct field, so a
workload that never mentioned isolation held the empty set and settled with no
attestation at all. `AttestNone` is how a workload says it requires nothing;
saying nothing is not the same thing
(`TestRevealRequiresAttestationEvenWithNoDemand`).

A workload that named a `Placement` is also answered from that place: the task
records where it asked to run, the evidence declares where it did, and `Attest`
compares them (`TestAttestChecksPlacement`).

`Engine` holds `*aivm.Engine` **privately rather than embedding it**: embedding
would promote `RevealResponse` onto the type and give an operator a way to answer
without showing evidence.

AgentVM drives A-Chain's engine over **AgentVM's own state and ledger**. No
A-Chain node serves those slots, so the two chains share code and share no state.

### Claim, evidence and signature are not circular

- `Receipt.Claim()` is a statement about the run — workload, operator, output,
  exit, consumption — fixed **before** any evidence exists, so a hardware quote
  can be requested against it (`report_data = claim`).
- `Evidence.Attestation(claim, out)` covers the claim **and every evidence fact**,
  so a signature cannot be moved onto different evidence for the same run
  (`TestSignatureCoversEveryFact`).

### Attestation is always attributed

`Attest` requires the evidence signature to recover to the calling operator
whatever the demand says, because the chain is recording a statement and a
statement needs an author. Without it an operator could present a peer's evidence
as its own (`TestAttestRefusesAnotherOperatorsEvidence`).

---

## 8. Price

`price.go`. Price is a **pure function of the workload**, so nobody names a
number and every validator computes the same reward.

It is over what the run **reserves**, not what it uses — it has to be, since the
reward is escrowed before anyone runs. Consumption is not thereby unpriced: a
receipt claiming more than its ask is refused (`Receipt.Check`), so the ask is a
real ceiling.

Properties are surcharges in percent, summed and applied as one multiplication and
one division so the result does not depend on summation order. They are not a
ladder: each property costs what providing it costs.

---

## 9. Tenancy

A workload carries a `Payer`, signed over the workload id. Anyone may deliver a
workload; only its payer can spend against their balance
(`TestOpenRefusesUnauthorizedSpending`). There is no parallel identity concept.

A private workload is expressed with the properties that already exist —
`MemoryEncrypted` + `AttestHardware` — not with a separate flag.

---

## 10. Changes to `aivm`

The A-Chain package is **additive at every exported surface**; no existing
signature, encoding or behaviour changed. The pre-existing `aivm` suite passes
unchanged, which is the proof.

- **`aivm/compose.go`** (new file): `TaskSpec`, `OpenTask`, `Eligible`, `Staked`,
  `Draw`, `RequiredMargin`. A specialised VM supplies its own selection policy;
  everything after the pool — distinctness, margin, escrow, burn, draw, record —
  is the same one mechanism the model path uses.
- **`aivm/compose_test.go`** (new file): the duplicate-pool refusal and the
  distinctness of a draw.
- **`aivm/task.go`**: `createTask` (unexported) takes its candidate pool as a
  parameter instead of building it from a model spec, and reduces it with
  `distinct()` before the margin is counted. On the model path the pool comes
  from `eligibleSet`, which reads an append-only set and cannot repeat an
  address — so that call is a no-op and the behaviour is unchanged. A caller's
  pool carries no such history, and without the reduction one address repeated
  five times would have been drawn five times and produced a quorum of one party
  agreeing with itself (`TestOpenTaskRefusesARepeatedPool`).
- **`aivm/import_c_intent.go`**: passes `eligibleSet(...)` explicitly. The pool,
  its order and the resulting draw are identical.

This opens no door on A-Chain. Its VM's only task-opening call is still
`importPending → ImportCommittedIntent`, under consensus, behind a committedness
proof.

---

## 11. Who may call what

Three entry points distrust their caller and three trust it. The difference is
not accidental, but it is a **contract**, and only the first three enforce it:

| entry point | authorization |
|---|---|
| `Open` | payer signature over the workload id |
| `Attest` | evidence signature recovering to the calling operator |
| `Advertise` | operator signature + monotonic nonce |
| `AdmitAttestingKey` | **none — caller contract** |
| `AdmitStateRoot` | **none — caller contract** |
| `Revoke*` | **none — caller contract** |

The admissions are governance operations. **Admitting one key satisfies every
hardware-attestation demand on the chain** — the only guarantee here that does
not rest on an operator's bond — so a VM binding MUST reach them only from the
consensus-gated block path and MUST NOT route any request surface to them.

This is the convention A-Chain already uses for `SetCommitVerifier`, and like
that one it is a contract rather than a check: nothing in this package can tell
an authorised caller from an unauthorised one, because the authority is the
chain's own consensus and the engine type does not see it. They fail closed on a
fresh chain (`TestFreshChainBelievesNothing`), which bounds the damage to
whatever a binding chooses to expose — and that is the whole of the mitigation.

---

## 12. Files

| file | lines | what |
|---|---|---|
| `engine.go` | 435 | Open, Commit, Attest, Reveal, Settle, Trust |
| `mechanism.go` | 359 | Mechanism, Property, Properties, the grants table, Placement |
| `evidence.go` | 348 | Witness, Evidence, the per-property proof walk |
| `workload.go` | 311 | Code, Var, Resource, Capability, Workload, authorization |
| `scheduler.go` | 304 | Advertisement + its signature, candidates, the one-per-domain pool |
| `handle.go` | 248 | Handle, Pin, Replica, Durability |
| `quote.go` | 208 | SEV-SNP / TDX report layouts, ECDSA verification |
| `state.go` | 196 | slots, namespaces, encoders, the enumerable set |
| `catalog.go` | 168 | Catalog, Group, on-chain registration |
| `price.go` | 108 | the pure price function |
| `errors.go` | 88 | every refusal |
| `run.go` | 74 | Receipt, Claim, Check |
| `runner/runner.go` | 135 | Runner, Attestor, Result, Set |
| `cmd/catalog/` | 202 | the OpenAPI catalog generator |

5,842 lines of code, 4,695 of tests, 278 tests, zero skips.
