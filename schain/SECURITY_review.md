# S-Chain (storage VM) — Adversarial Cryptographic + Consensus Security Review

**Reviewer role:** skeptical cryptographer / protocol auditor
**Scope:** PQ-readiness + permissionless soundness gate before any public-mainnet move
**Date of review:** 2026-06-25
**Verdict (one line):** **GATE FAILS — and the primary finding is that the review subject does not exist in the codebase.** Of the security-bearing questions that *can* be answered against real code, the consensus/identity PQ story is genuinely strong; the data-availability story for a storage VM is entirely unbuilt and is the deepest blocker.

---

## 0. Threat model (stated first, per discipline)

- **Network:** public, permissionless. Validators are open, stake-bounded, and assumed up to `<1/3` Byzantine by stake (the cert-finality bound). Anyone may run a node, propose, and — in the described design — be HRW-selected as a pinned owner of a key-range.
- **Adversary classes considered:** (a) classical network adversary; (b) malicious validator / pinned owner (equivocation, censorship, invalid-manifest commit, grinding); (c) **CRQC** — a cryptographically-relevant quantum computer able to break ECDLP/pairing-DLP (forges Ed25519/ECDSA/BLS) and to run Grover (halves preimage security of hashes); (d) blob-withholding / data-availability adversary.
- **Security goals:** consensus safety (no two finalized conflicting blocks), liveness (progress despite a Byzantine minority), state integrity (committed manifest is authenticated by the state root), data availability (a committed manifest's blob is retrievable by anyone), and **post-quantum** versions of all signature/identity goals.

---

## 1. PRIMARY FINDING — the S-chain storage VM does not exist in the tree (BLOCKER, pre-everything)

Every file the review brief names is **absent**. Exhaustive search of `~/work/lux` (excluding `vendor/`, `node_modules/`, `pkg/mod/`):

| Brief-named artifact | Status |
|---|---|
| `~/work/lux/chains/schain/` (whole dir) | **does not exist** (`ls` → No such file or directory) |
| `vm.go`, `block.go` (storage VM) | absent |
| `state/state.go` (M1 manifest state root, SHA-256 fold) | absent |
| `txs/`, `object/` (on-chain manifest / off-chain blob split) | absent |
| `pinning/pinning.go` (HRW weighted-rendezvous owner assignment) | absent |
| `DESIGN_pinned_writer.md` | absent |
| `EpochFingerprint` symbol | **0 hits** anywhere in the tree |
| `M1 STATE ROOT` string | **0 hits** |
| dedicated blob / volume-server / erasure-coding DA layer | absent |

What *does* exist and is genuinely close enough to be the seed of confusion:

- **`~/work/lux/chains/dexvm/registry/manifest_pin_test.go`** — a *different* concept. "Pinning" here means binding a manifest to a **CI-approved artifact by content-hash (SHA-256)** (`manifest_pin_test.go:18-22`). It is anti-tamper for a static config file, **not** HRW weighted-rendezvous owner-assignment over the validator set.
- **`~/work/lux/consensus/docs/zookeeper-to-lux.md:23-40`, `raft-to-lux.md`, `migrate-to-lux-consensus.md`** — the "**deterministic pinned writer**" is documented here as a *coordination pattern* (writer = lexicographically-lowest member of consensus-agreed membership), replacing leader election. This is the conceptual ancestor of the brief's "leaderless pinned writer," but it is prose/design, **not** a storage VM, and crucially it is *unweighted lowest-ID*, not HRW.

**Consequence for the gate:** I cannot audit a SHA-256 fold's collision-safety, a `pinning.go` HRW grinding surface, or `Verify`'s state-root recompute **line-by-line, because they are not written.** Anyone presenting this chain as "M0+M1+pinning, ready for a public-mainnet move" is describing **vaporware against the committed tree.** That alone is a hard DEVNET-not-even-started gate. The rest of this review therefore does two things: (i) audits the **real** consensus/crypto substrate the storage VM would ride on (this is solid and reusable), and (ii) audits the **design as described in the brief** adversarially, so that when the code is written it inherits the must-fixes rather than the bugs.

---

## 2. PQ inventory — primitive by primitive (against REAL code where it exists)

### 2.1 Validator identity (NodeID) — **PQ-ready, well-constructed** ✅

`~/work/lux/ids/node_id_scheme.go`:
- ML-DSA-65 = `0x42` (`:67`), ML-DSA-87 = `0x43` (`:72`), secp256k1 = `0x90` (`:78`, classical-compat-unsafe only).
- Derivation (`DeriveMLDSA`, `:142-184`):
  `digest = SHAKE256-384(left_encode(8·len(prefix))‖"NODE_ID_V1"‖left_encode(8·IDLen)‖chainID‖left_encode(8)‖scheme‖left_encode(8·len(pk))‖pk)`, `NodeID = digest[:20]`.
- **Crucially, every field carries SP 800-185 `left_encode` length-framing** (`:168-176`) so concatenation is unambiguous — a pubkey cannot be crafted to spell another field. This is the correct domain-separation discipline.
- `chainID` is bound in → no cross-chain replay of validator registrations.

Note the 20-byte (160-bit) NodeID truncation: collision security ~80-bit classically, ~`2^{53}` under a Grover/BHT-style quantum collision search. For an *identifier* (not a commitment) bound to a full 48-bit... full 48-**byte** `FullDigest` available for transcripts, the 20-byte form is an index, not the security anchor — **acceptable**, but document that the 48-byte digest, not the 20-byte NodeID, is what binds in any security proof.

### 2.2 Validator / block / vote signatures — **PQ-ready HYBRID, strong design** ✅

`~/work/lux/consensus/protocol/quasar/`:
- Per-validator vote evidence can be **Pulsar (ML-DSA-65)**, **Corona (Ring-LWE threshold)**, **Magnetar (SLH-DSA / FIPS-205)**, or **classical BLS12-381** (`consensus_cert.go:178-191`).
- The finality certificate is a **policy-gated envelope** (`ConsensusCert`, `:296-340`). **Invariant I11** (`:80-83`, enforced `:741-750`): a classical-only cert is **rejected** under any policy requiring a PQ leg; classical (BLS) is accepted *only after every required PQ leg is already satisfied by PQ evidence* → `ErrMissingRequiredPQLeg`.
- Production profiles (`polaris.go:11-13`): **Pulsar** = BLS‖Puls‖ZK, **Aurora** = +Corona, **Polaris** = +Magnetar (cross-family). All require ≥1 PQ leg.
- Hybrid is explicit: `PolarisLegs.BLS *bls.Signature` is **optional / nil for pure-PQ** (`polaris.go:56-59`), always verified when present (`cert_policy_verify.go:122-128`).

**CRQC exposure of finality: NONE, *provided the chain runs a strict-PQ / Polaris policy*.** Breaking BLS12-381 alone does not forge a cert; the adversary must also forge the lattice/hash-based legs. This is the correct hybrid posture (NIST SP 800-208 / CNSA-2.0 transition philosophy).

**The one CRQC caveat to call out loudly:** the `ProfilePermissive` path (`profiles.go:91-143`) sets `ForbidECDSAWallets:false`, `ForbidFallbacks:false`, and the `classicalCompatUnsafe` flag (`validator_scheme.go:79-104`) admits secp256k1 (`0x90`) NodeIDs on permissive profiles. **A storage VM that launches on a permissive profile is NOT post-quantum at the consensus layer** — a CRQC forges proposer attribution and (if BLS-only legs are permitted) finality. **MAINNET MUST pin `ProfileStrictPQ` or `ProfileFIPS`** (`security_profile.go:67-72`; strict-PQ forbids classical even under the unsafe flag, `validator_scheme.go:94-98`). This is a deployment-config gate, not a code bug — but it is the difference between "PQ chain" and "PQ-only-at-the-transport chain."

### 2.3 Transport PQ — context only, NOT the consensus question ✅/⚠️

`github.com/zap-proto/go` pins X25519MLKEM768 (X-Wing hybrid KEM) for node-to-node. This is genuinely PQ for **confidentiality of links**. It says **nothing** about whether *finality* is PQ — that is §2.2's job. Do not let "PQ transport" be cited as evidence the chain is PQ; they are orthogonal axes.

### 2.4 State root + block id — SHA-256 — **adequate strength, but the *fold construction is unbuilt and the described construction is under-specified*** ⚠️

- Block ID hashing is full **SHA-256 / 32 bytes** (`~/work/lux/crypto/hash/hash.go:38`, `~/work/lux/ids/id.go:194,215,288,293`) — no truncation. Grover takes preimage to ~128-bit, collision (BHT) to ~`2^{85}`. **128-bit preimage is adequate** for the foreseeable PQ era; SHA-256 is a NIST-blessed PQ-acceptable hash (it is the basis of SLH-DSA). ✅ for block id.
- **The M1 state-root "SHA-256 fold over lexicographically-ordered manifest keyspace" with shape `len‖key‖len‖value` does not exist in code, so I review the *described* construction:**
  - **Canonicalization ambiguity risk (MEDIUM, must-fix-before-it-is-written):** a bare `len‖key‖len‖value` fold is collision-safe **only if** (a) `len` is a fixed-width, big-endian, domain-separated length encoding (not a varint, never the raw value bytes), and (b) there is a **domain-separation prefix** distinguishing "this is a manifest-entry node" from a raw key/value, and (c) the running accumulator is folded with an explicit position/index tag so two different orderings cannot alias. The **right** primitive already exists *in this very repo*: the NodeID derivation's **SP 800-185 `left_encode` framing** (`node_id_scheme.go:168-176`). The state root MUST reuse that discipline — or better, use **TupleHash256 / cSHAKE256** (already used for `ChainSecurityProfile` hashing per `security_profile.go`) which is *designed* for unambiguous tuple hashing. A hand-rolled `len‖k‖len‖v` is the classic place a 2nd-preimage/aliasing bug is born (e.g. key=`"a"`,val=`"\x01b…"` vs key=`"a\x01b"`,val=`…` colliding if the length field is itself attacker-influenced or variable-width). **Do not ship a hand-rolled fold; use TupleHash/left_encode.**
  - **Length-extension:** SHA-256 is Merkle–Damgård and IS length-extendable. A *fold* that ends on a bare `SHA256(accumulator‖next)` and exposes the digest as the state root is length-extension-exposed **if** any verifier ever checks `SHA256(stateRoot‖x)`-style continuations. Mitigate by (i) finalizing with a length/count suffix (total-entries, total-bytes) so the digest is over a fixed-length-terminated message, or (ii) using SHA-512/256 or a cSHAKE/SHA-3 sponge (no length-extension). **Prefer cSHAKE256 to kill the whole class.**

### 2.5 Pinning HRW hash + EpochFingerprint — **unbuilt; described design has a grinding surface** ⚠️ (see §3)

No `pinning.go`, no `EpochFingerprint` in the tree. The HRW hash choice is unspecified. Reviewed adversarially in §3.2.

### 2.6 zapdb integrity — **plain KV, NO state-root authentication of reads** ⚠️ (architecturally important)

`~/work/lux/database/zapdb/db.go:35` — "Database is a badgerdb backed database." It is a BadgerDB LSM KV store: Snappy compression, bloom filters, `ValueThreshold=256`, `NumVersionsToKeep=1` (`:53-91`). **There is no Merkle tree, no state root, no authenticated-read structure at the storage layer.** Authentication is entirely the application/VM's responsibility.

This is **fine as a design** (geth does the same: trie on top of a KV store) **but it means the S-chain's `Verify` MUST recompute the state root from the manifest keyspace and reject on mismatch** — exactly what the brief *claims* M1 does. Since that code does not exist, **the claim is unverified.** A node could today serve **unauthenticated manifest reads** straight off zapdb with nothing binding them to a finalized state root. This is the integrity hole the (unbuilt) M1 root is supposed to close; until the recompute-and-reject path exists and is tested, **reads are unauthenticated.**

---

## 3. Permissionless soundness of the leaderless pinned-writer (against the DESCRIBED design)

### 3.1 Censorship / liveness by a Byzantine pinned owner — **UNRESOLVED, likely a permanent capability (HIGH)**

HRW pins each key-range to exactly one owner. In a permissionless set, **whoever HRW selects for a range can withhold/refuse writes for that range indefinitely.** The brief's own self-flagged blocker (b) — "pure-local validator-set lookup in `Verify`" — is necessary but **not sufficient** for liveness. The questions the design must answer and (being unbuilt) does not:
- **What forces re-pin away from a censoring owner?** If the owner stays in the validator set (stake intact, just silent), HRW keeps selecting it. There is no described fault-detector → no re-assignment trigger → **censorship of a key-range is a permanent capability of the HRW-selected owner.** This is the dominant liveness break.
- **Required mitigation:** a *liveness fallback* — e.g., after a bounded timeout with no owner-produced manifest for a pending write, the **next HRW-ranked owner (the "second-lowest")** may produce it, gated by cert finality so the fallback cannot itself equivocate. This is exactly the `raft-to-lux.md` "next-lowest takes over deterministically" pattern (`zookeeper-to-lux.md:38-40`) but it **must be HRW-weighted, timeout-driven, and cert-gated**, and it is not specified for the storage VM. **TESTNET blocker.**

### 3.2 Owner equivocation / invalid manifests — **safe ONLY IF `Verify` fully recomputes the state root (UNVERIFIED, the code doesn't exist)**

The safety argument the brief gestures at: ">2/3 cert finality on `Verify`" stops a malicious owner. **This holds only if `Verify` is *complete*** — i.e., it recomputes the M1 state root over the full manifest keyspace and rejects any block whose header root ≠ recomputed root, AND validates that every manifest entry's blob-reference is well-formed. Since `state/state.go` and `block.go` do not exist, **this is an unproven claim.** A malicious owner committing "a manifest pointing at a blob it never stored" is **not** caught by the state root at all — the state root authenticates the *manifest bytes*, not *blob existence* (see §4). So even a perfect `Verify` does not stop the blob-withholding variant. **The safety story is half-built in design and zero-built in code.**

### 3.3 Grinding / MEV — pin-grinding to capture lucrative ranges (MEDIUM)

HRW owner = `argmax_v  H(key ‖ validatorIdentity_v) · weight_v` (standard weighted rendezvous). Two grinding surfaces:
- **Identity grind:** in a permissionless set, an adversary chooses its **validator identity / pubkey** freely before registering. It can grind candidate keys offline until its identity wins HRW for a **target lucrative key-range** (e.g., a high-value namespace). Because NodeID derivation is `SHAKE256(...‖pubkey)` and ML-DSA keygen is cheap, an attacker can generate many identities and pick the one that captures the range. **This is a real, quantum-independent grinding attack.** Mitigation: bind HRW to an **unpredictable, post-registration epoch beacon** (a VRF/VDF output or the finalized `EpochFingerprint` derived from consensus-agreed randomness *after* the validator set is frozen) so the adversary cannot grind identity against a known target ordering. The brief mentions `EpochFingerprint` — **its construction is the whole ballgame and it is unbuilt.** If `EpochFingerprint` is a plain `hash(validator-set)`, it is grindable; it must fold in **beacon randomness the registrant cannot predict.**
- **Stake-split:** if HRW weight scales with stake, splitting stake across many identities changes which ranges you can plausibly win; combined with identity-grind this lets an adversary concentrate ownership on chosen ranges. Mitigation: weight by stake but cap per-identity influence and, again, randomize the ordering per-epoch with an unpredictable beacon.

### 3.4 Epoch-boundary races on validator-set change — **double/zero-ownership window (MEDIUM–HIGH)**

When the validator set changes, HRW ownership of a range can shift. Without an atomic, cert-finalized cutover there is a window where **two owners both believe they own a range (equivocation/split-brain) or none does (stall).** The `zookeeper-to-lux.md:38` "next-lowest takes over deterministically" assumes a *single, consensus-agreed membership snapshot*; the storage VM must pin ownership to a **specific finalized height's validator set** (not a local view) and switch ownership only at a cert-finalized epoch boundary. This is the same root cause as self-flagged blocker (b) (pure-local validator-set lookup in `Verify`) and it is correctly flagged — but the fix (ownership keyed to finalized-height validator set, atomic at epoch boundary) is unspecified and unbuilt. **TESTNET blocker.**

---

## 4. Data availability — the DEEPEST issue (BLOCKER for public mainnet)

Manifests are on-chain (authenticated, once M1 exists); **blobs are off-chain in volume servers that do not exist in the tree.** For a public chain this is the classic DA problem, and the described design has **no DA guarantee whatsoever:**

- **No erasure coding / no replication proof / no DA sampling.** Searched the tree: there is no Reed–Solomon/erasure layer wired to a storage VM, no `DataAvailability` proof, no volume-server replication-proof. A committed manifest can point at a blob that **no honest node holds** → the manifest is permanently **un-GETtable**. The state root says "this manifest is canonical"; it says **nothing** about "this blob is retrievable."
- **Blob-withholding attack (permissionless):** if the blob layer is itself permissionless and the pinned owner is the only party that ever held the blob, that owner withholds the blob after committing the manifest. Finality says the manifest is valid; the data is gone. **This is unrecoverable without erasure-coded redundancy + a DA sampling scheme** (à la Celestia DAS, Ethereum EIP-4844 KZG blob commitments + custody, or Reed–Solomon + fraud proofs). None of that exists.
- **The brief's self-flagged blocker (a)** — "off-chain blob durability ordered before on-chain manifest commit" — **is correctly identified and is necessary**, but it only addresses *ordering* (don't commit the manifest until the blob is durably stored). It does **not** address *who stores it, with what replication factor, and how anyone proves availability after commit.* Ordering durability before commit on a *single owner* still loses the blob the moment that one owner withholds/dies. **Durability ≠ availability.**

**Verdict on §4:** a public permissionless storage chain whose blobs can vanish without a DA proof is **not sound to launch.** This requires an erasure-coding + replication + availability-proof design (and code, and adversarial tests) before mainnet. It is, as the brief suspects, the deepest blocker.

---

## 5. Are the 2 self-flagged blockers correct & sufficient? + ones the design MISSED

| Self-flagged blocker | Correctly identified? | Sufficient? |
|---|---|---|
| (a) off-chain blob durability ordered before on-chain manifest commit | **Yes** | **No** — fixes *ordering*, not *availability/withholding*. Durability-of-one ≠ availability-to-all. See §4. |
| (b) pure-local validator-set lookup in `Verify` | **Yes** | **No** — necessary; must be paired with §3.4 epoch-atomic ownership cutover + §3.1 censorship fallback. |

**Blockers the design MISSED (added by this review):**
1. **Data availability / blob-withholding** (§4) — no erasure coding, no DA proof. *Deepest.*
2. **Permanent censorship by HRW-selected owner** (§3.1) — no timeout-driven, cert-gated re-pin fallback.
3. **Pin-grinding via free identity choice** (§3.3) — HRW ordering must be randomized by an unpredictable post-registration beacon; `EpochFingerprint` construction unspecified.
4. **State-root canonicalization / length-extension** (§2.4) — the `len‖k‖len‖v` fold must be replaced with TupleHash256/cSHAKE256 or strict `left_encode` framing before it is written.
5. **Unauthenticated reads** (§2.6) — zapdb is plain KV; until `Verify` recompute-and-reject exists and is tested, manifest reads are not bound to finalized state.
6. **Permissive-profile CRQC exposure** (§2.2) — launching on `ProfilePermissive` makes consensus non-PQ regardless of transport. Mainnet must pin strict-PQ.

---

## 6. VERDICT & GATE

**Is the S-chain, as built (M0+M1+pinning), sound to launch as a public permissionless PQ chain?**
**No. It is not built.** "M1+pinning" describes code absent from the committed tree. There is nothing to launch.

### Ranked gate

**DEVNET-safe now:**
- The **consensus/crypto substrate** (Quasar hybrid finality, ML-DSA NodeID derivation, strict-PQ profile machinery) is real, well-constructed, and genuinely PQ when run on a strict-PQ profile. A storage VM *built on it* could run a single-operator or trusted-set **devnet** for development. Nothing about the substrate blocks devnet.
- **Caveat:** even on devnet, do not advertise DA or censorship-resistance guarantees; they don't exist.

**MUST fix before TESTNET (ranked):**
1. **Write the VM.** `vm.go`/`block.go`/`state/state.go`/`pinning/`/`object/` must exist with tests. (You cannot testnet vaporware.)
2. **State root:** implement the M1 root with **TupleHash256/cSHAKE256 or `left_encode` framing** (reuse `node_id_scheme.go:168-176` discipline), not a hand-rolled `len‖k‖len‖v` fold; finalize with a length/count terminator to kill length-extension (§2.4).
3. **`Verify` completeness:** recompute state root over full keyspace + reject on mismatch + validate every manifest entry's blob-reference well-formedness, tested adversarially (§2.6, §3.2).
4. **Ownership = finalized-height validator set, atomic epoch cutover** (fix blocker (b) fully) + **censorship fallback** (timeout-driven, cert-gated next-HRW-owner) (§3.1, §3.4).
5. **`EpochFingerprint` from an unpredictable beacon** (VRF/VDF or post-freeze consensus randomness) to defeat pin-grinding (§3.3).
6. **Pin the chain to `ProfileStrictPQ`/`ProfileFIPS`**, forbid `classicalCompatUnsafe` (§2.2).

**MUST fix before public MAINNET (ranked, on top of testnet):**
1. **DATA AVAILABILITY (deepest):** erasure-coding (Reed–Solomon) + replication factor + an availability-proof/DA-sampling scheme + blob-withholding fraud proofs. Without this, committed manifests can become permanently un-GETtable. **Hard blocker.** (§4)
2. **Durability ≠ availability:** the blob layer's storers, replication, and post-commit retrievability proof must be specified and adversarially tested against a withholding majority of a key-range's would-be storers (§4, §5(a)).
3. **Economic/slashing model for owners** that censor or withhold — HRW selection of a Byzantine owner must carry a slashable, detectable penalty, else §3.1 censorship is free.
4. **External review of the lattice/hash-based cert legs** (Pulsar/Corona/Magnetar) under the actual storage-VM finality policy, and a written reduction for the hybrid I11 invariant under composition.

### The two questions the brief expected to be blockers — confirmed:

- **PQ-signature question:** **Not a blocker at the consensus layer *if* strict-PQ is pinned** — the Quasar hybrid (BLS‖ML-DSA‖SLH-DSA, Invariant I11) is correctly built and CRQC-resistant for finality (§2.2). It **becomes** a blocker if the chain launches on `ProfilePermissive` (then a CRQC forges attribution/finality). So: *config gate, not code gate* — but a real one.
- **Data-availability question:** **Confirmed deepest blocker** — entirely unbuilt, no erasure coding, no DA proof, blobs can vanish. Public mainnet is unsound until this is designed, built, and adversarially tested (§4).

### Bottom line

The PQ *consensus* foundation Lux has built is real and good. The S-chain storage VM that is supposed to ride on it — manifest state root, HRW pinning, leaderless writer, off-chain blob layer — **is not in the tree**, and its *described* design has at minimum six exploitable gaps, the worst being **data availability**. **Gate: not even testnet-ready. Do not represent this as a launch-ready PQ storage chain.**

---

*No production code was modified by this review. The "pinned writer" and HRW state-root constructions could not be tested for collisions because they are unimplemented; §2.4 and §3.3 give the adversarial constructions to test against once the code exists.*
