# mpcvm — M-Chain

**M-Chain is the MPC threshold-custody chain.** `chains/mpcvm` is its VM: a
plugin-loaded `chain.ChainVM` with genesis, validators, block production and
replicated state.

It exists to hold the keys that custody bridged assets on external chains, and
to do that on-chain instead of in an off-chain signer cluster.

- **vmID** `mpcvm` = `constants.MPCVMID`, CB58
  `qCURact1n41FcoNBch8iMVBwc9AWie48D118ZNJ5tBdWrvryS`. The plugin binary's
  filename **must** be that CB58 — that is how the node resolves a
  `CreateChainTx`'s vmID to an implementation. A vmID is an immutable one-way
  door once a chain is created with it; `TestVMID_IsCanonicalAndStable` pins it
  and lists every declaration that must move together.
- **Genesis chain.** M-Chain is in the P-Chain chain set at height 0 on every
  network (`genesis/configs/*/mchain.json`), tracked by validators from boot —
  not created later by a `CreateChainTx` someone has to remember to submit.
- Per LP-134 / LP-7050 there is no T-Chain and no `teleportvm`: teleport IS
  `bridgevm` (B-Chain, LP-6000), and the FHE half of the retired ThresholdVM is
  `fhevm` (F-Chain, LP-8200). Any identifier still naming "T-Chain" or
  "ThresholdVM-as-a-chain" is stale.

## The quorum, and why it is spelled "3-of-5"

A threshold policy has two numbers that differ by one, and confusing them is
the defining failure mode of this domain:

| | meaning | where it appears |
|---|---|---|
| **K** | signers required | operator language, runbooks, genesis `policy` |
| **t** | polynomial degree = K−1 | `cmp.Keygen`, `frost.Keygen`, stored configs |

Passing an operator's `3` where a library wants `t` builds a **4-of-5** key.
Nothing errors; three custodians simply cannot sign, and for a key that already
holds funds the only fix is a resharing ceremony with parties that may no
longer exist.

So M-Chain never carries a bare threshold number. Genesis states
`"policy": "3-of-5"`, it decodes to a `quorum.Policy`, and the degree is
obtained **only** by calling `Policy.Degree()`. `luxfi/threshold/pkg/quorum` is
the one place K and t are allowed to meet.

M-Chain additionally requires `2K > N` (`types.HasUniqueQuorum`). CGGMP21 is
unforgeable against up to N−1 corruptions, so 2-of-5 is cryptographically
sound; but with two disjoint quorums, two halves of the committee could
authorise contradictory releases of the same funds.

The policy must also fit the network's validator set — the committee IS the
validator set, so `N` cannot exceed the validators that exist to hold shares.
`TestMChainPolicyIsSatisfiableByTheGenesisValidatorSet` in the node repo
enforces it.

## What is on-chain and what is not

| | replicated | in the state root | contents |
|---|---|---|---|
| `c/` consensus | yes | yes | key registry, ceremony log, blocks, height index |
| `n/` node-private | **no** | **no** | this validator's secret key shares |

The registry holds only public values — policy, participants, group public key,
custody address. A share never enters consensus state. State is written the
moment each fact becomes true, so a crash cannot lose the record of who holds
the funds, and `Initialize` resumes the accepted tip rather than recomputing
genesis.

## Blocks are verified, not trusted

- A **sign** operation carries the signature; `Verify` re-checks it against the
  group public key already in the registry. A proposer cannot fabricate one
  without forging ECDSA, and a validator that sat out the ceremony still
  verifies the result.
- A **keygen** operation carries a proof of possession by the new group key
  over its own registration. That rules out registering a key you do not
  control. The declared *degree* is bound separately, by participants
  cross-checking the record against their own share — one honest participant is
  enough to reject a mis-declared key.
- Every block carries its post-state root. `Verify` recomputes it, so two
  validators that would diverge cannot both accept.

## Leaderless and permissionless

Ceremony ids are **derived** from the task — `H(tag ‖ keyID ‖ digest ‖ sorted
signers)` — so every validator converges on the same ceremony with no announce
round and no coordinator. The signing quorum is likewise a pure function of the
task, so all nodes agree on which K sign without an election.

The committee is the chain's own validator set. Joining the signing ring is
joining the validator set: no allowlist, no operator registry, no admin-gated
key ceremony.

## Proof

`TestBridgeCustody_ThreeOfFive` runs five VMs over the real gossip transport: a
real CGGMP21 DKG at degree 2, exactly three of five sign, two decline, the
signature verifies under the group key, and a block carrying it is verified and
accepted by all five — including the two that never touched the ceremony — with
every node ending on the same state root.

## Layout

| path | role |
|---|---|
| `vm.go` | `chain.ChainVM`: Initialize/resume, BuildBlock, custody API |
| `custody.go` | ceremony lifecycle — DKG, signing, quorum selection, staging |
| `state.go` | persisted state: registry, ceremony log, roots, share store |
| `block.go` | the verified state transition |
| `wire.go` | native-ZAP struct-is-wire encodings |
| `transport.go` | gossip router (production) + in-process mesh (tests) |
| `executor.go` | drives `luxfi/threshold` protocol handlers |
| `types/` | shared ceremony state machine and the `2K > N` custody floor |
| `fhe/` | TFHE helpers retained for the F-Chain handoff |
