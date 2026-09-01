# LLM context — `chains/mpcvm/`

## What this is

**This package IS M-Chain.** It is the VM for the MPC threshold-custody chain:
a plugin-loaded `chain.ChainVM` with genesis, validators, block production and
replicated consensus state. It holds the keys that custody bridged assets on
external chains.

An earlier revision of this file said the opposite — "a library substrate, not
a Lux chain", imported by `chains/mchain/` and `chains/fchain/`. Those packages
do not exist and never did. The instruction that followed from it ("do not turn
this back into a chain, no new VM ID") was wrong and, while it stood, the VM
declared a private `thresholdvm` vmID that matched nothing else in the stack.
The node installed the plugin under that dead name's CB58 while genesis
declared `constants.MPCVMID`, so M-Chain could not have started.

## Identity — the one-way door

vmID is `constants.MPCVMID` (`mpcvm`), CB58
`qCURact1n41FcoNBch8iMVBwc9AWie48D118ZNJ5tBdWrvryS`.

It is immutable once a chain is created with it, and it must agree in **all** of:

| where | what |
|---|---|
| `luxfi/constants` | `vm_ids.go` `MPCVMID` |
| `node/genesis/builder` | `registry.go` M-Chain row |
| `node/node` | `vms.go` `OptionalVMs` (plugin-only; never link in-process) |
| `node/Dockerfile` | plugin build `-o`, the build-verify list, the runtime `COPY` |
| `node/scripts` | `publish_plugin_set.sh` |
| `chains/mpcvm` | `factory.go`, `vmid_test.go` |

The plugin binary's **filename** is the CB58 — that is how the registry
resolves a `CreateChainTx`'s vmID. `TestVMID_IsCanonicalAndStable` pins it.

## What an agent must NOT do here

- Do **not** reintroduce a bare `Threshold`/`TotalParties` pair, or any single
  integer named "threshold". A quorum is a `quorum.Policy` (K-of-N) and the
  polynomial degree is obtained only via `Policy.Degree()`. Those two numbers
  differ by one, and conflating them silently provisions a wrong-degree key
  that cannot be fixed without a resharing ceremony.
- Do **not** add a second path to a key or a signature. `RunKeygen` and
  `RunSign` in `custody.go` are the only ones; the in-memory session machinery
  that used to shadow them (`keygenSessions`, `signingSessions`, `activeKeyID`,
  a `keys` map flushed at shutdown) was deleted because it was an unreplicated
  copy of state that could disagree with the chain.
- Do **not** put a secret under the `c/` prefix. `c/` is replicated and enters
  the state root; key shares live under `n/`, node-private.
- Do **not** make `Block.Verify` trust the proposer. Every operation carries a
  verifiable artifact and the block carries its post-state root.
- Do **not** reintroduce `t-chain`/`tchain` types or a "T-Chain". Per LP-1340 /
  LP-7050 it is removed with zero remainder: MPC→M-Chain, FHE→F-Chain
  (`fhevm`), teleport→B-Chain (`bridgevm`).
- Do **not** derive an external custody address with anything but Keccak-256.
  It was SHA-256 once; the published address then belongs to no one, and funds
  sent to it are unspendable.
- Do **not** make a consensus bound configurable. `maxOpsPerBlock`,
  `maxBlockBytes` and `maxFutureSkew` are constants because `Verify` enforces
  them: a bound each operator could set would let two honestly-configured
  validators reach opposite verdicts on one block. `ThresholdConfig` had a
  `MaxOpsPerBlock` knob that was read only by the builder, one edit away from
  being the split.
- Do **not** trust a field of the document you are checking against another
  field of the same document. `VerifyAttestation` compared `len(Signers)` to
  the attestation's own `Policy` and therefore held for every attestation ever
  written. The quorum comes from the key's record in consensus state.
- Do **not** deliver a ceremony message without binding it to the peer that
  sent it. `party.ID` IS the `NodeID` string, so `Gossip` refuses a message
  whose `From` is not the authenticated sender. The threshold library carries
  the sender as plain data and expects its transport to authenticate it.

## Invariants worth knowing before editing

- Ceremony ids are **derived** from the task, never announced. That is what
  makes the protocol leaderless — change the derivation and nodes stop
  converging on the same ceremony.
- The committee is the validator set (`Committee`), so the policy's `N` cannot
  exceed the network's validator count or keygen fails closed forever.
- `2K > N` (`types.HasUniqueQuorum`) is a custody policy, not a protocol
  requirement — it prevents two disjoint quorums authorising contradictory
  releases.
- `Initialize` resumes the persisted tip. It must never recompute genesis over
  live state.

## Status

- M-Chain is in the genesis chain set of every network
  (`genesis/configs/*/mchain.json`), policy `3-of-5` on
  mainnet/testnet/devnet and `2-of-3` on localnet.
- Proven: boots on luxd as a genesis chain and serves `/v1/chain/m-chain/rpc`;
  `TestBridgeCustody_ThreeOfFive` runs a real 5-validator CGGMP21 DKG at
  degree 2 with a genuine 3-of-5 signature verified and recorded on-chain.
- **Not** yet proven: a DKG across five separate luxd OS processes over real
  sockets. Resharing does not exist at all — no ceremony, and `State.ReplaceKey`
  (a second writer into the key registry, with no caller) was deleted. A key's
  participant set is fixed at the DKG that created it, so a key survives only
  while K of its original N remain. `KeyRecord.Validate` therefore rejects a
  nonzero `Generation`.
- Cert-lane enums `MChainCGGMP21=5`, `MChainFROST=6`, `MChainCoronaGen=7`,
  `FChainTFHE=8`, `FChainBootstrap=9`. Never reorder; appends only.
- `types/` and `cert/` hold the shared ceremony state machine. `types` is wired
  (`HasUniqueQuorum` is the custody floor `KeyRecord.Validate` reads); `cert/`
  has **no consumer anywhere in the repo** — it is the M/F lane-ownership
  registry, kept and fully tested, but nothing constructs one. `runtime/` and
  `protocol/{cggmp21,frost,corona_general,tfhe_keygen}` were interface-only
  packages with no implementation and no importer, and are gone; `docs/` and
  `DESIGN.md` documented them and a `chains/mchain/` tree that never existed.

## What one boot fault looked like

`parseHeldShare` handed `cmpconfig.EmptyConfig` a **nil curve**, which that
constructor exists to refuse — so it could not succeed for any input. Every
validator that actually held a share failed `Initialize` with
`load key shares: config must be initialized using EmptyConfig`; a validator
holding none restarted fine, so the path that broke was the one only real
committee members took. Nothing caught it because no test had ever stored a
real share and restarted. `realShare` in `harness_test.go` now generates one
genuine CMP config per package run for exactly that reason: the share store
round-trips through the library's encoding, which validates a Paillier secret
on the way back in, so a hand-assembled config cannot stand in.

## Where the state root is load-bearing

Linearity is not enforced by a tip check; it is enforced by the root chain, and
`Block.Verify` compares `parent.StateRoot` to this node's applied root. That
single predicate is what refuses a stale sibling, a block from another chain
(the genesis root is seeded from the chain id), and — the one that halted the
chain — a block built on a parent still in flight. Every check in
`verifyOperation` reads APPLIED state, so a block built on an unapplied parent
claims a root that skips the parent's operations: it verifies on every peer,
wins consensus, and fails at `Accept` once the parent lands.
