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
- Do **not** reintroduce `t-chain`/`tchain` types or a "T-Chain". Per LP-134 /
  LP-7050 it is removed with zero remainder: MPC→M-Chain, FHE→F-Chain
  (`fhevm`), teleport→B-Chain (`bridgevm`).
- Do **not** derive an external custody address with anything but Keccak-256.
  It was SHA-256 once; the published address then belongs to no one, and funds
  sent to it are unspendable.

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
- Proven: boots on luxd as a genesis chain and serves `/v1/bc/m-chain/rpc`;
  `TestBridgeCustody_ThreeOfFive` runs a real 5-validator CGGMP21 DKG at
  degree 2 with a genuine 3-of-5 signature verified and recorded on-chain.
- **Not** yet proven: a DKG across five separate luxd OS processes over real
  sockets, and resharing/refresh (`ReshareKey`/`RefreshKey` are not
  implemented — a validator joining after a key exists is not yet shared in).
- Cert-lane enums `MChainCGGMP21=5`, `MChainFROST=6`, `MChainCoronaGen=7`,
  `FChainTFHE=8`, `FChainBootstrap=9`. Never reorder; appends only.
- `types/`, `cert/`, `runtime/` hold the shared ceremony state machine that
  F-Chain will also consume. `types` is wired (the custody floor); `cert/` and
  `runtime/` are **not** yet consumed by the VM.
