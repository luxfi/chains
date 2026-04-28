# Architecture

ThresholdVM is the **shared library substrate** beneath M-Chain and
F-Chain. The substrate has zero runtime presence; it compiles into
both chains' binaries.

## The three pieces

```
+-----------------------------------------------------------+
|                      Quasar 3.0                           |
|  (consensus, certificate_subject binds all chain roots)   |
+-----------+--------------------------+--------------------+
            |                          |
            | mchain_ceremony_root     | fchain_fhe_root
            |                          |
   +--------v---------+      +---------v--------+
   |     M-Chain      |      |     F-Chain      |
   |  validators      |      |  validators      |
   |  + MPC drivers   |      |  + GPU drivers   |
   |  + lane registry |      |  + lane registry |
   |  (MChainCGGMP21, |      |  (FChainTFHE,    |
   |   MChainFROST,   |      |   FChainBootstr) |
   |   MChainRingTl)  |      |                  |
   +--------+---------+      +---------+--------+
            |                          |
            |       imports            |
            |                          |
            +----------+---------------+
                       |
              +--------v---------+
              |   thresholdvm    |
              |  (this library)  |
              |                  |
              | types/           |
              | protocol/*/iface |
              | cert/lane,subj   |
              | runtime/*Adapter |
              +------------------+
```

## What lives where

| Concern | Owner |
|---|---|
| Ceremony state machine (Registered → Round1 → Round2 → Finalized) | substrate (`types/ceremony.go`) |
| Share envelope `(offset, len)` indirection | substrate (`types/share.go`) |
| Participant set + Selector contract | substrate (`types/participant.go`) |
| Cert lane registry (per-owner enforcement) | substrate (`cert/lane.go`) |
| `certificate_subject` binding | substrate (`cert/subject.go`) |
| CGGMP21 / FROST / Ringtail-general drivers | M-Chain (`chains/mchain/protocol/*/`) |
| TFHE bootstrap-key generation | M-Chain producer + F-Chain consumer |
| TFHE compute kernels | F-Chain (`chains/fchain/`) |
| Block production, gossip, p2p | each chain's VM |
| Validator selection (stake-weighted VRF) | each chain's `Selector` impl |
| Persistence | each chain's database |

## Why orthogonal at the type level

The substrate's `LaneRegistry` carries an `Owner` field. `Register`
checks the verifier's lane against the owner's allowed range:

- `OwnerMChain` accepts lanes 5..7
- `OwnerFChain` accepts lanes 8..9

A misrouted verifier (e.g. F-Chain trying to register a CGGMP21
verifier) returns an error from `Register` at boot. The chain fails
to start, not at runtime in the middle of a ceremony.

Similarly, `runtime.MChainAdapter` and `runtime.FChainAdapter` are
disjoint interfaces. A chain implementing both is a code smell that
shows up in code review (and in `go doc` output).

## Why one substrate, two chains

The state machine is identical. The envelope is identical. The cert
binding is identical. The only thing that differs across the two
chains is the per-protocol payload — which is opaque to the
substrate and dispatched by lane.

If we kept M-Chain and F-Chain on separate substrates, we would have
two copies of the state machine, two copies of the share envelope,
two copies of the subject binding. Drift is inevitable; bugs would
fix on one side and not the other.

The substrate is the orthogonal piece. The chains are the
operational pieces. PHILOSOPHY.md §3.

## Cross-chain handoff

The only cross-chain ceremony today is **TFHE bootstrap-key gen**:

1. M-Chain runs FROST DKG on the TFHE secret-key polynomial. The
   ceremony has `Kind = KindTFHEKeygen`, `Lane = LaneMChainFROST`.
2. M-Chain finalizes; the proof's payload is the serialized TFHE
   evaluation key.
3. The substrate's handoff envelope wraps the M-Chain proof into a
   F-Chain `Share` with `Lane = LaneFChainBootstrap`. The wrapper's
   payload is `(offset, len)` into the upstream artifact buffer.
4. F-Chain ingests via `OnBootstrapHandoff`, verifies the upstream
   M-Chain ceremony root from the round descriptor, installs the
   key, advances `fchain_fhe_root`.
5. Quasar 3.0's `certificate_subject` for the round binds both
   `mchain_ceremony_root` (post-FROST) and `fchain_fhe_root`
   (post-install). Atomic from the network's view.

No new envelope type. The handoff is just two shares on two lanes
with a deterministic wrapping.

## References

| LP | Topic |
|---|---|
| LP-019 | Threshold MPC |
| LP-013 | FHE on GPU |
| LP-076 | Universal Threshold Cryptography |
| LP-132 | QuasarGPU Execution Adapter |
| LP-134 | Lux Chain Topology |
| LP-020 | Quasar Consensus 3.0 |
