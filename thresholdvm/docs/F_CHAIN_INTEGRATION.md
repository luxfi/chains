# F-Chain Integration

This document describes how `chains/fchain/` plugs into the
ThresholdVM substrate.

## Boot sequence

```
1. F-Chain VM starts.
2. F-Chain constructs cert.NewRegistry(cert.OwnerFChain).
3. F-Chain registers each protocol verifier:
     reg.Register(tfheVerifier{...})            // LaneFChainTFHE
     reg.Register(bootstrapVerifier{...})       // LaneFChainBootstrap
4. During the LP-134 grace epoch, F-Chain wires legacy aliases:
     reg.RegisterLegacyAlias(LaneTChainFHE, LaneFChainTFHE)
5. F-Chain implements runtime.FChainAdapter.
6. F-Chain begins accepting blocks.
```

## Validator subset

F-Chain validators are the subset of P-Chain validators with stake
delegated to F-Chain. GPU operators self-select by delegating here
— no allowlist; the chain rejects participants who can't keep up
with bootstrap latency, but only at the validator-set level (slow
nodes get pruned by economic incentives, not by an admin key).

## Ceremony cadence

F-Chain block time targets **~2 s** to amortize TFHE bootstrap
latency. This means:

- A TFHE compute attestation ceremony finalizes in ~4 s.
- A bootstrap proof finalizes in ~2 s (single-round attestation).
- Bootstrap-key handoff from M-Chain takes one F-Chain block to
  ingest.

## Lanes F-Chain owns

| Lane | Verifier | Driver |
|---|---|---|
| LaneFChainTFHE | F-Chain TFHE compute attestation verifier | F-Chain `drain_fhe` service |
| LaneFChainBootstrap | F-Chain bootstrap-handoff verifier (`protocol/tfhe_keygen.Consumer`) | none — bootstrap proofs come from M-Chain |

F-Chain **does not** own LaneMChain*. The registry refuses
registration of MChain lanes under OwnerFChain.

## Bootstrap handoff (M → F)

When M-Chain finalizes a KindTFHEKeygen ceremony:

```
M-Chain proof:
  Lane = LaneMChainFROST
  Payload = serialized TFHE evaluation key

Wrapped F-Chain share:
  Lane = LaneFChainBootstrap
  PayloadOffset/Len = window into the upstream artifact buffer
  Verifier (F-Chain): tfhe_keygen.Consumer.VerifyHandoff(...)
                       checks the upstream M-Chain ceremony root
                       referenced by certificate_subject.
```

F-Chain's `runtime.FChainAdapter.OnBootstrapHandoff` takes the
upstream proof, verifies it under the M-Chain ceremony root in the
round descriptor, installs the new TFHE evaluation key into the
F-Chain key arena, and advances `fchain_fhe_root`.

In the same Quasar 3.0 round, `certificate_subject` binds both
`mchain_ceremony_root` (post-FROST) and `fchain_fhe_root`
(post-install). The handoff is atomic from the network's view —
either both roots advance or neither does.

## TFHE compute attestations

For each `fhe_*` precompile call on C-Chain, F-Chain runs a small
attestation ceremony:

1. The C-Chain transaction triggers a `FheCompute` event consumed by
   F-Chain's `drain_fhe` service (LP-132 §FheCompute).
2. F-Chain validators run the TFHE op on GPU, produce a compute
   transcript, and emit a `LaneFChainTFHE` share carrying the
   transcript's hash.
3. The substrate's `LaneRegistry.Verify` dispatches to F-Chain's
   TFHE verifier, which checks the transcript matches the input
   ciphertexts and the published evaluation key.
4. On finalize, the transcript hash advances `fchain_fhe_root` and
   the ciphertext output is delivered to C-Chain.

## Migration from T-Chain

LP-5013's T-Chain hosted FHE compute under a different chain ID.
The migration path is:

- All FHE compute moves to F-Chain unchanged. Kernels (LP-013)
  port across — they were never tied to T-Chain semantics.
- During the grace epoch, F-Chain accepts legacy `LaneTChainFHE`
  shares via `RegisterLegacyAlias` and dispatches them to
  `LaneFChainTFHE`.
- After the grace epoch, F-Chain calls `ClearAliases()`.
