# M-Chain Integration

This document describes how `chains/mchain/` plugs into the
ThresholdVM substrate.

## Boot sequence

```
1. M-Chain VM starts.
2. M-Chain constructs cert.NewRegistry(cert.OwnerMChain).
3. M-Chain registers each protocol verifier:
     reg.Register(cggmp21Verifier{...})         // LaneMChainCGGMP21
     reg.Register(frostVerifier{...})           // LaneMChainFROST
     reg.Register(ringtailGenVerifier{...})     // LaneMChainRingtailGen
4. During the LP-134 grace epoch, M-Chain wires legacy aliases:
     reg.RegisterLegacyAlias(LaneTChainSign, LaneMChainCGGMP21)
     // ... per the LP-134 deprecation table.
5. M-Chain implements runtime.MChainAdapter and hands itself to the
   substrate's ceremony driver.
6. M-Chain begins accepting blocks. Each ceremony round is an entry
   in the block, decoded as types.Share, validated via reg.Verify(),
   and accumulated into a types.CeremonyRound. At round-2 close,
   the substrate calls OnFinalize and the M-Chain validator subset
   emits the cert.
```

## Validator subset

M-Chain validators are the subset of P-Chain validators with stake
delegated to M-Chain. The substrate's `Selector` interface (see
`types/participant.go`) is implemented by M-Chain over its own
delegation table.

VRF seed: `H(epoch || pchain_validator_root || ceremony_kind)`.
Stake-weighted: probability of selection ∝ delegated stake at the
epoch cutoff. Same security analysis as Lux's existing P-Chain VRF.

Permissionless: any P-Chain validator can delegate to M-Chain. No
allowlist, no admin key.

## Ceremony cadence

M-Chain block time targets **~500 ms**. This means:

- A 2-round CGGMP21 / FROST ceremony finalizes in ~1 s.
- A pre-sign + sign CGGMP21 sequence is ~1.5 s.
- Ringtail-general (2-round) is ~1 s.

GPU acceleration (LP-132) is optional; current M-Chain validators
are CPU-only. F-Chain is where GPU lives.

## Lanes M-Chain owns

| Lane | Verifier | Driver |
|---|---|---|
| LaneMChainCGGMP21 | `protocol/cggmp21.Verifier` | `protocol/cggmp21.Driver` |
| LaneMChainFROST   | `protocol/frost.Verifier`   | `protocol/frost.Driver` |
| LaneMChainRingtailGen | `protocol/ringtail_general.Verifier` | `protocol/ringtail_general.Driver` |

M-Chain **does not** own LaneFChainTFHE or LaneFChainBootstrap. The
substrate's registry refuses to register them under OwnerMChain.

## TFHE keygen — the cross-chain ceremony

M-Chain runs the FROST DKG that produces the TFHE evaluation key.
Concretely:

```go
// chains/mchain/ceremony/tfhe_keygen.go
ceremony := types.Ceremony{
    Kind: types.KindTFHEKeygen,   // cross-chain
    // ... rest as for any FROST DKG ...
}
proof, err := frostDriver.Finalize(ctx, ceremony.ID, round2Payloads)
// proof.Lane == LaneMChainFROST
// proof.Payload == serialized TFHE evaluation key
adapter.OnFinalize(ctx, ceremony, proof)
```

The substrate notices `Kind == KindTFHEKeygen` and routes the proof
into the F-Chain handoff envelope (see
`docs/F_CHAIN_INTEGRATION.md` §"Bootstrap handoff").

## Migration from T-Chain

LP-5013's T-Chain hosted both MPC and FHE. After the LP-134
activation epoch:

- All T-Chain MPC ceremonies move to M-Chain unchanged. Same
  protocol semantics, same threshold parameters; only the chain ID
  and root labels change.
- During the grace epoch, M-Chain's `LaneRegistry` accepts legacy
  T-Chain lane numbers via `RegisterLegacyAlias` and dispatches
  them to the modern `MChain*` verifiers.
- After the grace epoch, M-Chain calls `ClearAliases()` and drops
  legacy support. Any client still emitting T-Chain shares fails.
