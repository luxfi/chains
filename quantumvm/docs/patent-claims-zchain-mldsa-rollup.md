# Z-Chain Groth16-over-ML-DSA Per-Epoch Rollup — Patent Claim Drafts (Attorney Review)

> **Internal working document.** Bundle #14 of the Lux PATENT-INVENTORY.
> Not a filed application; not a legal opinion.

## §0 Bundle summary

- **Title**: Per-epoch rollup of `n` individual FIPS 204 ML-DSA-65
  identity signatures into a single Groth16 zero-knowledge proof
  on the BLS12-381 curve, using a shared-matrix optimization
  amortizing the per-validator `2^22.5` R1CS constraint count
  below `n × 2^22.5` for `n ≥ 21` validators.
- **Inventors**: Lux Industries cryptography team.
- **Priority date**: file as US provisional within 12 months.
- **Estimated claim count**: 15 (2 independent + 13 dependent).
- **Defensive-vs-offensive**: **Offensive.**

## §1 Background and prior art

1. **Bowe-Gabizon-Miers 2017 / 2018 Groth16 trusted setup**: MPC
   ceremony for Groth16 SRS over BLS12-381.
2. **Plumo / Celo Plumo light-client proofs** (Plumo 2020-2022):
   BLS aggregation in Groth16 / PLUMO.
3. **EthSTARK / StarkNet ML-DSA verifier** (recent 2024-2026): no
   public production Groth16-over-ML-DSA verifier circuit.
4. **Filecoin Groth16 storage proofs**: Groth16-over-PoSt;
   different inner statement.
5. **Halo2 / PLONK ML-DSA verifier research** (academic 2024-
   2026): research stage; not production.

Closest prior art: no public production circuit verifies ML-DSA-65
inside Groth16 at scale. Academic papers exist (e.g., a
sketch from 2024 estimating ~2^22.5 constraints for a single
ML-DSA-65 verification), but the **shared-matrix optimization
across n=21 validators** is the load-bearing novelty.

## §2 Inventive concept

For each consensus epoch, every validator emits a single-party
FIPS 204 ML-DSA-65 signature over a canonical epoch transcript.
Z-Chain rolls these `n` signatures into a **single Groth16 proof**
of ~192 bytes:

```
Statement (public input):
  - n validator identity public keys (committed via 48-byte commitment)
  - epoch transcript hash
  - signer-set bitmap

Witness (private input):
  - the n ML-DSA-65 signatures themselves

Constraint:
  For every i ∈ active-signer-set:
    FIPS-204-ML-DSA-65-verify(pk_i, transcript, sig_i) = TRUE
```

**Shared-matrix optimization**: the FIPS 204 expansion of the
public-matrix `A` from the seed is the dominant constraint cost.
Since every validator's ML-DSA-65 verification at the same epoch
uses the SAME `A` matrix (the SHARED group matrix from the
threshold Pulsar lane — see Pulsar's claim 6), the expansion
sub-circuit is computed ONCE in the rolled-up Groth16 statement
and reused across all `n` verifications, amortizing total
constraint count to below `n × 2^22.5` for `n ≥ 21`.

## §3 Independent claims (drafts)

### Claim 1 (rollup circuit claim, draft)

> **Claim 1.** A computer-implemented method for producing a
> compact zero-knowledge proof attesting that `n` post-quantum
> identity signatures are individually valid under their
> respective signer public keys, the method comprising:
>
> (a) provisioning a Groth16 arithmetic constraint system on the
>     BLS12-381 elliptic curve, said constraint system encoding
>     the FIPS 204 ML-DSA-65 verification predicate as a system
>     of rank-one-constraint statements (R1CS) over the BLS12-381
>     scalar field;
>
> (b) receiving, per consensus epoch, `n` per-validator FIPS 204
>     ML-DSA-65 signatures `{σ_i}_{i ∈ active-set}` over a
>     canonical epoch transcript `m_epoch`, said signatures
>     produced by each validator independently under its
>     long-term identity ML-DSA-65 secret key;
>
> (c) computing a Groth16 witness assignment that satisfies the
>     constraint system of step (a) with public inputs `(m_epoch,
>     {pk_i}, signer_bitmap)` and private inputs `({σ_i})`;
>
> (d) computing the Groth16 proof `π_ID` of approximately 192 bytes
>     from the witness assignment using the trusted-setup
>     structured reference string of step (a);
>
> (e) emitting the proof `π_ID` as the per-epoch attestation
>     artifact, said proof verifiable by any party in
>     approximately one millisecond using the Groth16 verifier
>     equation under the BLS12-381 pairing.

### Claim 2 (shared-matrix amortization claim, draft)

> **Claim 2.** The method of claim 1, wherein the FIPS 204 ML-DSA-65
> verification predicate of step (a) is structured to share, across
> all `n` per-validator sub-circuits, the FIPS 204 §3.5.3 ExpandA
> sub-circuit that expands the public-matrix seed into the public
> matrix `A`, such that the total constraint count of the rolled-
> up circuit is approximately
>
>     C_total = C_ExpandA + n × C_per-validator-residual
>
> rather than
>
>     C_total = n × (C_ExpandA + C_per-validator-residual)
>
> where `C_ExpandA ≈ C_per-validator-residual / 2` per measurements
> on the production circuit, yielding an amortized total of
> approximately `n × 2^20` constraints for `n ≥ 21` validators (a
> ~2x reduction compared to per-validator independent circuits).

## §4 Dependent claims (drafts)

**Claim 3.** The method of claim 1, wherein the structured
reference string of step (a) is produced by a multi-party
computation ceremony with at least one honest participant
contributing before the SRS is finalized, satisfying the
Bowe-Gabizon-Miers ceremony soundness.

**Claim 4.** The method of claim 1, wherein the per-validator
ML-DSA-65 signatures of step (b) are produced independently —
each validator using its own long-term identity ML-DSA-65 secret
key — and the signatures are NOT a threshold signature output.

**Claim 5.** The method of claim 1, wherein the proof `π_ID` is
embedded in a blockchain finality certificate alongside (i) a
classical BLS12-381 aggregate signature and (ii) a Module-Lattice
threshold signature (Pulsar), forming a three-lane parallel-
hardness QuasarCert.

**Claim 6.** The method of claim 1, wherein the signer bitmap
field of the public input identifies which `n` validators of
the active validator set are attesting to the epoch transcript,
with at most one bit per validator and the bit width
proportional to the validator-set cardinality.

**Claim 7.** The method of claim 1, wherein the proof verification
is performed by an EVM precompile at the Lux unified PQCrypto
block (e.g., a Groth16 verifier precompile co-located with the
P3Q STARK verifier), allowing the proof to be verified by smart
contracts and cross-chain bridges.

**Claim 8.** The method of claim 1, wherein the proof generation
is performed by a Z-Chain validator that aggregates the per-
validator ML-DSA-65 signatures into a single Groth16 proof
asynchronously between consensus rounds, with one proof per
epoch.

**Claim 9.** The method of claim 2, wherein the FIPS 204 §6.2
inner-loop sub-circuit (the rejection-sampling-bounded high-bits
decomposition and hint verification) is implemented in R1CS over
the BLS12-381 scalar field with field-operation cost dominated by
the polynomial arithmetic over `R_q` for the FIPS 204 prime
`q = 2^23 - 2^13 + 1`.

**Claim 10.** The method of claim 1, wherein the BLS12-381 curve
is chosen for the Groth16 SRS because it provides ≥ 128 bits of
classical pairing security, and wherein the underlying Module-
LWE assumption of FIPS 204 ML-DSA-65 provides post-quantum
security for the witness ML-DSA-65 signatures, making the
proof simultaneously classically-sound (Groth16 + BLS12-381) and
post-quantum-binding (the witnessed signatures themselves are
PQ-secure).

**Claim 11.** The method of claim 1, wherein a PLONK-style
universal-SRS upgrade path is supported, allowing the chain to
migrate from Groth16 to PLONK without re-running the trusted-
setup ceremony.

**Claim 12.** The method of claim 1, wherein the per-epoch
Groth16 proof generation on production hardware (AWS p4d.24xlarge
or equivalent) completes in approximately 5-15 milliseconds, and
proof verification completes in approximately 1-3 milliseconds.

**Claim 13.** The method of claim 1, wherein the proof generator
employs GPU acceleration for the multi-scalar-multiplication
operations of the Groth16 prover, dispatching to a luxfi/accel
GPU backend when batch size exceeds 64.

**Claim 14.** The method of claim 1, wherein the same circuit
also supports FIPS 205 SLH-DSA verification as an alternative
identity-signature scheme, allowing chains to migrate between
ML-DSA-65 and SLH-DSA identity schemes without re-deploying the
Z-Chain.

**Claim 15.** A non-transitory computer-readable medium storing
the Groth16 R1CS constraint system, the trusted-setup SRS, the
prover and verifier executables, and the EVM precompile shim that
exposes the verifier to smart contracts.

## §5 Reference to implementation

- `~/work/lux/chains/quantumvm/quasar.go`,
  `~/work/lux/chains/quantumvm/quasar_witness.go`.
- `~/work/lux/chains/quantumvm/quantum/signer.go`,
- `~/work/lux/chains/quantumvm/stamper/quantum_stamper.go`,
- `~/work/lux/chains/quantumvm/stamper/realtime_stamper.go`,
- `~/work/lux/proofs/quasar-cert-soundness.tex` App B (R1CS
  constraint count derivation).
- Performance note: proof verification ~1-3 ms CPU per
  consensus CLAUDE.md.

## §6 Defensive vs offensive

**OFFENSIVE.** Production Groth16-over-FIPS-204-ML-DSA-65 is a
defining moat for Z-Chain's value as the PQ-rollup market grows.

---

**Document metadata**
- Path: `chains/quantumvm/docs/patent-claims-zchain-mldsa-rollup.md`
- Bundle: #14 of `lps/PATENT-INVENTORY.md`
- Created: 2026-05-19
