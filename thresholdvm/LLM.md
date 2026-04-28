# LLM context — `chains/thresholdvm/`

## What this is

ThresholdVM is a **library substrate**, not a Lux chain. It is imported by:

- `chains/mchain/` — MPC ceremonies (CGGMP21, FROST, Ringtail-general)
- `chains/fchain/` — FHE compute (TFHE bootstrap, encrypted EVM)

The substrate hosts the ceremony state machine, share envelope,
QuasarCertLane registration, and certificate-subject binding logic
shared by both chains.

## What an agent must NOT do here

- Do **not** turn this back into a chain. No `factory.go` exposed to
  `chains.Manager`. No new VM ID. M-Chain and F-Chain are the chains.
- Do **not** import M-Chain or F-Chain code from this package. The
  dependency graph is `mchain → thresholdvm` and `fchain → thresholdvm`;
  reverse edges are forbidden.
- Do **not** add a protocol implementation here. Protocol packages
  expose **interfaces only**; impls live in the chain that runs the
  protocol (CGGMP21 in M-Chain, TFHE keygen straddles M-Chain →
  F-Chain via the handoff envelope).
- Do **not** introduce `t-chain` / `tchain` types here. The legacy
  `vm.go`, `block.go`, `factory.go`, `fhe/`, `cmd/` files in the
  parent directory are the deprecated T-Chain shim from LP-5013.
  They exist only for one-epoch grace-window migration, then are
  removed.

## Status

- Substrate ships with Quasar 3.0 activation on **2025-12-25**.
- LP-5013 (T-Chain) is **deprecated** by LP-134.
- Cert-lane enums `MChainCGGMP21=5`, `MChainFROST=6`,
  `MChainRingtailGen=7`, `FChainTFHE=8`, `FChainBootstrap=9`. Never
  reorder; appends only.

## Where to read next

| File | Why |
|---|---|
| `DESIGN.md` | architecture, state machine, lane integration |
| `docs/ARCHITECTURE.md` | how M-Chain / F-Chain plug in |
| `docs/M_CHAIN_INTEGRATION.md` | M-Chain adapter contract |
| `docs/F_CHAIN_INTEGRATION.md` | F-Chain adapter contract |
| `types/ceremony.go` | the state machine in code |
| `cert/subject.go` | how `certificate_subject` binds both roots |
