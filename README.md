# Lux Chains

Independent VM plugin binaries for the Lux Network.

Each directory builds to a standalone binary that the Lux node loads as a plugin via `--plugin-dir`.

## Build

```bash
make            # build all VMs
make evm        # build one VM
make test       # test all
```

## Install

```bash
lpm install evm
lpm install dexvm
```

Or copy binaries to `~/.lux/plugins/<vmid>`.

## VMs

| VM | Chain | Purpose |
|----|-------|---------|
| evm | C-Chain | EVM smart contracts |
| dexvm | D-Chain | Decentralized exchange |
| aivm | A-Chain | AI/ML inference |
| bridgevm | B-Chain | Cross-chain bridge |
| graphvm | G-Chain | GraphQL data layer |
| identityvm | I-Chain | Decentralized identity |
| keyvm | K-Chain | Key management |
| oraclevm | O-Chain | Oracle/off-chain data |
| quantumvm | Q-Chain | Post-quantum consensus signing (Pulsar) |
| relayvm | R-Chain | Cross-chain relay |
| servicenodevm | S-Chain | Service node registry |
| teleportvm | T-Chain | Unified teleport (bridge + relay + oracle) |
| thresholdvm (MPC) | M-Chain | MPC ceremonies (CGGMP21, FROST, Pulsar-general) — bridge custody for external wallets |
| thresholdvm (FHE) | F-Chain | FHE compute + TFHE bootstrap-key generation (encrypted EVM) |
| zkvm | Z-Chain | Groth16 over BLS12-381 (rolls N × ML-DSA-65 sigs into 192-byte proof) |
