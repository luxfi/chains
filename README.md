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
| quantumvm | Q-Chain | Post-quantum security |
| relayvm | R-Chain | Cross-chain relay |
| servicenodevm | S-Chain | Service node registry |
| teleportvm | T-Chain (teleport) | Unified bridge+relay+oracle |
| thresholdvm | T-Chain (threshold) | Threshold signatures |
| zkvm | Z-Chain | Zero-knowledge proofs |
