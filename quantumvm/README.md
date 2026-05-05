# Q-chain Virtual Machine (QVM)

The Q-chain Virtual Machine (QVM) hosts the Q lane of Lux's parallel-witness
finality model (LP-020 Quasar). When the operator-selected witness set
includes `WitnessQ` (policies `PolicyPQ` or `PolicyQuantum`), Q-Chain runs a
Ringtail 2-round threshold ceremony per consensus round and emits the
resulting threshold signature as the round's Q-witness. Q-Chain is one of
three parallel finality producers (P, Q, Z); adding it does not change
finality latency, only parallel verification cost.

The VM also provides per-validator ML-DSA-65 (FIPS 204) identity signatures
and a quantum stamp for individual transactions.

## Features

### Q-witness production (Quasar parallel-witness finality)
- **Ringtail threshold (Module-LWE, eprint 2024/1113)**: 2-round threshold
  signing per consensus round, t = ⌊2n/3⌋ + 1 of n validators, combined
  public key rooted in `qchain_ceremony_root`.
- **Per-validator ML-DSA-65 (FIPS 204)**: identity signatures over round
  digests, used by the Z lane (chains/zkvm) to produce the Groth16 rollup.
- **Quantum stamp**: time-windowed transaction-level binding.

### Performance Optimization
- **Parallel Transaction Processing**: Process multiple transactions concurrently
- **Configurable Batch Sizes**: Optimize throughput based on network conditions
- **Worker Pool Architecture**: Efficient resource utilization with pooled workers

### Configuration

The QVM can be configured through the `config.Config` structure:

```go
type Config struct {
    TxFee                   uint64        // Base transaction fee
    CreateAssetTxFee        uint64        // Asset creation fee
    QuantumVerificationFee  uint64        // Fee for quantum signature verification
    MaxParallelTxs          int           // Maximum parallel transactions
    QuantumAlgorithmVersion uint32        // Quantum algorithm version
    RingtailKeySize         int           // Size of Ringtail keys in bytes
    QuantumStampEnabled     bool          // Enable quantum stamp validation
    QuantumStampWindow      time.Duration // Validity window for quantum stamps
    ParallelBatchSize       int           // Batch size for parallel processing
    QuantumSigCacheSize     int           // Cache size for quantum signatures
    RingtailEnabled         bool          // Enable Ringtail key support
    MinQuantumConfirmations uint32        // Minimum confirmations for quantum stamps
}
```

## Architecture

### Core Components

1. **VM** (`vm.go`): Main virtual machine implementation
2. **Factory** (`factory.go`): VM factory for creating QVM instances
3. **Config** (`config/config.go`): Configuration management
4. **Quantum Signer** (`quantum/signer.go`): Quantum signature implementation

### Transaction Flow

1. Transactions are submitted to the transaction pool
2. Worker threads process transactions in parallel batches
3. Quantum signatures are verified using the quantum signer
4. Valid transactions are included in blocks
5. Blocks are signed with quantum stamps

### RPC API

The QVM exposes the following RPC endpoints:

- `qvm.getBlock`: Retrieve a block by ID
- `qvm.generateRingtailKey`: Generate a new Ringtail key pair
- `qvm.verifyQuantumSignature`: Verify a quantum signature
- `qvm.getPendingTransactions`: Get pending transactions
- `qvm.getHealth`: Get VM health status
- `qvm.getConfig`: Get current configuration

## Security Features

### Quantum Signatures
The QVM uses ML-DSA (FIPS 204, NIST module-lattice DSA) for per-validator
quantum-resistant signatures:
- ML-DSA-44/65/87 supported (NIST Level 2/3/5)
- Quantum stamp: time-windowed binding of message + nonce + timestamp,
  prevents stamp replay
- GPU batch verification via `accel.DilithiumVerifyBatch` (`accel.Available()`,
  threshold 64+ signatures)

### Validator key material
Two distinct categories live on Q-Chain validators:
- **Per-validator ML-DSA-65 identity key**: `MLDSAValidatorKey` in
  `quantum/signer.go` (kept exposed via the legacy `GenerateRingtailKey`
  RPC name). Used for individual round attestations and the Z-witness
  rollup input.
- **Ringtail threshold share**: per-validator share of the combined
  Ringtail key, produced by the Q-Chain DKG ceremony (rooted in
  `qchain_ceremony_root`). Lives in `luxfi/threshold/protocols/ringtail`.

### Parallel Processing Safety
- Thread-safe transaction pool with mutex protection
- Isolated worker threads for transaction processing
- Atomic operations for state updates

## Usage

### Creating a QVM Instance

```go
factory := &qvm.Factory{
    Config: config.DefaultConfig(),
}

vm, err := factory.New(logger)
if err != nil {
    return err
}
```

### Initializing the VM

```go
err := vm.Initialize(
    ctx,
    chainRuntime,
    db,
    genesisBytes,
    upgradeBytes,
    configBytes,
    toEngine,
    fxs,
    appSender,
)
```

### Building Blocks

```go
block, err := vm.BuildBlock(ctx)
if err != nil {
    return err
}
```

## Testing

The QVM includes comprehensive error handling and logging for production use:
- Error recovery for parallel processing failures
- Detailed logging at all levels (Info, Debug, Error)
- Health check monitoring
- Metrics collection

## Future Enhancements

Planned improvements include:
- Additional quantum-resistant algorithms (SPHINCS+, Dilithium, Falcon)
- Enhanced parallel processing with GPU acceleration
- Cross-chain quantum signature verification
- Advanced caching strategies for improved performance

## License

Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
See the file LICENSE for licensing terms.