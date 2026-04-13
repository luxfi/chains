# Q-chain Virtual Machine (QVM)

The Q-chain Virtual Machine (QVM) is a quantum-resistant blockchain virtual machine implementation for the Lux Network. It provides advanced cryptographic features including quantum signatures and parallel transaction processing.

## Features

### Quantum Resistance
- **Ringtail Key Support**: Quantum-resistant key generation and management
- **Quantum Signatures**: Post-quantum cryptographic signatures for transaction and block validation
- **Quantum Stamp Validation**: Time-based quantum stamps for enhanced security

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
The QVM implements quantum-resistant signatures using:
- SHA-512 based hashing with quantum noise
- XOR-based signature generation with private keys
- Time-windowed validation to prevent replay attacks

### Ringtail Keys
Ringtail keys provide:
- Large key sizes (default 1024 bytes)
- Version tracking for algorithm upgrades
- Nonce-based randomization

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