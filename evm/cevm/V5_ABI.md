# cevm GPU ABI v5 — CALL / CREATE on device

Status: spec. luxcpp-side work; Go-side scaffold lands in this directory.

## Why v5

V4 (`gpu_execute_block_v4`) interprets ADD / SSTORE / SLOAD / Keccak / MSTORE
/ MLOAD / MCOPY on the GPU but traps on `CALL` / `CREATE` / `CREATE2` /
`DELEGATECALL` / `STATICCALL` — any block touching a contract interaction
falls back to the Go EVM. That breaks block-batched dispatch on every
contract-heavy block, which is the common case for the C-Chain workload.

V5 adds (a) a code-table the device can resolve callees from, (b) a
storage-trie root that survives nested SSTORE/SLOAD across frames, and
(c) a per-tx log API so receipts can be reconstructed without re-running
the block on the host.

## ABI

C entry point (additive — V4 stays for back-compat):

```c
// luxcpp/cevm/lib/evm/gpu/go_bridge.h (new in v5)
gpu_block_result_v5* gpu_execute_block_v5(
    const gpu_tx_v5*     txs,
    uint32_t             num_txs,
    gpu_backend_t        backend,
    uint32_t             num_threads,
    int                  revision,
    const BlockContext*  block_ctx,
    const StateAccount*  state,         // V4-shape, now with storage_root
    uint32_t             state_len,
    const uint8_t*       code_blob,
    uint64_t             code_size,
    const gpu_code_entry* code_table,    // NEW: addr -> code_blob offset
    uint32_t             code_table_len);

void gpu_free_result_v5(gpu_block_result_v5*);
```

New types:

```c
typedef struct {
    uint8_t address[20];   // contract address
    uint64_t code_offset;  // offset into code_blob where this address's bytecode lives
    uint64_t code_len;
} gpu_code_entry;

typedef struct {
    uint8_t  address[20];
    uint64_t nonce;
    uint8_t  balance[32];        // u256 LE
    uint8_t  storage_root[32];   // NEW: kept across CALL frames in the kernel
    uint64_t code_offset;        // points into code_blob (0 = EOA, no code)
    uint64_t code_len;
} StateAccount;  // unchanged shape from V4 except storage_root is now load-bearing

typedef struct {
    uint8_t  hash[32];
    uint8_t  sender[20];
    uint8_t  to[20];             // zero = contract creation
    uint8_t  value[32];          // u256 LE
    uint64_t gas;
    uint64_t gas_price;
    uint64_t nonce;
    const uint8_t* data;
    uint64_t       data_len;
} gpu_tx_v5;  // unchanged from V4

typedef struct {
    // per-tx outputs
    uint64_t* gas_used;
    uint8_t*  status;             // 0 = revert, 1 = success
    uint8_t   state_root[32];
    // NEW in v5: per-tx logs flat-encoded
    gpu_log_entry* logs;
    uint32_t       num_logs;
    uint32_t*      tx_log_count;  // logs[] partition by tx
} gpu_block_result_v5;

typedef struct {
    uint8_t  address[20];
    uint8_t  topics[4][32];
    uint8_t  num_topics;
    const uint8_t* data;
    uint32_t       data_len;
} gpu_log_entry;
```

## Kernel-side work (luxcpp/cevm)

1. **Call stack on device**: kernel maintains a per-tx stack of frames
   (depth ≤ 1024 per EVM spec); each frame has its own scratch memory,
   PC, and gas counter. `CALL` pushes; `RETURN` / `REVERT` pops.
2. **Code resolution**: `CALL`/`DELEGATECALL`/`STATICCALL`/`CREATE2`
   load callee bytecode from `code_blob` via `code_table` lookup
   (binary search on the 20-byte address). EOAs (no entry) are
   pure-value transfers.
3. **Storage threading**: `SSTORE` / `SLOAD` operate on the active
   frame's account's `storage_root`. Frame pop merges the dirty set
   back into the parent's state-account row.
4. **Log emission**: `LOG0..LOG4` opcodes append to a per-tx log list.
   On block completion the kernel concatenates per-tx lists into the
   flat `gpu_log_entry[] logs` buffer and writes per-tx counts.

## Go-side opt-in

`chains/evm/cevm/cevm_cgo.go` adds:

```go
// ExecuteBlockV5 dispatches to gpu_execute_block_v5 when the linked
// libevm-gpu exports the symbol (runtime dlsym probe). Falls through
// to ExecuteBlockV4 (or Go EVM) otherwise.
func ExecuteBlockV5(...) (*BlockResultV5, error)
```

`parallel/parallel.go::BlockExecutor` picks V5 when:
1. The block contains CALL / CREATE family opcodes (cheap pre-scan)
2. `ExecuteBlockV5` is bound at the dlsym layer
3. `backend.IsGPU()`

If any of those are false, the existing V4 path or the Go EVM fall-back
runs unchanged.

## Equivalence + tests

`cevm_v5_parity_test.go` (to write) runs each block through both the Go
EVM and `ExecuteBlockV5`, asserting byte-equal state-root + log set
across a synthetic suite covering: pure value transfer, CREATE / CREATE2,
nested CALL (depth 4), DELEGATECALL preserving storage, STATICCALL
trapping SSTORE, LOG0..LOG4 emission.

Existing block-batched parity tests (`cevm_cgo_test.go`) stay green
because V5 is a strict superset of V4.

## Open questions

- **Self-destructed accounts**: V5 must thread the suicide-list out of
  the kernel so the host trie can prune. Two options — return as part
  of `gpu_block_result_v5` or include in the per-tx log stream as a
  pseudo-log. Pick one and pin in a follow-up note.
- **Precompile dispatch**: V4 punts all precompile addresses to the host.
  V5 keeps that for now; native precompiles (Lux V4 DEX precompile at
  0x9012, FHE precompiles 0x0200…0083) stay on the host until each one
  gets a dedicated GPU kernel. Document the punt set in
  `cevm_cgo.go::isHostPrecompile`.
- **Gas refund accounting** (EIP-3529): the kernel returns `gas_used`
  net of refund; the host should not re-apply the refund.

## Out of scope

- KZG / EIP-4844 blob handling — V4 already routes that to the host;
  no GPU win.
- Beacon root opcode (`PUSH 0x4A`) — Lux disables Cancun beacon-root
  semantics; the kernel can short-circuit it to a no-op.
