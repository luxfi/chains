// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package multichain is the cross-chain block builder. It runs C-Chain
// (EVM), D-Chain (DEX), and F-Chain (FHE) transitions atomically so a
// single transaction can flow through multiple chains in one block
// without going CPU → GPU → CPU → GPU on every chain boundary.
//
// Design intent
// =============
//
// A tx that enters C-Chain and calls a precompile at 0x9020 (CLOB) or
// 0x9300 (FHE) today bounces: the EVM kernel returns control to the host,
// the host enqueues a D-Chain or F-Chain operation, the D/F block builder
// kicks in, the GPU dispatch happens again. Every chain boundary is a
// round trip. multichain.BlockBuilder collapses those boundaries.
//
// Today (Phase 1): sequential dispatch from one host coordinator.
//
//	builder.ExecuteBlock(batch)
//	  ├─> EVM kernel for C-Chain txs (cevm.ExecuteBlock)
//	  ├─> CLOB kernel for D-Chain ops (lx.MatchOrderGPU)
//	  ├─> FHE NTT kernel for F-Chain ops (fhe.NTTEngine.NTTBatch)
//	  └─> seals all three sub-blocks; gossips one MultiChainBlock
//
// The host coordinates but never reads partial state — the kernels write
// directly into shared MvMemory, and the host only sees the sealed result
// when every kernel reports done.
//
// Tomorrow (Phase 2, luxcpp shared MvMemory): single kernel dispatch.
//
//	builder.ExecuteBlock(batch)
//	  └─> ONE GPU kernel runs all three chains over shared MvMemory.
//	      EVM frame hits CALL 0x9020 → device-local jump into CLOB kernel
//	      writing the same MvMemory; trade record lands in the C-Chain
//	      receipt buffer without the host ever seeing it.
//
// The BlockBuilder API does not change between Phase 1 and Phase 2 —
// callers see one entry point. Only the underlying dispatch optimization
// changes when luxcpp ships the shared MvMemory + in-kernel precompile
// dispatch table (see PRECOMPILE_DISPATCH.md for the kernel design).
//
// Transport
// =========
//
// Once the MultiChainBlock is sealed, it is gossiped via the configured
// zap.Transport (see github.com/luxfi/zap/transport). The host never
// inspects sub-block contents — they ship as opaque byte buffers that
// the receiving validator's same multichain builder verifies.
package multichain
