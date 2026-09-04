// Copyright (c) 2019-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

// Package fee is the whole native fee model of a Lux service chain: the
// ADMISSION policy a VM declares at boot (policy.go) and the SETTLEMENT
// mechanism that meters, debits and burns the admitted fee during block
// execution (balance.go, meter.go, settle.go).
//
// Admission is the half every user-facing chain must declare: a Policy whose
// MinTxFee is > 0, or the NoUserTxPolicy sentinel for committee-only chains,
// checked once by Validate. Settlement is the half the 2026-05 fee audit found
// missing: nothing could actually METER, DEBIT, and BURN a fee during block
// execution the way the C-Chain EVM does (evm/core/state_transition.go buyGas:
// balance check -> ErrInsufficientFunds -> SubBalance). Service chains charged
// "fees" that were unbacked integers a caller wrote into a JSON request —
// never settled against real on-chain balance.
//
// This package supplies the three pillars those chains lacked, modelled on the
// EVM's buyGas but for the native account model (P/X-Chain style direct usage,
// not EVM-gas yet — that is a later dual-metering layer that composes on top):
//
//   - Balances (balance.go) — a debitable balance surface the VM can Burn from.
//     Burn(acct, amount) is the debit: it removes funds from the payer AND
//     reduces circulating supply (no coinbase credit) — i.e. a native burn.
//     Credit funds an account (genesis / future treasury inflows). Ledger
//     (ledger.go) is the canonical KV-backed implementation; any chain whose
//     state is a luxfi/database.Database gets a working ledger with no bespoke
//     code.
//
//   - GasMeter (meter.go) — per-operation gas metering with a hard limit,
//     mirroring the EVM gas pool (SubGas / ErrOutOfGas). A VM meters each
//     operation's real cost against the payer's GasLimit before pricing it.
//
//   - Settlement (settle.go) — Cost converts metered gas to nLUX at a price;
//     CanPay is the read-only affordability check a block runs in Verify (so an
//     unpayable block is never accepted — fail closed); Charge is the
//     authoritative debit+burn a block runs in Accept. Settlement happens
//     INSIDE consensus block processing, atomically with the operation's state
//     effect via the VM's versiondb commit — never in a synchronous RPC.
//
// Orthogonality. Admission and settlement are two files of one package, not
// one mechanism: a VM declares a Policy AND settles through a Ledger; the two
// compose, they do not overlap. The schedule of "which operation costs how
// much gas" is supplied BY THE VM (keyvm prices per cryptographic algorithm) —
// this package is the pure mechanism, the VM owns the values.
//
// It lives in the chains module on purpose: the VMs are plugin binaries built
// without the node daemon in their dependency closure, so the fee surface they
// program against must live beside them.
package fee
