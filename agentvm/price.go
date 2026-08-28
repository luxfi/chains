// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// price.go turns a workload into what one operator is owed for running it. It is
// a pure function of the workload — nobody names a number — so every validator
// computes the same reward and a requester cannot underpay for a demand that is
// expensive to meet.
//
// The price is over what the run RESERVES, not over what it turns out to use. It
// has to be: the reward is escrowed before anyone runs, so the only quantity
// available at that moment is the ask. Consumption is not thereby unpriced — a
// receipt claiming more than its ask is refused (Receipt.Check), so the ask is a
// real ceiling and pricing it is pricing the capacity actually held.
//
// Properties are surcharges, in percent, over the resource price. They are not a
// ladder: each property costs what providing it costs, and a demand's surcharge
// is the sum over the properties it names. Nothing here compares two mechanisms.

import "github.com/holiman/uint256"

// Resource rates, in wei per unit-second. A unit-second is one thousandth of a
// core, one mebibyte, or one device, held for one second.
var (
	// RatePerCPU is charged per thousandth of a core per second.
	RatePerCPU = uint256.NewInt(1_000_000_000_000)
	// RatePerMemory is charged per mebibyte per second.
	RatePerMemory = uint256.NewInt(1_000_000_000)
	// RatePerGPU is charged per device per second.
	RatePerGPU = uint256.NewInt(1_000_000_000_000_000)
)

// surcharge is what each property adds, in percent of the resource price. Sharing
// the host kernel, taking syscalls directly, running in plain memory and
// attesting nothing are what a bare process already is, so they add nothing.
var surcharge = [propertyCount]uint64{
	KernelShared:    0,
	KernelGuest:     40,
	SyscallDirect:   0,
	SyscallFiltered: 5,
	SyscallMediated: 25,
	MemoryPlain:     0,
	MemoryEncrypted: 60,
	AttestNone:      0,
	AttestSoftware:  5,
	AttestHardware:  50,
	ReplicaOne:      0,
	ReplicaMany:     30,
	ReplicaErasure:  20,
}

// percent is the denominator the surcharges are expressed against.
const percent = 100

// mebibyte is the memory unit the rate is quoted in.
const mebibyte = 1 << 20

// Price is what one operator is owed for running w. Every step is checked for
// overflow and the whole computation fails closed: a workload that cannot be
// priced cannot be opened, so no task is ever created with a reward nobody can
// compute.
func Price(w Workload) (*uint256.Int, error) {
	if !w.Demand.Wellformed() {
		return nil, ErrDemandMalformed
	}

	// Seconds held, rounded up: a run that may take part of a second holds the
	// capacity for the whole of it.
	seconds := uint256.NewInt((uint64(w.Resource.Timeout) + 999) / 1000)

	total := uint256.NewInt(0)
	add := func(rate *uint256.Int, units uint64) error {
		term := new(uint256.Int)
		if _, over := term.MulOverflow(rate, uint256.NewInt(units)); over {
			return ErrPriceOverflow
		}
		if _, over := term.MulOverflow(term, seconds); over {
			return ErrPriceOverflow
		}
		if _, over := total.AddOverflow(total, term); over {
			return ErrPriceOverflow
		}
		return nil
	}

	if err := add(RatePerCPU, uint64(w.Resource.CPU)); err != nil {
		return nil, err
	}
	// Memory is quoted per mebibyte, rounded up, so an ask below a mebibyte still
	// pays for the mebibyte it occupies.
	if err := add(RatePerMemory, (w.Resource.Memory+mebibyte-1)/mebibyte); err != nil {
		return nil, err
	}
	if err := add(RatePerGPU, uint64(w.Resource.GPU)); err != nil {
		return nil, err
	}

	// One multiplication and one division for the whole surcharge, so the result
	// does not depend on the order the properties were summed in.
	factor := uint64(percent)
	w.Demand.Each(func(p Property) { factor += surcharge[p] })

	if _, over := total.MulOverflow(total, uint256.NewInt(factor)); over {
		return nil, ErrPriceOverflow
	}
	return total.Div(total, uint256.NewInt(percent)), nil
}
