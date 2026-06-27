// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fee

import "errors"

// ErrOutOfGas is returned by GasMeter.Consume when an operation's gas exceeds
// the remaining limit. It mirrors the EVM gas pool's exhaustion error and is
// fail-secure: the operation does not proceed.
var ErrOutOfGas = errors.New("fee: out of gas")

// Gas is a unit of metered work. A VM's gas schedule assigns a Gas cost to each
// operation (keyvm prices per cryptographic algorithm); Cost converts Gas to
// nLUX at a per-unit price.
type Gas uint64

// GasMeter meters gas consumption against a hard limit, exactly like the EVM
// gas pool (SubGas / out-of-gas). A VM constructs one per fee-bearing operation
// with the payer's declared GasLimit, then Consumes the operation's metered
// cost; Consume past the limit denies the operation rather than overdraw.
type GasMeter struct {
	limit     Gas
	remaining Gas
}

// NewGasMeter returns a meter with the given limit, fully unconsumed.
func NewGasMeter(limit Gas) *GasMeter {
	return &GasMeter{limit: limit, remaining: limit}
}

// Consume deducts amount from the remaining gas. It returns ErrOutOfGas (and
// changes nothing) if amount exceeds what remains.
func (m *GasMeter) Consume(amount Gas) error {
	if amount > m.remaining {
		return ErrOutOfGas
	}
	m.remaining -= amount
	return nil
}

// Remaining reports unconsumed gas.
func (m *GasMeter) Remaining() Gas { return m.remaining }

// Used reports consumed gas (limit - remaining).
func (m *GasMeter) Used() Gas { return m.limit - m.remaining }

// Limit reports the meter's hard limit.
func (m *GasMeter) Limit() Gas { return m.limit }
