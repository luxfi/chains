// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package config

import (
	"fmt"
	"time"
)

// Config contains all the foundational parameters of the QVM.
//
// Every field here governs behaviour. Q-Chain charges no user fee at all
// (LP-0130 §6 — finality-cert inclusion is a validator obligation, not
// purchasable blockspace), so the config declares no fee schedule: a number
// nothing reads is a price the chain does not actually charge, and reporting
// one over RPC tells operators otherwise.
type Config struct {
	// Maximum parallel transactions to process
	MaxParallelTxs int

	// Quantum signature algorithm version: 1=ML-DSA-44, 2=ML-DSA-65,
	// 3=ML-DSA-87. The parameter set fixes every key and signature width.
	// Zero means unset and settles on ML-DSA-65; anything else is refused.
	QuantumAlgorithmVersion uint32

	// Enable quantum stamp validation
	QuantumStampEnabled bool

	// How long a quantum stamp stays valid after it is made
	QuantumStampWindow time.Duration

	// Parallel processing batch size
	ParallelBatchSize int

	// Enable Corona key support
	CoronaEnabled bool

	// Minimum batch size before GPU acceleration kicks in
	GPUBatchThreshold int

	// Committee is how many validators the finality committee holds. The
	// threshold is derived from it, so it is the one number that decides how
	// many faults the chain survives. Zero means unset and settles on
	// CommitteeMin; anything below CommitteeMin is refused.
	Committee int
}

// DefaultConfig returns a Config with default values
func DefaultConfig() Config {
	return Config{
		MaxParallelTxs:          100,
		QuantumAlgorithmVersion: AlgorithmDefault,
		QuantumStampEnabled:     true,
		QuantumStampWindow:      30 * time.Second,
		ParallelBatchSize:       10,
		CoronaEnabled:           true,
		GPUBatchThreshold:       8,
		Committee:               CommitteeMin,
	}
}

// AlgorithmDefault is the parameter set an unset config settles on: ML-DSA-65,
// NIST level 3. DefaultConfig names the same constant, so a config the operator
// filled in and one left blank land on the same parameter set — two spellings of
// the default meant a chain signed under ML-DSA-44 or ML-DSA-65 depending on
// which door it came through.
const AlgorithmDefault uint32 = 2

// CommitteeMin is the smallest committee that survives one Byzantine validator.
// BFT tolerates f faults out of n ≥ 3f+1, so f ≥ 1 needs n ≥ 4; below that the
// quorum ⌊2n/3⌋+1 is the whole committee and one absent validator stops the
// chain while one dishonest validator decides it.
const CommitteeMin = 4

// Quorum is how many validators must agree, for a committee of n. It is the
// classical ⌊2n/3⌋+1, which for n ≥ CommitteeMin always lands strictly between
// 2 and n — the range the consensus core accepts.
func Quorum(n int) int { return n*2/3 + 1 }

// Validate replaces any non-positive sizing with its default and refuses an
// algorithm that does not exist.
//
// Each sizing divides or bounds a loop, so zero is not a weaker setting — it is
// a VM that batches nothing, caches nothing and builds empty blocks. The
// algorithm is different: an unrecognised number used to fall through to
// ML-DSA-65 inside the signer, so an operator who asked for something else got
// a chain signing under a parameter set nobody chose, and never heard about it.
func (c *Config) Validate() error {
	switch c.QuantumAlgorithmVersion {
	case 0:
		c.QuantumAlgorithmVersion = AlgorithmDefault
	case 1, 2, 3:
	default:
		return fmt.Errorf("config: quantum algorithm %d does not exist (1=ML-DSA-44, 2=ML-DSA-65, 3=ML-DSA-87)",
			c.QuantumAlgorithmVersion)
	}
	if c.MaxParallelTxs <= 0 {
		c.MaxParallelTxs = 100
	}
	if c.ParallelBatchSize <= 0 {
		c.ParallelBatchSize = 10
	}
	if c.GPUBatchThreshold <= 0 {
		c.GPUBatchThreshold = 8
	}
	if c.QuantumStampWindow <= 0 {
		c.QuantumStampWindow = 30 * time.Second
	}
	if c.Committee == 0 {
		c.Committee = CommitteeMin
	}
	return nil
}
