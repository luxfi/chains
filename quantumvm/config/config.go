// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package config

import "time"

// Config contains all the foundational parameters of the QVM
type Config struct {
	// Fee that is burned by every non-asset creating transaction
	TxFee uint64

	// Fee that must be burned by every asset creating transaction
	CreateAssetTxFee uint64

	// Fee for quantum signature verification
	QuantumVerificationFee uint64

	// Maximum parallel transactions to process
	MaxParallelTxs int

	// Quantum signature algorithm version
	QuantumAlgorithmVersion uint32

	// Ringtail key size in bytes
	RingtailKeySize int

	// Enable quantum stamp validation
	QuantumStampEnabled bool

	// Quantum stamp validity window (in seconds)
	QuantumStampWindow time.Duration

	// Time of the Quantum network upgrade
	QuantumTime time.Time

	// Parallel processing batch size
	ParallelBatchSize int

	// Maximum quantum signature cache size
	QuantumSigCacheSize int

	// Enable Ringtail key support
	RingtailEnabled bool

	// Minimum confirmations for quantum stamps
	MinQuantumConfirmations uint32

	// Minimum batch size before GPU acceleration kicks in
	GPUBatchThreshold int
}

// DefaultConfig returns a Config with default values
func DefaultConfig() Config {
	return Config{
		TxFee:                   1000,
		CreateAssetTxFee:        10000,
		QuantumVerificationFee:  500,
		MaxParallelTxs:          100,
		QuantumAlgorithmVersion: 1,
		RingtailKeySize:         1024,
		QuantumStampEnabled:     true,
		QuantumStampWindow:      30 * time.Second,
		QuantumTime:             time.Unix(1704067200, 0), // Jan 1, 2025
		ParallelBatchSize:       10,
		QuantumSigCacheSize:     10000,
		RingtailEnabled:         true,
		MinQuantumConfirmations: 1,
		GPUBatchThreshold:       8,
	}
}

// IsQuantumActivated returns true if the quantum features are activated
func (c *Config) IsQuantumActivated(timestamp time.Time) bool {
	return !timestamp.Before(c.QuantumTime)
}

// Validate ensures the configuration is valid
func (c *Config) Validate() error {
	if c.MaxParallelTxs <= 0 {
		c.MaxParallelTxs = 100
	}
	if c.ParallelBatchSize <= 0 {
		c.ParallelBatchSize = 10
	}
	if c.QuantumSigCacheSize <= 0 {
		c.QuantumSigCacheSize = 10000
	}
	if c.RingtailKeySize < 512 {
		c.RingtailKeySize = 1024
	}
	if c.GPUBatchThreshold <= 0 {
		c.GPUBatchThreshold = 8
	}
	return nil
}
