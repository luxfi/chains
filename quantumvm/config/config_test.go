// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package config

import (
	"testing"
	"time"
)

// TestValidateRefusesAnAlgorithmThatDoesNotExist.
//
// An unrecognised number used to fall through to ML-DSA-65 inside the signer,
// so an operator who configured 7 got a chain signing under a parameter set
// nobody chose — and no message saying so. The number is the one config field
// where a default is worse than a refusal.
func TestValidateRefusesAnAlgorithmThatDoesNotExist(t *testing.T) {
	for _, version := range []uint32{4, 7, 99, 1 << 20} {
		c := DefaultConfig()
		c.QuantumAlgorithmVersion = version
		if err := c.Validate(); err == nil {
			t.Fatalf("algorithm %d was accepted; the chain would sign under a parameter set nobody chose", version)
		}
	}

	for _, version := range []uint32{1, 2, 3} {
		c := DefaultConfig()
		c.QuantumAlgorithmVersion = version
		if err := c.Validate(); err != nil {
			t.Fatalf("algorithm %d is real and was refused: %v", version, err)
		}
		if c.QuantumAlgorithmVersion != version {
			t.Fatalf("algorithm %d was changed to %d", version, c.QuantumAlgorithmVersion)
		}
	}
}

// TestValidateSettlesAnEmptyConfig. Zero is not a weaker setting: a zero batch
// size batches nothing, a zero cache caches nothing, and a zero pool accepts
// nothing. A VM handed the empty config has to come out of Validate usable.
func TestValidateSettlesAnEmptyConfig(t *testing.T) {
	c := Config{}
	if err := c.Validate(); err != nil {
		t.Fatalf("the empty config was refused: %v", err)
	}

	if c.QuantumAlgorithmVersion != AlgorithmDefault {
		t.Fatalf("unset algorithm settled on %d, want %d", c.QuantumAlgorithmVersion, AlgorithmDefault)
	}
	for name, got := range map[string]int{
		"MaxParallelTxs":    c.MaxParallelTxs,
		"ParallelBatchSize": c.ParallelBatchSize,
		"GPUBatchThreshold": c.GPUBatchThreshold,
	} {
		if got <= 0 {
			t.Fatalf("%s settled on %d: a VM with that value does no work", name, got)
		}
	}
	if c.QuantumStampWindow <= 0 {
		t.Fatalf("stamp window settled on %s: every stamp would be born expired", c.QuantumStampWindow)
	}
}

// TestValidateReplacesNegativeSizes the same way it replaces zero — the sign is
// not the point, usability is.
func TestValidateReplacesNegativeSizes(t *testing.T) {
	c := DefaultConfig()
	c.MaxParallelTxs = -1
	c.ParallelBatchSize = -10
	c.GPUBatchThreshold = -8
	c.QuantumStampWindow = -time.Second

	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.MaxParallelTxs <= 0 || c.ParallelBatchSize <= 0 ||
		c.GPUBatchThreshold <= 0 || c.QuantumStampWindow <= 0 {
		t.Fatalf("a negative sizing survived Validate: %+v", c)
	}
}

// TestDefaultConfigIsAlreadyValid: the shipped defaults must not need repair,
// or the defaults are not the defaults.
func TestDefaultConfigIsAlreadyValid(t *testing.T) {
	before := DefaultConfig()
	after := before
	if err := after.Validate(); err != nil {
		t.Fatalf("the default config was refused: %v", err)
	}
	if after != before {
		t.Fatalf("Validate changed the defaults: %+v -> %+v", before, after)
	}
}
