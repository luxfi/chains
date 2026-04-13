// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package config

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInvalidThreshold  = errors.New("invalid threshold configuration")
	ErrInvalidValidators = errors.New("invalid validators configuration")
	ErrInvalidAlgorithm  = errors.New("invalid algorithm configuration")
	ErrInvalidPort       = errors.New("invalid port configuration")
)

// Config holds configuration for the K-Chain VM.
type Config struct {
	// Network settings
	NetworkID  uint32 `json:"networkId"`
	ChainID    string `json:"chainId"`
	ListenPort uint16 `json:"listenPort"` // Default: 9630

	// ML-KEM configuration
	MLKEMEnabled       bool `json:"mlkemEnabled"`
	MLKEMSecurityLevel int  `json:"mlkemSecurityLevel"` // 512, 768, or 1024
	MLDSAEnabled       bool `json:"mldsaEnabled"`
	MLDSASecurityLevel int  `json:"mldsaSecurityLevel"` // 44, 65, or 87

	// Threshold configuration
	DefaultThreshold   int `json:"defaultThreshold"`   // Default: 3
	DefaultTotalShares int `json:"defaultTotalShares"` // Default: 5
	MaxShares          int `json:"maxShares"`          // Maximum shares allowed

	// Validator configuration
	Validators        []string      `json:"validators"`
	ValidatorTimeout  time.Duration `json:"validatorTimeout"`
	HeartbeatInterval time.Duration `json:"heartbeatInterval"`

	// Storage configuration
	DataDir        string `json:"dataDir"`
	MaxKeys        int    `json:"maxKeys"`
	ShareCacheSize int    `json:"shareCacheSize"`

	// Security configuration
	TLSEnabled  bool   `json:"tlsEnabled"`
	TLSCertPath string `json:"tlsCertPath"`
	TLSKeyPath  string `json:"tlsKeyPath"`
	MTLSEnabled bool   `json:"mtlsEnabled"`
	MTLSCAPath  string `json:"mtlsCaPath"`

	// Performance configuration
	MaxParallelOps int `json:"maxParallelOps"`
	BatchSize      int `json:"batchSize"`

	// Block configuration
	BlockInterval  time.Duration `json:"blockInterval"`
	MaxTxsPerBlock int           `json:"maxTxsPerBlock"`

	// Proactive resharing
	ReshareEnabled  bool          `json:"reshareEnabled"`
	ReshareInterval time.Duration `json:"reshareInterval"`
}

// DefaultConfig returns a config with default values.
func DefaultConfig() Config {
	return Config{
		ListenPort:         9630,
		MLKEMEnabled:       true,
		MLKEMSecurityLevel: 768,
		MLDSAEnabled:       true,
		MLDSASecurityLevel: 65,
		DefaultThreshold:   3,
		DefaultTotalShares: 5,
		MaxShares:          100,
		Validators: []string{
			"validator-1.kchain.lux.network:9630",
			"validator-2.kchain.lux.network:9631",
			"validator-3.kchain.lux.network:9632",
			"validator-4.kchain.lux.network:9633",
			"validator-5.kchain.lux.network:9634",
		},
		ValidatorTimeout:  30 * time.Second,
		HeartbeatInterval: 10 * time.Second,
		MaxKeys:           10000,
		ShareCacheSize:    1000,
		TLSEnabled:        true,
		MTLSEnabled:       true,
		MaxParallelOps:    100,
		BatchSize:         10,
		BlockInterval:     2 * time.Second,
		MaxTxsPerBlock:    100,
		ReshareEnabled:    true,
		ReshareInterval:   24 * time.Hour,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate port
	if c.ListenPort == 0 {
		c.ListenPort = 9630
	}

	// Validate ML-KEM security level
	if c.MLKEMEnabled {
		switch c.MLKEMSecurityLevel {
		case 512, 768, 1024:
			// Valid
		default:
			return ErrInvalidAlgorithm
		}
	}

	// Validate ML-DSA security level
	if c.MLDSAEnabled {
		switch c.MLDSASecurityLevel {
		case 44, 65, 87:
			// Valid
		default:
			return ErrInvalidAlgorithm
		}
	}

	// Validate threshold configuration
	if c.DefaultThreshold <= 0 || c.DefaultTotalShares <= 0 {
		return ErrInvalidThreshold
	}
	if c.DefaultThreshold > c.DefaultTotalShares {
		return ErrInvalidThreshold
	}

	// Validate validators
	if len(c.Validators) < c.DefaultTotalShares {
		return ErrInvalidValidators
	}

	return nil
}

// ParseConfig parses configuration from JSON bytes.
func ParseConfig(data []byte) (Config, error) {
	cfg := DefaultConfig()
	if len(data) == 0 {
		return cfg, nil
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
