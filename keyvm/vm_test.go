// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/chains/keyvm/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	require.Equal(t, uint16(9630), cfg.ListenPort)
	require.True(t, cfg.MLKEMEnabled)
	require.Equal(t, 768, cfg.MLKEMSecurityLevel)
	require.True(t, cfg.MLDSAEnabled)
	require.Equal(t, 65, cfg.MLDSASecurityLevel)
	require.Equal(t, 3, cfg.DefaultThreshold)
	require.Equal(t, 5, cfg.DefaultTotalShares)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		wantErr bool
	}{
		{
			name:    "default config valid",
			cfg:     config.DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid ml-kem security level",
			cfg: config.Config{
				ListenPort:         9630,
				MLKEMEnabled:       true,
				MLKEMSecurityLevel: 999,
				DefaultThreshold:   3,
				DefaultTotalShares: 5,
				Validators:         []string{"a", "b", "c", "d", "e"},
			},
			wantErr: true,
		},
		{
			name: "invalid ml-dsa security level",
			cfg: config.Config{
				ListenPort:         9630,
				MLDSAEnabled:       true,
				MLDSASecurityLevel: 999,
				DefaultThreshold:   3,
				DefaultTotalShares: 5,
				Validators:         []string{"a", "b", "c", "d", "e"},
			},
			wantErr: true,
		},
		{
			name: "threshold exceeds total shares",
			cfg: config.Config{
				ListenPort:         9630,
				DefaultThreshold:   10,
				DefaultTotalShares: 5,
				Validators:         []string{"a", "b", "c", "d", "e"},
			},
			wantErr: true,
		},
		{
			name: "insufficient validators",
			cfg: config.Config{
				ListenPort:         9630,
				DefaultThreshold:   3,
				DefaultTotalShares: 5,
				Validators:         []string{"a", "b"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestKeyMetadata(t *testing.T) {
	now := time.Now()
	meta := &KeyMetadata{
		ID:          ids.GenerateTestID(),
		Name:        "test-key",
		Algorithm:   "ml-kem-768",
		KeyType:     "encryption",
		PublicKey:   []byte("test-public-key"),
		Threshold:   3,
		TotalShares: 5,
		Validators:  []string{"v1", "v2", "v3", "v4", "v5"},
		CreatedAt:   now,
		UpdatedAt:   now,
		Status:      "active",
		Tags:        []string{"test", "demo"},
	}

	require.Equal(t, "test-key", meta.Name)
	require.Equal(t, "ml-kem-768", meta.Algorithm)
	require.Equal(t, "encryption", meta.KeyType)
	require.Equal(t, 3, meta.Threshold)
	require.Equal(t, 5, meta.TotalShares)
	require.Equal(t, "active", meta.Status)
}

func TestTransaction(t *testing.T) {
	keyID := ids.GenerateTestID()
	payload := []byte("test-payload")
	sender := []byte("test-sender")

	tx := NewTransaction(TxTypeCreateKey, keyID, payload, sender)

	// The ID is computed from the serialized bytes
	// Verify the serialization produces consistent data
	data := tx.Bytes()
	require.NotEmpty(t, data)
	require.Equal(t, TxTypeCreateKey, int(tx.Type()))
	require.Equal(t, keyID, tx.KeyID())
	require.Equal(t, payload, tx.Payload())
	require.True(t, tx.Timestamp().Before(time.Now().Add(time.Second)))
}

func TestTransactionSerialization(t *testing.T) {
	keyID := ids.GenerateTestID()
	payload := []byte("test-payload-data")
	sender := []byte("test-sender-address")

	tx := NewTransaction(TxTypeDistributeKey, keyID, payload, sender)

	// Serialize
	data := tx.Bytes()
	require.NotEmpty(t, data)

	// Deserialize
	parsedTx, err := ParseTransaction(data)
	require.NoError(t, err)
	require.NotNil(t, parsedTx)

	require.Equal(t, tx.Type(), parsedTx.Type())
	require.Equal(t, tx.KeyID(), parsedTx.KeyID())
	require.Equal(t, tx.Payload(), parsedTx.Payload())
}

func TestTransactionValidation(t *testing.T) {
	tests := []struct {
		name    string
		txType  uint8
		wantErr bool
	}{
		{
			name:    "valid create key",
			txType:  TxTypeCreateKey,
			wantErr: false,
		},
		{
			name:    "valid delete key",
			txType:  TxTypeDeleteKey,
			wantErr: false,
		},
		{
			name:    "valid distribute key",
			txType:  TxTypeDistributeKey,
			wantErr: false,
		},
		{
			name:    "valid reshare key",
			txType:  TxTypeReshareKey,
			wantErr: false,
		},
		{
			name:    "invalid tx type",
			txType:  255,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := NewTransaction(tt.txType, ids.GenerateTestID(), nil, nil)
			err := tx.Verify(nil)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBlock(t *testing.T) {
	parentID := ids.GenerateTestID()
	tx := NewTransaction(TxTypeCreateKey, ids.GenerateTestID(), nil, nil)

	block := &Block{
		id:           ids.GenerateTestID(),
		parentID:     parentID,
		height:       100,
		timestamp:    time.Now(),
		transactions: []*Transaction{tx},
	}

	require.NotEqual(t, ids.Empty, block.ID())
	require.Equal(t, parentID, block.ParentID())
	require.Equal(t, uint64(100), block.Height())
	require.NotZero(t, block.Timestamp())
}

func TestBlockSerialization(t *testing.T) {
	parentID := ids.GenerateTestID()
	tx := NewTransaction(TxTypeCreateKey, ids.GenerateTestID(), []byte("payload"), nil)

	block := &Block{
		id:           ids.GenerateTestID(),
		parentID:     parentID,
		height:       42,
		timestamp:    time.Now(),
		transactions: []*Transaction{tx},
	}

	// Serialize
	data := block.Bytes()
	require.NotEmpty(t, data)

	// Verify data contains expected components
	// Parent ID (32) + Height (8) + Timestamp (8) + TxCount (4) + TxLen (4) + TxData
	require.Greater(t, len(data), 52)
}

func TestAlgorithmInfo(t *testing.T) {
	service := &Service{}
	var args ListAlgorithmsArgs
	var reply ListAlgorithmsReply

	err := service.ListAlgorithms(nil, &args, &reply)
	require.NoError(t, err)
	require.NotEmpty(t, reply.Algorithms)

	// Verify expected algorithms
	algNames := make(map[string]bool)
	for _, alg := range reply.Algorithms {
		algNames[alg.Name] = true
	}

	require.True(t, algNames["ml-kem-768"], "should have ml-kem-768")
	require.True(t, algNames["ml-kem-512"], "should have ml-kem-512")
	require.True(t, algNames["ml-kem-1024"], "should have ml-kem-1024")
	require.True(t, algNames["ml-dsa-65"], "should have ml-dsa-65")
	require.True(t, algNames["bls-threshold"], "should have bls-threshold")
}
