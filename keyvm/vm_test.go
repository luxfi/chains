// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/keyvm/config"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// ---- shared test helpers ----

// newTestVM initializes an in-memory K-Chain seeded with the given funding
// allocation (hex address -> nLUX).
func newTestVM(t *testing.T, alloc map[string]uint64) *VM {
	t.Helper()
	logger := log.NewNoOpLogger()
	gb, err := json.Marshal(Genesis{Version: 1, Timestamp: time.Now().Unix(), Alloc: alloc})
	require.NoError(t, err)
	rt := &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger}
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  gb,
	}))
	return vm
}

// testKey is an external payer identity (the payer holds its own secret; K never
// does). The ML-DSA-65 private key here lives ONLY in the test, exercising the
// public-key authentication path on the VM side.
type testKey struct {
	priv *mldsa.PrivateKey
	pub  []byte
	addr fee_Account
}

// fee_Account aliases the fee package account type for brevity in tests.
type fee_Account = ids.ShortID

func newTestKey(t *testing.T) testKey {
	t.Helper()
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	pub := priv.PublicKey.Bytes()
	return testKey{priv: priv, pub: pub, addr: addressOf(pub)}
}

func (k testKey) hexAddr() string { return hex.EncodeToString(k.addr[:]) }

// sign attaches the payer's public key and a valid signature over the tx's
// signing bytes, then clears the cached id so ID() recomputes.
func (k testKey) sign(t *testing.T, tx *Transaction) {
	t.Helper()
	tx.Auth = k.pub
	sig, err := k.priv.Sign(rand.Reader, tx.SigningBytes(), crypto.Hash(0))
	require.NoError(t, err)
	tx.Sig = sig
	tx.id = ids.Empty
}

// registerTx builds a signed RegisterKey transaction for an ML-DSA-65 key.
func registerTx(t *testing.T, k testKey, name string, gasLimit, nonce uint64) *Transaction {
	t.Helper()
	payload, err := json.Marshal(RegisterKeyPayload{
		Name:        name,
		PublicKey:   []byte("PUBLIC-KEY-MATERIAL-ONLY"),
		Threshold:   3,
		TotalShares: 5,
		Commitments: [][]byte{{0x01}, {0x02}, {0x03}}, // PUBLIC VSS commitments
		Committee:   []ids.NodeID{},
		Policy:      AuthPolicy{},
	})
	require.NoError(t, err)
	tx := &Transaction{
		Type:      TxRegisterKey,
		Algorithm: "ml-dsa-65",
		Payer:     k.addr,
		KeyID:     deriveKeyID(name),
		GasLimit:  gasLimit,
		Nonce:     nonce,
		Payload:   payload,
	}
	k.sign(t, tx)
	return tx
}

// ---- config tests (config is unchanged by the auth-only rewrite) ----

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
		{name: "default config valid", cfg: config.DefaultConfig(), wantErr: false},
		{
			name: "invalid ml-kem security level",
			cfg: config.Config{
				ListenPort: 9630, MLKEMEnabled: true, MLKEMSecurityLevel: 999,
				DefaultThreshold: 3, DefaultTotalShares: 5,
				Validators: []string{"a", "b", "c", "d", "e"},
			},
			wantErr: true,
		},
		{
			name: "threshold exceeds total shares",
			cfg: config.Config{
				ListenPort: 9630, DefaultThreshold: 10, DefaultTotalShares: 5,
				Validators: []string{"a", "b", "c", "d", "e"},
			},
			wantErr: true,
		},
		{
			name: "insufficient validators",
			cfg: config.Config{
				ListenPort: 9630, DefaultThreshold: 3, DefaultTotalShares: 5,
				Validators: []string{"a", "b"},
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

func TestVMInitializeAuthOnly(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()

	v, err := vm.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, Version, v)

	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, h.Healthy)
	require.Equal(t, "true", h.Details["authOnly"])
}
