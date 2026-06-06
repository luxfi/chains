// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// Round-trip tests for the hand-rolled wire layout. These pin the canonical
// binary so an accidental field reorder or layout change shows up as a test
// failure rather than silent on-disk corruption.

func TestRoundTrip_UTXO(t *testing.T) {
	req := require.New(t)
	u := &UTXO{
		TxID:        ids.GenerateTestID(),
		OutputIndex: 7,
		Commitment:  []byte("commitment-bytes-32-bytes-padded"),
		Ciphertext:  bytes.Repeat([]byte{0xaa}, 256),
		EphemeralPK: bytes.Repeat([]byte{0xbb}, 32),
		Height:      42,
	}
	b, err := marshalUTXO(u)
	req.NoError(err)
	req.Equal(sizeUTXO(u), len(b))

	var got UTXO
	req.NoError(unmarshalUTXO(b, &got))
	req.Equal(*u, got)
}

func TestRoundTrip_PrivateAddress(t *testing.T) {
	req := require.New(t)
	p := &PrivateAddress{
		Address:         bytes.Repeat([]byte{0x01}, 32),
		ViewingKey:      bytes.Repeat([]byte{0x02}, 32),
		SpendingKey:     bytes.Repeat([]byte{0x03}, 32),
		Diversifier:     bytes.Repeat([]byte{0x04}, 11),
		IncomingViewKey: bytes.Repeat([]byte{0x05}, 32),
		CreatedAt:       1234567890,
	}
	b, err := marshalPrivateAddress(p)
	req.NoError(err)
	req.Equal(sizePrivateAddress(p), len(b))

	var got PrivateAddress
	req.NoError(unmarshalPrivateAddress(b, &got))
	req.Equal(*p, got)
}

func TestRoundTrip_ZConfig(t *testing.T) {
	req := require.New(t)
	c := &ZConfig{
		EnableConfidentialTransfers: true,
		EnablePrivateAddresses:      true,
		ProofSystem:                 "groth16",
		CircuitType:                 "transfer",
		VerifyingKeyPath:            "/etc/zkvm/vk",
		TrustedSetupPath:            "/etc/zkvm/setup",
		EnableFHE:                   true,
		FHEScheme:                   "CKKS",
		SecurityLevel:               128,
		MaxUTXOsPerBlock:            100,
		ProofVerificationTimeout:    150 * time.Millisecond,
		ProofCacheSize:              1000,
	}
	b, err := marshalConfig(c)
	req.NoError(err)
	req.Equal(sizeConfig(c), len(b))

	var got ZConfig
	req.NoError(unmarshalConfig(b, &got))
	req.Equal(*c, got)
}

func TestRoundTrip_Transaction_Shielded(t *testing.T) {
	req := require.New(t)
	tx := &Transaction{
		ID:      ids.GenerateTestID(),
		Type:    TransactionTypeTransfer,
		Version: 1,
		Nullifiers: [][]byte{
			bytes.Repeat([]byte{0xa0}, 32),
			bytes.Repeat([]byte{0xa1}, 32),
		},
		Outputs: []*ShieldedOutput{
			{
				Commitment:      bytes.Repeat([]byte{0xc1}, 32),
				EncryptedNote:   bytes.Repeat([]byte{0xc2}, 128),
				EphemeralPubKey: bytes.Repeat([]byte{0xc3}, 32),
				OutputProof:     bytes.Repeat([]byte{0xc4}, 96),
			},
		},
		Proof: &ZKProof{
			ProofType: "groth16",
			ProofData: bytes.Repeat([]byte{0xdd}, 192),
			PublicInputs: [][]byte{
				bytes.Repeat([]byte{0xee}, 32),
			},
		},
		Fee:       2500,
		Expiry:    999,
		Memo:      []byte("hello"),
		Signature: bytes.Repeat([]byte{0xff}, 64),
	}
	b, err := marshalTransaction(tx)
	req.NoError(err)
	req.Equal(sizeTransaction(tx), len(b))

	var got Transaction
	req.NoError(unmarshalTransaction(b, &got))
	req.Equal(*tx, got)
}

func TestRoundTrip_Transaction_Transparent(t *testing.T) {
	req := require.New(t)
	tx := &Transaction{
		ID:      ids.GenerateTestID(),
		Type:    TransactionTypeShield,
		Version: 1,
		TransparentInputs: []*TransparentInput{
			{
				TxID:      ids.GenerateTestID(),
				OutputIdx: 3,
				Amount:    1_000_000,
				Address:   bytes.Repeat([]byte{0xaa}, 20),
			},
		},
		TransparentOutputs: []*TransparentOutput{
			{
				Amount:  500_000,
				Address: bytes.Repeat([]byte{0xbb}, 20),
				AssetID: ids.GenerateTestID(),
			},
		},
		Outputs: []*ShieldedOutput{
			{
				Commitment:      bytes.Repeat([]byte{0xc1}, 32),
				EncryptedNote:   bytes.Repeat([]byte{0xc2}, 64),
				EphemeralPubKey: bytes.Repeat([]byte{0xc3}, 32),
				OutputProof:     bytes.Repeat([]byte{0xc4}, 64),
			},
		},
		Proof: &ZKProof{ProofType: "plonk", ProofData: []byte("p")},
		FHEData: &FHEData{
			EncryptedInputs:  [][]byte{[]byte("ein")},
			CircuitID:        "C1",
			EncryptedResult:  []byte("er"),
			ComputationProof: []byte("cp"),
		},
		Fee:    1,
		Expiry: 2,
	}
	b, err := marshalTransaction(tx)
	req.NoError(err)

	var got Transaction
	req.NoError(unmarshalTransaction(b, &got))
	req.Equal(*tx, got)
}

func TestRoundTrip_Block(t *testing.T) {
	req := require.New(t)
	blk := &Block{
		ParentID_:      ids.GenerateTestID(),
		BlockHeight:    101,
		BlockTimestamp: 1_700_000_000,
		Txs: []*Transaction{
			{
				ID:      ids.GenerateTestID(),
				Type:    TransactionTypeTransfer,
				Version: 1,
				Nullifiers: [][]byte{
					bytes.Repeat([]byte{0xaa}, 32),
				},
				Outputs: []*ShieldedOutput{
					{
						Commitment:      bytes.Repeat([]byte{0xb1}, 32),
						EncryptedNote:   bytes.Repeat([]byte{0xb2}, 32),
						EphemeralPubKey: bytes.Repeat([]byte{0xb3}, 32),
						OutputProof:     bytes.Repeat([]byte{0xb4}, 32),
					},
				},
				Proof: &ZKProof{ProofType: "groth16", ProofData: []byte("p")},
			},
		},
		StateRoot:  bytes.Repeat([]byte{0xee}, 32),
		BlockProof: &ZKProof{ProofType: "plonk", ProofData: []byte("bp")},
	}
	b, err := marshalBlock(blk)
	req.NoError(err)
	req.Equal(sizeBlock(blk), len(b))

	var got Block
	req.NoError(unmarshalBlock(b, &got))
	req.Equal(blk.ParentID_, got.ParentID_)
	req.Equal(blk.BlockHeight, got.BlockHeight)
	req.Equal(blk.BlockTimestamp, got.BlockTimestamp)
	req.Equal(blk.StateRoot, got.StateRoot)
	req.Len(got.Txs, 1)
	req.Equal(*blk.Txs[0], *got.Txs[0])
	req.Equal(*blk.BlockProof, *got.BlockProof)
}

func TestRoundTrip_Genesis(t *testing.T) {
	req := require.New(t)
	g := &Genesis{
		Timestamp: 1_607_144_400,
		InitialTxs: []*Transaction{
			{
				ID:      ids.GenerateTestID(),
				Type:    TransactionTypeMint,
				Version: 1,
				Outputs: []*ShieldedOutput{
					{
						Commitment:      bytes.Repeat([]byte{0x11}, 32),
						EncryptedNote:   bytes.Repeat([]byte{0x22}, 32),
						EphemeralPubKey: bytes.Repeat([]byte{0x33}, 32),
						OutputProof:     bytes.Repeat([]byte{0x44}, 32),
					},
				},
				Proof: &ZKProof{ProofType: "groth16", ProofData: []byte("p")},
			},
		},
		SetupParams: &SetupParams{
			PowersOfTau:     bytes.Repeat([]byte{0xa1}, 64),
			VerifyingKey:    bytes.Repeat([]byte{0xa2}, 64),
			PlonkSRS:        bytes.Repeat([]byte{0xa3}, 64),
			FHEPublicParams: bytes.Repeat([]byte{0xa4}, 64),
		},
	}
	b, err := marshalGenesis(g)
	req.NoError(err)
	req.Equal(sizeGenesis(g), len(b))

	var got Genesis
	req.NoError(unmarshalGenesis(b, &got))
	req.Equal(g.Timestamp, got.Timestamp)
	req.Len(got.InitialTxs, 1)
	req.Equal(*g.InitialTxs[0], *got.InitialTxs[0])
	req.Equal(*g.SetupParams, *got.SetupParams)
}

func TestUnmarshal_ShortBuffer(t *testing.T) {
	req := require.New(t)
	req.Error(unmarshalUTXO(nil, &UTXO{}))
	req.Error(unmarshalBlock(nil, &Block{}))
	req.Error(unmarshalTransaction(nil, &Transaction{}))
	req.Error(unmarshalGenesis(nil, &Genesis{}))
	req.Error(unmarshalConfig(nil, &ZConfig{}))
	req.Error(unmarshalPrivateAddress(nil, &PrivateAddress{}))
}
