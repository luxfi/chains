// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package stamper

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// hybridStamp returns a hybrid-mode stamp whose SLH-DSA signature is made over
// its OWN signing bytes, plus the signing bytes themselves.
func hybridStamp(t *testing.T, qs *QuantumStamper, height uint64) (*QuantumStamp, []byte) {
	t.Helper()

	stamp := &QuantumStamp{
		CChainHeight: height,
		CChainHash:   common.BigToHash(new(big.Int).SetUint64(height)),
		QChainHeight: height,
		QChainHash:   common.BytesToHash([]byte{byte(height)}),
		Mode:         StampModeHybrid,
		Timestamp:    time.Unix(int64(height), 0),
		StateRoot:    common.BytesToHash([]byte{byte(height), 0x01}),
		ReceiptsRoot: common.BytesToHash([]byte{byte(height), 0x02}),
		GasUsed:      1000 + height,
		Nonce:        []byte{byte(height)},
	}

	signData := qs.prepareSignatureData(stamp)

	sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	require.NoError(t, err)
	sig, err := sk.SignCtx(rand.Reader, signData, nil)
	require.NoError(t, err)

	stamp.SLHDSASignature = sig
	stamp.PublicKeySLH = sk.PublicKey.Bytes()
	return stamp, signData
}

// TestHybridBatchVerifiesEachStampAgainstItsOwnData proves the SLH-DSA leg of a
// hybrid stamp is checked against that stamp's signing bytes.
//
// signDataSlice is indexed by batch position while indices maps position to stamp
// index. Reading signDataSlice[0] for every hybrid stamp verified each one's
// post-quantum signature against the FIRST batch entry's bytes, so a signature
// over data the stamp does not commit to satisfied its post-quantum leg — and the
// submitter of a batch chooses what entry zero contains.
func TestHybridBatchVerifiesEachStampAgainstItsOwnData(t *testing.T) {
	require := require.New(t)
	qs := &QuantumStamper{log: nil}

	first, firstData := hybridStamp(t, qs, 1)
	second, secondData := hybridStamp(t, qs, 2)
	require.NotEqual(firstData, secondData, "the two stamps commit to different bytes")

	stamps := []*QuantumStamp{first, second}
	indices := []int{0, 1}
	signDataSlice := [][]byte{firstData, secondData}
	results := []bool{true, true}

	qs.verifyHybridSLHDSA(stamps, indices, signDataSlice, results)

	require.True(results[0], "batch position 0 verifies against its own data")
	require.True(results[1], "batch position 1 must verify against ITS data, not position 0's")
}

// TestHybridBatchRejectsSignatureOverAnotherStampsData is the negative half: a
// stamp carrying a signature made over a different stamp's bytes is refused.
func TestHybridBatchRejectsSignatureOverAnotherStampsData(t *testing.T) {
	require := require.New(t)
	qs := &QuantumStamper{log: nil}

	first, firstData := hybridStamp(t, qs, 1)
	forged, forgedData := hybridStamp(t, qs, 2)

	// Give the second stamp a signature that is valid over the FIRST stamp's data.
	sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	require.NoError(err)
	sig, err := sk.SignCtx(rand.Reader, firstData, nil)
	require.NoError(err)
	forged.SLHDSASignature = sig
	forged.PublicKeySLH = sk.PublicKey.Bytes()

	stamps := []*QuantumStamp{first, forged}
	results := []bool{true, true}
	qs.verifyHybridSLHDSA(stamps, []int{0, 1}, [][]byte{firstData, forgedData}, results)

	require.True(results[0])
	require.False(results[1], "a signature over another stamp's data must not satisfy this stamp")
}

// TestStampMatchesBlockCoversReceiptsRoot pins the block-correspondence predicate
// both verification paths share. The accelerated batch path re-listed the fields
// itself and omitted ReceiptsRoot, so a stamp with a forged receipts root was
// accepted whenever the batch went to the accelerator and refused when it did not.
func TestStampMatchesBlockCoversReceiptsRoot(t *testing.T) {
	require := require.New(t)

	header := &types.Header{
		Number:      new(big.Int).SetUint64(7),
		Root:        common.BytesToHash([]byte{0xaa}),
		ReceiptHash: common.BytesToHash([]byte{0xbb}),
		GasUsed:     4242,
	}
	block := types.NewBlockWithHeader(header)

	good := &QuantumStamp{
		CChainHeight: block.NumberU64(),
		CChainHash:   block.Hash(),
		StateRoot:    block.Root(),
		ReceiptsRoot: block.ReceiptHash(),
		GasUsed:      block.GasUsed(),
	}
	require.True(stampMatchesBlock(good, block))

	for name, tamper := range map[string]func(*QuantumStamp){
		"height":       func(s *QuantumStamp) { s.CChainHeight++ },
		"hash":         func(s *QuantumStamp) { s.CChainHash = common.BytesToHash([]byte{0x01}) },
		"stateRoot":    func(s *QuantumStamp) { s.StateRoot = common.BytesToHash([]byte{0x02}) },
		"receiptsRoot": func(s *QuantumStamp) { s.ReceiptsRoot = common.BytesToHash([]byte{0x03}) },
		"gasUsed":      func(s *QuantumStamp) { s.GasUsed++ },
	} {
		bad := *good
		tamper(&bad)
		require.False(stampMatchesBlock(&bad, block), "a forged %s must not match the block", name)
	}
}
