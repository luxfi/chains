// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"errors"
	"fmt"

	"github.com/luxfi/accel"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

// ErrInvalidBridgeSignature is returned when CMP (CGGMP21) threshold
// signature verification fails on a bridge request or block. Custody
// signing itself runs on M-Chain (mpcvm) via dealerless FROST/CGGMP21;
// B-Chain only VERIFIES the resulting threshold signatures here.
var ErrInvalidBridgeSignature = errors.New("invalid bridge signature")

// batchVerifyBlockSignatures verifies all MPC block signatures using GPU-accelerated
// ECDSA batch verification when available. Falls back to sequential verification.
// Returns the count of valid signatures.
func batchVerifyBlockSignatures(
	blockHash ids.ID,
	signatures map[ids.NodeID][]byte,
	mpcCfg *config.Config,
	logger log.Logger,
) int {
	if len(signatures) == 0 || mpcCfg == nil {
		return 0
	}

	// Collect entries that have a known public key
	var entries []sigEntry
	for nodeID, sigBytes := range signatures {
		pid := party.ID(nodeID.String())
		if _, exists := mpcCfg.Public[pid]; exists {
			entries = append(entries, sigEntry{nodeID, sigBytes, pid})
		}
	}

	if len(entries) == 0 {
		return 0
	}

	// GPU batch path
	if accel.Available() && len(entries) > 1 {
		count, err := batchVerifyECDSABlockGPU(blockHash, entries, mpcCfg, logger)
		if err == nil {
			return count
		}
		logger.Debug("GPU ECDSA batch verify failed, falling back to CPU",
			log.Reflect("error", err),
		)
	}

	// CPU fallback: sequential
	validCount := 0
	for _, e := range entries {
		if verifyBlockSig(mpcCfg, blockHash, e) {
			validCount++
		}
	}
	return validCount
}

// verifyBlockSig is the ONE acceptance predicate for a block MPC signature: is
// sigBytes a valid signature by this party's key over the block hash? Both the
// CPU loop and the GPU batch answer this same question — the accelerator only
// batches it, it never redefines it.
func verifyBlockSig(mpcCfg *config.Config, blockHash ids.ID, e sigEntry) bool {
	sig, err := deserializeSignature(mpcCfg.Group, e.sigBytes)
	if err != nil {
		return false
	}
	return sig.Verify(mpcCfg.Public[e.partyID].ECDSA, blockHash[:])
}

// sigEntry holds a signature entry for batch verification.
type sigEntry struct {
	nodeID   ids.NodeID
	sigBytes []byte
	partyID  party.ID
}

// Tensor row widths for the block-signature batch.
const (
	batchHashSize = 32
	batchSigSize  = 64
	batchPKSize   = 33
)

// packBlockSigBatch lays out the (message, signature, public key) rows the ECDSA
// batch kernel consumes, one row per entry.
//
// The message is the block hash ITSELF, byte for byte what verifyBlockSig hands
// to sig.Verify. Hashing it again here would have the accelerator check a
// different message than the CPU, so one signature set would be valid on a GPU
// node and invalid on a node without one — an accept/reject split decided by host
// hardware.
//
// Every row of the result vector must carry real inputs. Zero-filling a row whose
// signature or public key could not be prepared, and then trusting the kernel's
// verdict for that row, counts a signature the CPU path rejects outright. Anything
// this layout cannot represent exactly is an error, which sends the whole batch to
// the CPU — the one acceptance authority.
func packBlockSigBatch(blockHash ids.ID, entries []sigEntry, mpcCfg *config.Config) (messages, sigs, pubkeys []byte, err error) {
	n := len(entries)
	messages = make([]byte, n*batchHashSize)
	sigs = make([]byte, n*batchSigSize)
	pubkeys = make([]byte, n*batchPKSize)

	for i, e := range entries {
		copy(messages[i*batchHashSize:], blockHash[:])

		if len(e.sigBytes) < batchSigSize {
			return nil, nil, nil, fmt.Errorf("signature for %s is %d bytes, want at least %d", e.partyID, len(e.sigBytes), batchSigSize)
		}
		copy(sigs[i*batchSigSize:], e.sigBytes[:batchSigSize])

		pkBytes, mErr := mpcCfg.Public[e.partyID].ECDSA.MarshalBinary()
		if mErr != nil {
			return nil, nil, nil, fmt.Errorf("public key for %s: %w", e.partyID, mErr)
		}
		if len(pkBytes) < batchPKSize {
			return nil, nil, nil, fmt.Errorf("public key for %s is %d bytes, want %d", e.partyID, len(pkBytes), batchPKSize)
		}
		copy(pubkeys[i*batchPKSize:], pkBytes[:batchPKSize])
	}
	return messages, sigs, pubkeys, nil
}

// batchVerifyECDSABlockGPU runs GPU-accelerated ECDSA batch verification for block signatures.
func batchVerifyECDSABlockGPU(
	blockHash ids.ID,
	entries []sigEntry,
	mpcCfg *config.Config,
	logger log.Logger,
) (int, error) {
	session, err := accel.DefaultSession()
	if err != nil {
		return 0, err
	}

	n := len(entries)
	hashSize, sigSize, pkSize := batchHashSize, batchSigSize, batchPKSize

	messages, sigs, pubkeys, err := packBlockSigBatch(blockHash, entries, mpcCfg)
	if err != nil {
		return 0, err
	}

	msgTensor, err := accel.NewTensorWithData[byte](session, []int{n, hashSize}, messages)
	if err != nil {
		return 0, err
	}
	defer msgTensor.Close()

	sigTensor, err := accel.NewTensorWithData[byte](session, []int{n, sigSize}, sigs)
	if err != nil {
		return 0, err
	}
	defer sigTensor.Close()

	pkTensor, err := accel.NewTensorWithData[byte](session, []int{n, pkSize}, pubkeys)
	if err != nil {
		return 0, err
	}
	defer pkTensor.Close()

	resultTensor, err := accel.NewTensor[byte](session, []int{n})
	if err != nil {
		return 0, err
	}
	defer resultTensor.Close()

	crypto := session.Crypto()
	if err := crypto.ECDSAVerifyBatch(
		msgTensor.Untyped(),
		sigTensor.Untyped(),
		pkTensor.Untyped(),
		resultTensor.Untyped(),
	); err != nil {
		return 0, err
	}

	if err := session.Sync(); err != nil {
		return 0, err
	}

	resultBytes, err := resultTensor.ToSlice()
	if err != nil {
		return 0, err
	}

	validCount := 0
	for _, r := range resultBytes {
		if r == 1 {
			validCount++
		}
	}

	logger.Debug("GPU ECDSA batch block sig verify",
		log.Int("total", n),
		log.Int("valid", validCount),
	)
	return validCount, nil
}

// batchVerifyRequestSignaturesGPU verifies MPC signatures on multiple bridge requests
// using GPU acceleration when available. Returns per-request errors.
func batchVerifyRequestSignaturesGPU(
	requests []*BridgeRequest,
	mpcCfg *config.Config,
	logger log.Logger,
) []error {
	results := make([]error, len(requests))

	if mpcCfg == nil {
		for i, req := range requests {
			if len(req.MPCSignatures) > 0 {
				results[i] = ErrInvalidBridgeSignature
			}
		}
		return results
	}

	// Collect requests that have signatures
	type reqEntry struct {
		index   int
		msgHash []byte
		sigData []byte
	}
	var entries []reqEntry
	for i, req := range requests {
		if len(req.MPCSignatures) == 0 {
			continue
		}
		entries = append(entries, reqEntry{
			index:   i,
			msgHash: computeRequestHash(req),
			sigData: req.MPCSignatures[0],
		})
	}

	if len(entries) <= 1 || !accel.Available() {
		// Sequential fallback
		groupPK := mpcCfg.PublicPoint()
		for _, e := range entries {
			sig, err := deserializeSignature(mpcCfg.Group, e.sigData)
			if err != nil {
				results[e.index] = fmt.Errorf("deserialize sig: %w", err)
				continue
			}
			if !sig.Verify(groupPK, e.msgHash) {
				results[e.index] = ErrInvalidBridgeSignature
			}
		}
		return results
	}

	// GPU batch path
	session, err := accel.DefaultSession()
	if err != nil {
		goto cpuFallback
	}

	{
		groupPK := mpcCfg.PublicPoint()
		if groupPK == nil {
			goto cpuFallback
		}
		groupPKBytes, err := groupPK.MarshalBinary()
		if err != nil {
			goto cpuFallback
		}

		n := len(entries)
		const hashSize = 32
		const sigSize = 64
		pkSize := len(groupPKBytes)
		if pkSize < 33 {
			pkSize = 33
		}

		messages := make([]byte, n*hashSize)
		sigBytes := make([]byte, n*sigSize)
		pubkeys := make([]byte, n*pkSize)

		for j, e := range entries {
			if len(e.msgHash) >= hashSize {
				copy(messages[j*hashSize:], e.msgHash[:hashSize])
			}
			if len(e.sigData) >= sigSize {
				copy(sigBytes[j*sigSize:], e.sigData[:sigSize])
			}
			copy(pubkeys[j*pkSize:], groupPKBytes)
		}

		msgTensor, err := accel.NewTensorWithData[byte](session, []int{n, hashSize}, messages)
		if err != nil {
			goto cpuFallback
		}
		defer msgTensor.Close()

		sigTensor, err := accel.NewTensorWithData[byte](session, []int{n, sigSize}, sigBytes)
		if err != nil {
			goto cpuFallback
		}
		defer sigTensor.Close()

		pkTensor, err := accel.NewTensorWithData[byte](session, []int{n, pkSize}, pubkeys)
		if err != nil {
			goto cpuFallback
		}
		defer pkTensor.Close()

		resultTensor, err := accel.NewTensor[byte](session, []int{n})
		if err != nil {
			goto cpuFallback
		}
		defer resultTensor.Close()

		crypto := session.Crypto()
		if err := crypto.ECDSAVerifyBatch(
			msgTensor.Untyped(),
			sigTensor.Untyped(),
			pkTensor.Untyped(),
			resultTensor.Untyped(),
		); err != nil {
			goto cpuFallback
		}

		if err := session.Sync(); err != nil {
			goto cpuFallback
		}

		resultData, err := resultTensor.ToSlice()
		if err != nil {
			goto cpuFallback
		}

		for j, e := range entries {
			if resultData[j] != 1 {
				results[e.index] = ErrInvalidBridgeSignature
			}
		}

		logger.Debug("GPU batch request sig verify",
			log.Int("total", n),
		)
		return results
	}

cpuFallback:
	groupPK := mpcCfg.PublicPoint()
	for _, e := range entries {
		sig, err := deserializeSignature(mpcCfg.Group, e.sigData)
		if err != nil {
			results[e.index] = fmt.Errorf("deserialize sig: %w", err)
			continue
		}
		if !sig.Verify(groupPK, e.msgHash) {
			results[e.index] = ErrInvalidBridgeSignature
		}
	}
	return results
}
