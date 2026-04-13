// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"crypto/sha256"
	"fmt"

	"github.com/luxfi/accel"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

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
		sig, err := deserializeSignature(mpcCfg.Group, e.sigBytes)
		if err != nil {
			continue
		}
		pubInfo := mpcCfg.Public[e.partyID]
		if sig.Verify(pubInfo.ECDSA, blockHash[:]) {
			validCount++
		}
	}
	return validCount
}

// sigEntry holds a signature entry for batch verification.
type sigEntry struct {
	nodeID   ids.NodeID
	sigBytes []byte
	partyID  party.ID
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
	msgHash := sha256.Sum256(blockHash[:])

	const hashSize = 32
	const sigSize = 64
	const pkSize = 33

	messages := make([]byte, n*hashSize)
	sigs := make([]byte, n*sigSize)
	pubkeys := make([]byte, n*pkSize)

	for i, e := range entries {
		copy(messages[i*hashSize:], msgHash[:])

		if len(e.sigBytes) >= sigSize {
			copy(sigs[i*sigSize:], e.sigBytes[:sigSize])
		}

		pubInfo := mpcCfg.Public[e.partyID]
		pkBytes, mErr := pubInfo.ECDSA.MarshalBinary()
		if mErr != nil {
			continue
		}
		if len(pkBytes) >= pkSize {
			copy(pubkeys[i*pkSize:], pkBytes[:pkSize])
		}
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
