// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// decryptSession builds a 3-of-5 handler with one open decryption session.
func decryptSession(threshold int) (*FHEProtocolHandler, [32]byte) {
	id := [32]byte{1}
	h := &FHEProtocolHandler{
		threshold: threshold,
		total:     5,
		sessions: map[[32]byte]*FHESession{
			id: {
				ID:     id,
				Type:   SessionDecrypt,
				Status: StatusPending,
				Shares: make(map[uint64][]byte),
			},
		},
	}
	return h, id
}

// TestOnePartyCannotReachDecryptionThreshold proves the threshold counts
// DISTINCT parties. One party resubmitting must never satisfy a 3-of-5 quorum:
// that would let a single share holder decrypt a value the scheme exists to keep
// from any minority.
func TestOnePartyCannotReachDecryptionThreshold(t *testing.T) {
	require := require.New(t)
	h, id := decryptSession(3)

	require.NoError(h.SubmitDecryptionShare(id, 1, []byte("share-from-party-1")))
	require.Error(h.SubmitDecryptionShare(id, 1, []byte("again")))
	require.Error(h.SubmitDecryptionShare(id, 1, []byte("and-again")))

	session := h.sessions[id]
	require.Equal(1, session.ShareCount, "one party contributed one share")
	require.Equal(StatusCollecting, session.Status,
		"a single party must not advance the session to processing")
}

// TestDistinctPartiesReachDecryptionThreshold is the other half: three different
// parties do satisfy 3-of-5.
func TestDistinctPartiesReachDecryptionThreshold(t *testing.T) {
	require := require.New(t)
	h, id := decryptSession(3)

	require.NoError(h.SubmitDecryptionShare(id, 1, []byte("s1")))
	require.NoError(h.SubmitDecryptionShare(id, 2, []byte("s2")))
	require.Equal(StatusCollecting, h.sessions[id].Status)

	require.NoError(h.SubmitDecryptionShare(id, 3, []byte("s3")))
	require.Equal(3, h.sessions[id].ShareCount)
	require.Equal(StatusProcessing, h.sessions[id].Status)
}
