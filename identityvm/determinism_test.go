// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

// credentialExpiringAt builds a self-issued credential with the given expiry.
func credentialExpiringAt(expiry time.Time) *Credential {
	return &Credential{
		ID:             ids.GenerateTestID(),
		Type:           []string{"VerifiableCredential"},
		Issuer:         ids.GenerateTestID(),
		Subject:        ids.GenerateTestID(),
		IssuanceDate:   expiry.Add(-time.Hour),
		ExpirationDate: expiry,
		Claims:         map[string]interface{}{"name": "test"},
		Status:         CredentialActive,
	}
}

// TestCredentialExpiryIsJudgedAtBlockTime pins credential expiry to the block
// timestamp rather than the wall clock. Against time.Now() the same block is
// valid before the expiry and invalid after it, so two nodes verifying either
// side of that instant disagree — and a node replaying history during bootstrap
// rejects every historical block whose credentials have since expired, which is
// every one of them.
func TestCredentialExpiryIsJudgedAtBlockTime(t *testing.T) {
	require := require.New(t)
	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// A block from the past carrying a credential that was valid then and has
	// since expired. Replaying it must still verify.
	blockTime := time.Now().Add(-48 * time.Hour)
	historical := &Block{
		BlockHeight:    1,
		BlockTimestamp: blockTime.Unix(),
		Credentials:    []*Credential{credentialExpiringAt(blockTime.Add(time.Hour))},
		vm:             vm,
	}
	require.NoError(historical.verifyCredential(historical.Credentials[0]),
		"a credential live at the block's timestamp must verify when replayed later")

	// A block that carries a credential already expired at its own timestamp is
	// still refused.
	stale := &Block{
		BlockHeight:    1,
		BlockTimestamp: blockTime.Unix(),
		Credentials:    []*Credential{credentialExpiringAt(blockTime.Add(-time.Hour))},
		vm:             vm,
	}
	require.Error(stale.verifyCredential(stale.Credentials[0]))
}

// TestRequireZKProofsCannotBeSkippedByOmittingTheProof proves the ZK requirement
// is not gated on the presence of the thing it requires. A credential with no
// proof object verified under RequireZKProofs, so the setting was bypassed by
// simply not supplying a proof.
func TestRequireZKProofsCannotBeSkippedByOmittingTheProof(t *testing.T) {
	require := require.New(t)
	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	vm.config.RequireZKProofs = true

	noProof := credentialExpiringAt(time.Now().Add(time.Hour))
	emptyProof := credentialExpiringAt(time.Now().Add(time.Hour))
	emptyProof.Proof = &CredentialProof{Type: "zk"}
	withProof := credentialExpiringAt(time.Now().Add(time.Hour))
	withProof.Proof = &CredentialProof{Type: "zk", ZKProof: []byte("proof-bytes")}

	vm.mu.Lock()
	for _, c := range []*Credential{noProof, emptyProof, withProof} {
		vm.credentials[c.ID] = c
	}
	vm.mu.Unlock()

	ok, err := vm.VerifyCredential(noProof.ID)
	require.False(ok, "a credential with no proof must not satisfy RequireZKProofs")
	require.ErrorIs(err, errInvalidProof)

	ok, err = vm.VerifyCredential(emptyProof.ID)
	require.False(ok)
	require.ErrorIs(err, errInvalidProof)

	ok, err = vm.VerifyCredential(withProof.ID)
	require.NoError(err)
	require.True(ok)
}
