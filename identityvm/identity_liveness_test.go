// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIssuingACredentialBuildsABlock is the whole path: a credential is issued,
// consensus is told there is work, and the block that gets built carries it.
//
// WaitForEvent used to wait only on the context, so it never returned, BuildBlock
// was never called, and I-Chain could not leave genesis however many credentials
// were issued.
func TestIssuingACredentialBuildsABlock(t *testing.T) {
	require := require.New(t)
	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	subject, err := vm.CreateIdentity([]byte("subject-key"), nil)
	require.NoError(err)

	// Nothing issued yet, so nothing should be claimed and nothing built.
	idle, cancelIdle := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelIdle()
	_, err = vm.WaitForEvent(idle)
	require.Error(err, "an idle chain reported work to build")

	_, err = vm.BuildBlock(context.Background())
	require.ErrorIs(err, errNothingToBuild,
		"a block with nothing in it says nothing and still has to be voted on")

	cred, err := vm.IssueCredential(subject.ID, subject.ID, []string{"test"},
		map[string]interface{}{"claim": "value"}, time.Hour)
	require.NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = vm.WaitForEvent(ctx)
	require.NoError(err, "a credential was issued and consensus was never told")

	blk, err := vm.BuildBlock(ctx)
	require.NoError(err)
	built, ok := blk.(*Block)
	require.True(ok)
	require.Len(built.Credentials, 1)
	require.Equal(cred.ID, built.Credentials[0].ID,
		"the block carries a different credential than the one issued")
}
