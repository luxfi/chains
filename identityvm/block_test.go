// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// refusingDB is a real database whose flush to disk can be made to fail. That
// is how a block fails in the field: the writes are complete and staged, and
// making them durable is what does not happen.
type refusingDB struct {
	database.Database
	refuse bool
}

func (d *refusingDB) NewBatch() database.Batch {
	return &refusingBatch{Batch: d.Database.NewBatch(), db: d}
}

type refusingBatch struct {
	database.Batch
	db *refusingDB
}

var errRefused = errors.New("flush refused")

func (b *refusingBatch) Write() error {
	if b.db.refuse {
		return errRefused
	}
	return b.Batch.Write()
}

func newRefusingVM(t *testing.T) (*VM, *refusingDB) {
	t.Helper()
	db := &refusingDB{Database: memdb.New()}

	genesisBytes, err := json.Marshal(&Genesis{
		Timestamp: 1,
		Config:    &Config{CredentialTTL: 3600, MaxClaims: 50, AllowSelfIssue: true},
	})
	require.NoError(t, err)

	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), Log: log.NewNoOpLogger()},
		DB:       db,
		Genesis:  genesisBytes,
		ToEngine: make(chan vmcore.Message, 10),
	}))
	return vm, db
}

// TestABlockThatCannotCommitLeavesNothingBehind is the defect this chain had.
// Accept used to set the status, move lastAccepted, and then issue one Put per
// credential, each returning early — so a failure partway through left the
// earlier credentials on disk with the chain already believing the block was
// applied, and no way back.
//
// Now every write of the block is staged and committed together. When the
// commit fails, none of it lands, the chain does not move, and none of the
// block's records become visible.
func TestABlockThatCannotCommitLeavesNothingBehind(t *testing.T) {
	vm, db := newRefusingVM(t)
	defer vm.Shutdown(context.Background())

	subject, err := vm.CreateIdentity([]byte("subject"), nil)
	require.NoError(t, err)
	issuer, err := vm.RegisterIssuer("issuer", []byte("issuer-key"), []string{"T"}, 1)
	require.NoError(t, err)

	var creds []*Credential
	for i := 0; i < 3; i++ {
		c, err := vm.IssueCredential(issuer.ID, subject.ID, []string{"T"},
			map[string]interface{}{"i": i}, time.Hour)
		require.NoError(t, err)
		creds = append(creds, c)
	}

	arrival := &Identity{ID: ids.GenerateTestID(), DID: "did:lux:arrival"}
	revoked := &RevocationEntry{CredentialID: creds[0].ID, RevokedBy: issuer.ID}

	built, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := built.(*Block)
	blk.Identities = []*Identity{arrival}
	blk.Revocations = []*RevocationEntry{revoked}

	tipBefore, heightBefore := vm.chain.Tip()
	queuedBefore := vm.pending.Len()

	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)

	// Nothing the block wrote is on disk — not even the first credential, which
	// under the old code always landed because its Put ran before any failure
	// could occur.
	for i, c := range creds {
		has, err := db.Database.Has(credentialKey(c.ID))
		require.NoError(t, err)
		require.Falsef(t, has, "credential %d must not survive a block that did not commit", i)
	}
	has, err := db.Database.Has(tipKeyForTest())
	require.NoError(t, err)
	require.False(t, has, "the tip pointer must not survive either")

	// And the chain does not believe the block happened.
	tip, height := vm.chain.Tip()
	require.Equal(t, tipBefore, tip)
	require.Equal(t, heightBefore, height)
	require.NotEqual(t, uint8(3), blk.Status(), "a block that did not commit is not accepted")

	// None of the block's records became visible.
	vm.chain.RLock()
	_, sawIdentity := vm.identities[arrival.ID]
	_, sawRevocation := vm.revocations[revoked.CredentialID]
	status := vm.credentials[creds[0].ID].Status
	vm.chain.RUnlock()
	require.False(t, sawIdentity, "an identity the block introduced must not appear")
	require.False(t, sawRevocation, "nor a revocation it applied")
	require.Equal(t, CredentialActive, status, "nor the status change that came with it")

	// The credentials are still queued, so the work is not lost either.
	require.Equal(t, queuedBefore, vm.pending.Len())
}

// TestTheChainRecoversFromABlockItCouldNotCommit proves the discarded writes
// are really discarded rather than merely unflushed: if they were still
// staged, they would ride along on whatever commits next.
func TestTheChainRecoversFromABlockItCouldNotCommit(t *testing.T) {
	vm, db := newRefusingVM(t)
	defer vm.Shutdown(context.Background())

	subject, _ := vm.CreateIdentity([]byte("subject"), nil)
	issuer, _ := vm.RegisterIssuer("issuer", []byte("issuer-key"), []string{"T"}, 1)

	doomed, err := vm.IssueCredential(issuer.ID, subject.ID, []string{"T"},
		map[string]interface{}{"n": 1}, time.Hour)
	require.NoError(t, err)

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	db.refuse = true
	require.ErrorIs(t, blk.Accept(context.Background()), errRefused)

	// A second block, which does commit.
	db.refuse = false
	vm.pending.Drop([]*Credential{doomed})
	kept, err := vm.IssueCredential(issuer.ID, subject.ID, []string{"T"},
		map[string]interface{}{"n": 2}, time.Hour)
	require.NoError(t, err)

	next, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.NoError(t, next.Accept(context.Background()))

	has, err := db.Database.Has(credentialKey(doomed.ID))
	require.NoError(t, err)
	require.False(t, has, "the abandoned block's credential did not ride along")

	has, err = db.Database.Has(credentialKey(kept.ID))
	require.NoError(t, err)
	require.True(t, has, "the block that committed did land")

	tip, height := vm.chain.Tip()
	require.Equal(t, next.ID(), tip)
	require.Equal(t, uint64(1), height)
}

// TestAnAcceptedBlockIsDurableAndVisible is the other half: what commits is on
// disk and in memory together.
func TestAnAcceptedBlockIsDurableAndVisible(t *testing.T) {
	vm, db := newRefusingVM(t)
	defer vm.Shutdown(context.Background())

	subject, _ := vm.CreateIdentity([]byte("subject"), nil)
	issuer, _ := vm.RegisterIssuer("issuer", []byte("issuer-key"), []string{"T"}, 1)
	cred, err := vm.IssueCredential(issuer.ID, subject.ID, []string{"T"}, nil, time.Hour)
	require.NoError(t, err)

	arrival := &Identity{ID: ids.GenerateTestID(), DID: "did:lux:arrival"}
	built, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := built.(*Block)
	blk.Identities = []*Identity{arrival}

	require.NoError(t, blk.Accept(context.Background()))

	has, err := db.Database.Has(credentialKey(cred.ID))
	require.NoError(t, err)
	require.True(t, has)

	tip, height := vm.chain.Tip()
	require.Equal(t, blk.ID(), tip)
	require.Equal(t, uint64(1), height)
	require.Zero(t, vm.pending.Len(), "the credential it carried is no longer waiting")

	vm.chain.RLock()
	_, sawIdentity := vm.identities[arrival.ID]
	vm.chain.RUnlock()
	require.True(t, sawIdentity)

	// The block is readable back by id and by height.
	got, err := vm.GetBlock(context.Background(), blk.ID())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), got.ID())
}

// TestTheHeightIndexNamesOnlyAcceptedBlocks pins the index to the commit that
// wrote it: it is written with the block, so it cannot name one the chain did
// not accept.
func TestTheHeightIndexNamesOnlyAcceptedBlocks(t *testing.T) {
	vm, db := newRefusingVM(t)
	defer vm.Shutdown(context.Background())

	subject, _ := vm.CreateIdentity([]byte("subject"), nil)
	issuer, _ := vm.RegisterIssuer("issuer", []byte("issuer-key"), []string{"T"}, 1)
	_, err := vm.IssueCredential(issuer.ID, subject.ID, []string{"T"}, nil, time.Hour)
	require.NoError(t, err)

	doomed, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	db.refuse = true
	require.ErrorIs(t, doomed.Accept(context.Background()), errRefused)

	_, err = vm.GetBlockIDAtHeight(context.Background(), 1)
	require.Error(t, err, "a block that did not commit has no height entry")

	db.refuse = false
	require.NoError(t, doomed.Accept(context.Background()))
	at, err := vm.GetBlockIDAtHeight(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, doomed.ID(), at)
}

// tipKeyForTest names the store's tip pointer. The test asserts on the key the
// store actually writes rather than on one it hopes matches.
func tipKeyForTest() []byte { return []byte("chain/tip") }
