// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// harness_test.go — the fixtures the state-transition tests are built on.
//
// # Why a plain secp256k1 key stands in for a threshold key
//
// The output of a CGGMP21 ceremony is an ordinary secp256k1 ECDSA signature
// under an ordinary secp256k1 public key. That is the entire point of using
// threshold ECDSA for bridge custody: an external chain's ecrecover cannot tell
// a threshold signature from a single-key one, and neither can Block.Verify,
// which calls the same secp256k1.VerifySignature.
//
// So a fixture that holds the group secret in one place produces artifacts that
// are byte-indistinguishable from real ceremony output, and lets the block
// rules be tested against thousands of cases in milliseconds instead of one
// case per DKG. What the fixture does NOT prove is that the ceremony produces
// such a signature — that is bridge_transport_test.go, which runs the real
// distributed key generation and the real signing rounds across five VMs over
// the real gossip transport, and is the reason this shortcut is a shortcut and
// not a stub.
//
// The fixture holding the whole secret is also what lets these tests forge: a
// test that can sign anything can produce the artifact an ATTACKER would need,
// which is how "the block rules refuse it" becomes a claim about an adversary
// rather than about a typo.

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/quorum"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	vmcore "github.com/luxfi/vm"
)

// custody is a registered custody key whose secret this test holds, so a test
// can produce the artifact a ceremony would have produced — or the artifact an
// attacker would need.
type custody struct {
	rec *KeyRecord
	sec *ecdsa.PrivateKey
}

// newCustody builds a key record under policy with n canonical participants,
// derived deterministically from seed so a test's expectations are stable.
func newCustody(t *testing.T, keyID string, policy quorum.Policy, seed byte) *custody {
	t.Helper()

	var d [32]byte
	d[31] = seed
	d[0] = 1 // keep the scalar well inside the curve order
	sec, err := luxcrypto.ToECDSA(d[:])
	require.NoError(t, err)

	pub := secp256k1.CompressPubkey(sec.PublicKey.X, sec.PublicKey.Y)
	require.Len(t, pub, 33)
	addr := publicKeyToAddress(pub)
	require.Len(t, addr, 20)

	return &custody{
		rec: &KeyRecord{
			KeyID:          keyID,
			Kind:           KindCGGMP21,
			Policy:         policy,
			Participants:   parties(policy.N),
			GroupPublicKey: pub,
			Address:        addr,
		},
		sec: sec,
	}
}

// sign produces the 65-byte r‖s‖v artifact over a 32-byte digest — the same
// encoding thresholdSign returns and the same one verifyGroupSignature checks.
func (c *custody) sign(t *testing.T, digest []byte) []byte {
	t.Helper()
	sig, err := luxcrypto.Sign(digest, c.sec)
	require.NoError(t, err)
	require.Len(t, sig, 65)
	return sig
}

// keygenOp is the operation that registers this key: the proof of possession
// over its own commit digest, under the derived ceremony id.
func (c *custody) keygenOp(t *testing.T) *Operation {
	t.Helper()
	commit := KeyCommitDigest(c.rec)
	return &Operation{
		Type:       OpTypeKeygen,
		CeremonyID: keygenCeremonyID(c.rec.KeyID, c.rec.Policy, c.rec.Participants),
		KeyID:      c.rec.KeyID,
		Digest:     commit[:],
		Artifact:   c.sign(t, commit[:]),
		Signers:    c.rec.Participants,
		Key:        c.rec,
	}
}

// signOpOver is a completed signing ceremony over digest by the quorum this
// task selects, with the ceremony id that task derives.
func (c *custody) signOpOver(t *testing.T, digest []byte) *Operation {
	t.Helper()
	signers := quorumFor(c.rec, digest)
	return &Operation{
		Type:       OpTypeSign,
		CeremonyID: ceremonyID(c.rec.KeyID, digest, signers),
		KeyID:      c.rec.KeyID,
		Digest:     digest,
		Artifact:   c.sign(t, digest),
		Signers:    signers,
	}
}

// parties returns n canonical party ids. They are not node ids — nothing in the
// block rules parses them as one; resolveCommittee is the only place that does
// and it is the transport's business, not consensus'.
func parties(n int) []party.ID {
	out := make([]party.ID, n)
	for i := range out {
		out[i] = party.ID([]byte{'p', byte('a' + i)})
	}
	return out
}

// digestOf is a 32-byte message digest, distinct per seed.
func digestOf(seed byte) []byte {
	d := make([]byte, 32)
	d[0] = seed
	d[31] = seed ^ 0xff
	return d
}

// newVM opens a VM on a fresh in-memory database, initialized exactly as the
// node initializes it. No field is reached into afterwards: a fixture that
// hand-assembled a VM would be testing a state the production path cannot
// produce.
func newVM(t *testing.T) *VM {
	t.Helper()
	vm := newVMOn(t, memdb.New(), nil)
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// newVMOn opens a VM over a caller-supplied database and config, for the tests
// that need to restart a node on the state it left or to fail a write.
func newVMOn(t *testing.T, db database.Database, config []byte) *VM {
	t.Helper()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime: &runtime.Runtime{
			NodeID:  ids.GenerateTestNodeID(),
			ChainID: ids.GenerateTestID(),
		},
		DB:       db,
		Config:   config,
		Log:      log.NewNoOpLogger(),
		ToEngine: make(chan vmcore.Message, 1),
	}))
	return vm
}

// register puts a custody key into consensus state through the block path, so
// every test that needs a registered key gets one that a block actually
// registered rather than one written behind the state machine's back.
func (c *custody) register(t *testing.T, vm *VM) *Block {
	t.Helper()
	blk := blockOver(t, vm, c.keygenOp(t))
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
	return blk
}

// hold gives this node the key's own share, which is what makes it a
// participant for crossCheckOwnShare. It is set directly because the only
// honest way to obtain one is to run the DKG, and what is under test here is
// what the cross-check does with a share, not how one is produced.
func (c *custody) hold(vm *VM, share *heldShare) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.shares[c.rec.KeyID] = share
}

// -----------------------------------------------------------------------------
// One real key share, generated once for the whole package
// -----------------------------------------------------------------------------

var (
	realOnce   sync.Once
	realCfgs   map[party.ID]*cmpconfig.Config
	realRaw    []byte
	realPub    []byte
	realDegree int
	realErr    error
)

// realShare returns the node-private encoding of a share a genuine two-party
// DKG produced, plus the group key and degree it belongs to.
//
// The share store round-trips through the threshold library's own encoding, and
// that encoding carries a Paillier secret whose primes are validated on the way
// back in. So a hand-assembled config cannot be stored and re-read, and the only
// honest way to test what a restarted node does with a stored share is to store
// one a ceremony produced. It is generated once — key generation is the
// expensive part of this protocol, and the tests below differ in what they do
// with the share, not in which share it is.
func realShare(t *testing.T) (raw, groupPub []byte, degree int) {
	t.Helper()
	realOnce.Do(func() {
		const t0 = 1 // polynomial degree: any 2 of the 2 parties reconstruct
		ids := []party.ID{"pa", "pb"}
		pl := pool.NewPool(2)
		defer pl.TearDown()

		net, routers := newMeshRouters(ids)
		defer net.close()

		var wg sync.WaitGroup
		cfgs := make([]*cmpconfig.Config, len(ids))
		errs := make([]error, len(ids))
		for i, id := range ids {
			wg.Add(1)
			go func(i int, id party.ID) {
				defer wg.Done()
				pe := NewProtocolExecutor(pl, log.NewTestLogger(log.ErrorLevel))
				cfgs[i], errs[i] = pe.RunCMPKeygen(context.Background(), "fixture", id, ids, t0, routers[id])
			}(i, id)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				realErr = err
				return
			}
		}
		realCfgs = make(map[party.ID]*cmpconfig.Config, len(ids))
		for i, id := range ids {
			realCfgs[id] = cfgs[i]
		}
		if realRaw, realErr = cfgs[0].MarshalBinary(); realErr != nil {
			return
		}
		realPub, realErr = cfgs[0].PublicPoint().MarshalBinary()
		realDegree = cfgs[0].Threshold
	})
	require.NoError(t, realErr)
	return realRaw, realPub, realDegree
}

// custodyFor builds a registry entry for a group key generated elsewhere, so a
// stored share and the record it is filed under agree — or, by choosing a
// different policy, disagree in exactly one way.
func custodyFor(t *testing.T, keyID string, policy quorum.Policy, groupPub []byte) *KeyRecord {
	t.Helper()
	addr := publicKeyToAddress(groupPub)
	require.Len(t, addr, 20)
	return &KeyRecord{
		KeyID:          keyID,
		Kind:           KindCGGMP21,
		Policy:         policy,
		Participants:   parties(policy.N),
		GroupPublicKey: groupPub,
		Address:        addr,
	}
}

// realConfigs returns every party's share of the package's one real key, so a
// signing ceremony can actually be run across the committee that generated it.
func realConfigs(t *testing.T) map[party.ID]*cmpconfig.Config {
	t.Helper()
	realShare(t)
	return realCfgs
}
