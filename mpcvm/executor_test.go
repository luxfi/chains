// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// executor_test.go — the one place that knows the threshold library exists.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
)

func newExecutor(t *testing.T) *ProtocolExecutor {
	t.Helper()
	pl := pool.NewPool(2)
	t.Cleanup(pl.TearDown)
	return NewProtocolExecutor(pl, log.NewTestLogger(log.ErrorLevel))
}

// A ceremony is registered while it runs and gone when it ends, so a leaked
// handler — one whose goroutines are still holding a worker pool and a party's
// round state — is visible rather than silent.
func TestACeremonyIsTrackedWhileItRunsAndNotAfter(t *testing.T) {
	pe := newExecutor(t)
	require.Zero(t, pe.Live())

	start := cmp.Keygen(curve.Secp256k1{}, "pa", []party.ID{"pa", "pb"}, 1, pe.pool)
	handler, err := pe.CreateHandler(ctx(), "mpc/one", start)
	require.NoError(t, err)
	require.NotNil(t, handler)
	require.Equal(t, 1, pe.Live())

	pe.RemoveHandler("mpc/one")
	require.Zero(t, pe.Live())

	pe.RemoveHandler("mpc/one")
	require.Zero(t, pe.Live(), "tearing down a ceremony twice is not an error")
	pe.RemoveHandler("mpc/never-existed")
}

// A ceremony that cannot be started is reported as such rather than registered
// as a ceremony that is running.
func TestACeremonyThatCannotStartIsNotTracked(t *testing.T) {
	pe := newExecutor(t)
	// A start function for a party that is not in its own participant set: the
	// library refuses before the first round.
	start := cmp.Keygen(curve.Secp256k1{}, "stranger", []party.ID{"pa", "pb"}, 1, pe.pool)
	_, err := pe.CreateHandler(ctx(), "mpc/doomed", start)
	require.ErrorContains(t, err, "create ceremony handler")
	require.Zero(t, pe.Live())
}

// A ceremony whose transport fails is reported as a transport failure, named
// with the ceremony, rather than as a protocol failure or a timeout.
func TestATransportFailureIsAttributedToTheTransport(t *testing.T) {
	pe := newExecutor(t)
	ctxT, cancel := context.WithTimeout(ctx(), 30*time.Second)
	defer cancel()

	start := cmp.Keygen(curve.Secp256k1{}, "pa", []party.ID{"pa", "pb"}, 1, pe.pool)
	_, err := runProtocol[*ecdsa.Signature](ctxT, pe, "mpc/broken", start, &brokenRouter{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mpc/broken")
}

// A ceremony that produces something other than what the caller asked for is an
// error naming both types, not a zero value the caller reads as success.
func TestAnUnexpectedCeremonyResultIsNamed(t *testing.T) {
	pe := newExecutor(t)
	ctxT, cancel := context.WithTimeout(ctx(), 60*time.Second)
	defer cancel()

	ids := []party.ID{"pa", "pb"}
	net, routers := newMeshRouters(ids)
	defer net.close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		other := NewProtocolExecutor(pe.pool, log.NewTestLogger(log.ErrorLevel))
		start := cmp.Keygen(curve.Secp256k1{}, "pb", ids, 1, other.pool)
		_, _ = runProtocol[*ecdsa.Signature](ctxT, other, "mpc/typed", start, routers["pb"])
	}()

	start := cmp.Keygen(curve.Secp256k1{}, "pa", ids, 1, pe.pool)
	_, err := runProtocol[*ecdsa.Signature](ctxT, pe, "mpc/typed", start, routers["pa"])
	require.ErrorContains(t, err, "produced *config.Config, want *ecdsa.Signature")
	<-done
}

// A ceremony whose context is already dead does not run.
func TestACeremonyWithNoTimeLeftDoesNotRun(t *testing.T) {
	pe := newExecutor(t)
	dead, cancel := context.WithCancel(ctx())
	cancel()

	net, routers := newMeshRouters([]party.ID{"pa", "pb"})
	defer net.close()
	_, err := pe.RunCMPKeygen(dead, "mpc/dead", "pa", []party.ID{"pa", "pb"}, 1, routers["pa"])
	require.Error(t, err)
}

// -----------------------------------------------------------------------------
// The signature encoding
// -----------------------------------------------------------------------------

// The one encoding M-Chain stores and every verifier reads: r(32) ‖ s(32) ‖
// v(1), low-S normalised, so it verifies under luxfi/crypto and under an
// on-chain ecrecover without either side re-deriving anything.
func TestASignatureIsStoredInTheEncodingEveryVerifierReads(t *testing.T) {
	_, groupPub, degree := realShare(t)
	require.Equal(t, 1, degree)
	require.Len(t, groupPub, 33)

	pe := newExecutor(t)
	ctxT, cancel := context.WithTimeout(ctx(), 120*time.Second)
	defer cancel()

	sig := signWithRealShare(t, ctxT, pe, digestOf(1))
	require.Len(t, sig.R, 32)
	require.Len(t, sig.S, 32)

	raw := append(append([]byte(nil), sig.R...), sig.S...)
	require.True(t, secp256k1.VerifySignature(groupPub, digestOf(1), raw),
		"a signature the executor produced must verify under the key the DKG produced")
	require.NoError(t, verifyGroupSignature(groupPub,
		digestOf(1), append(raw, sig.V)),
		"and under the same check a block applies")
}

// A ceremony that produced nothing is reported as nothing, not dereferenced.
// The type assertion in runProtocol admits a typed nil, and SigEthereum has a
// value receiver, so encoding one would fault the VM rather than fail a
// ceremony.
func TestACeremonyThatProducedNothingIsNamedNotDereferenced(t *testing.T) {
	_, err := ecdsaSigToWrapper(nil)
	require.ErrorContains(t, err, "nil signature")
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// brokenRouter refuses to carry anything, which is how a ceremony fails when
// the network under it does.
type brokenRouter struct{}

func (brokenRouter) Send(*protocol.Message) error      { return errors.New("carrier pigeon lost") }
func (brokenRouter) Receive() <-chan *protocol.Message { return make(chan *protocol.Message) }

// signWithRealShare runs a signing ceremony across the committee that generated
// the package's one real key, and returns the signature every signer derived.
func signWithRealShare(t *testing.T, c context.Context, pe *ProtocolExecutor, digest []byte) *ECDSASignature {
	t.Helper()
	cfgs := realConfigs(t)

	signers := make([]party.ID, 0, len(cfgs))
	for id := range cfgs {
		signers = append(signers, id)
	}
	signers = canonicalParties(signers)

	net, routers := newMeshRouters(signers)
	defer net.close()

	sigs := make([]*ECDSASignature, len(signers))
	errs := make([]error, len(signers))
	var wg sync.WaitGroup
	for i, id := range signers {
		wg.Add(1)
		go func(i int, id party.ID) {
			defer wg.Done()
			exec := NewProtocolExecutor(pe.pool, log.NewTestLogger(log.ErrorLevel))
			sigs[i], errs[i] = exec.RunCMPSign(c, "mpc/sign", cfgs[id], signers, digest, routers[id])
		}(i, id)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "signer %s", signers[i])
	}
	for i := 1; i < len(sigs); i++ {
		require.Equal(t, sigs[0].R, sigs[i].R, "every honest signer derives the identical signature")
		require.Equal(t, sigs[0].S, sigs[i].S)
	}
	return sigs[0]
}

// A signing ceremony that cannot start is reported as a failed ceremony, not as
// a signature that failed to encode.
func TestASigningCeremonyThatCannotStartIsNamed(t *testing.T) {
	pe := newExecutor(t)
	dead, cancel := context.WithCancel(ctx())
	cancel()

	cfgs := realConfigs(t)
	signers := make([]party.ID, 0, len(cfgs))
	for id := range cfgs {
		signers = append(signers, id)
	}
	signers = canonicalParties(signers)

	net, routers := newMeshRouters(signers)
	defer net.close()

	_, err := pe.RunCMPSign(dead, "mpc/dead-sign", cfgs[signers[0]], signers, digestOf(1), routers[signers[0]])
	require.ErrorContains(t, err, "mpc/dead-sign")

	// And a ceremony whose start function refuses is reported before any round.
	_, err = pe.RunCMPKeygen(ctx(), "mpc/no-self", "stranger", signers, 1, routers[signers[0]])
	require.ErrorContains(t, err, "create ceremony handler")
}
