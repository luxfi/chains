// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/ids"
)

// rpc drives the JSON-RPC server the node mounts, which is what a client
// actually reaches — a method table over one path, so the exact-path mount the
// node performs is not in the way.
func (h *harness) rpc(t *testing.T, method string, args interface{}) (json.RawMessage, *rpcError) {
	t.Helper()

	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "identity." + method,
		"params":  []interface{}{args},
	})
	require.NoError(t, err)

	handlers, err := h.CreateHandlers(context.Background())
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/v1/chain/chain/rpc", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers["/rpc"].ServeHTTP(rec, r)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return out.Result, out.Error
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *harness) call(t *testing.T, method string, args, reply interface{}) {
	t.Helper()
	raw, rpcErr := h.rpc(t, method, args)
	require.Nil(t, rpcErr, "%s: %v", method, rpcErr)
	if reply != nil {
		require.NoError(t, json.Unmarshal(raw, reply))
	}
}

func (h *harness) callFails(t *testing.T, method string, args interface{}) string {
	t.Helper()
	_, rpcErr := h.rpc(t, method, args)
	require.NotNil(t, rpcErr, "%s was expected to fail", method)
	return rpcErr.Message
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// A mutating call submits a SIGNED record. It does not create one: the caller
// holds the key, so the caller signs. The service used to build the record
// itself from a public key the caller named.
func TestSubmitIdentityOverRPC(t *testing.T) {
	h := newHarness(t)
	p := newParty(t)
	identity := h.identity(t, p, map[string]string{"org": "lux"})

	args := &SubmitIdentityArgs{
		PublicKey: b64(p.pub),
		Signature: b64(identity.Signature),
		Created:   identity.Created.UnixNano(),
		Metadata:  identity.Metadata,
		Fee:       fee.MinTxFeeFloor,
	}

	var reply SubmitReply
	h.call(t, "SubmitIdentity", args, &reply)
	require.Equal(t, identity.ID.String(), reply.ID)

	// A fee below the floor is refused before anything else.
	free := *args
	free.Fee = 0
	require.Contains(t, h.callFails(t, "SubmitIdentity", &free), "fee")

	// Base64 that is not base64.
	bad := *args
	bad.PublicKey = "!!!"
	require.NotEmpty(t, h.callFails(t, "SubmitIdentity", &bad))

	bad = *args
	bad.Signature = "!!!"
	require.NotEmpty(t, h.callFails(t, "SubmitIdentity", &bad))

	// A signature over different content is refused at the door.
	wrong := *args
	wrong.Metadata = map[string]string{"org": "someone else"}
	require.Contains(t, h.callFails(t, "SubmitIdentity", &wrong), "authorize")

	// Consensus is told there is work the moment something is queued.
	_, err := h.WaitForEvent(context.Background())
	require.NoError(t, err)

	// The queued identity becomes state when a block carries it.
	built, err := h.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := built.(*Block)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))

	var got IdentityReply
	h.call(t, "GetIdentity", &IDArgs{ID: identity.ID.String()}, &got)
	require.Equal(t, identity.ID.String(), got.ID)
	require.Equal(t, didPrefix+identity.ID.String(), got.DID)
	require.Equal(t, b64(p.pub), got.PublicKey)
	require.Equal(t, "lux", got.Metadata["org"])

	// And is reachable by the DID it answers to.
	var resolved IdentityReply
	h.call(t, "ResolveIdentity", &ResolveArgs{DID: got.DID}, &resolved)
	require.Equal(t, got, resolved)

	require.Contains(t, h.callFails(t, "ResolveIdentity", &ResolveArgs{DID: "did:web:example"}), "unknown identity")
	require.NotEmpty(t, h.callFails(t, "ResolveIdentity", &ResolveArgs{DID: didPrefix + "nonsense"}))
	require.NotEmpty(t, h.callFails(t, "GetIdentity", &IDArgs{ID: "nonsense"}))
	require.Contains(t, h.callFails(t, "GetIdentity", &IDArgs{ID: ids.GenerateTestID().String()}), "unknown identity")
}

func TestSubmitIssuerAndCredentialOverRPC(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	issuer, subject := newParty(t), newParty(t)
	issuerRecord := h.issuer(t, issuer, "registry")
	subjectRecord := h.identity(t, subject, nil)

	var reply SubmitReply
	h.call(t, "SubmitIssuer", &SubmitIssuerArgs{
		Name:      issuerRecord.Name,
		PublicKey: b64(issuer.pub),
		Signature: b64(issuerRecord.Signature),
		Types:     issuerRecord.Types,
		CreatedAt: issuerRecord.CreatedAt.UnixNano(),
		Fee:       fee.MinTxFeeFloor,
	}, &reply)
	require.Equal(t, issuerRecord.ID.String(), reply.ID)

	h.call(t, "SubmitIdentity", &SubmitIdentityArgs{
		PublicKey: b64(subject.pub),
		Signature: b64(subjectRecord.Signature),
		Created:   subjectRecord.Created.UnixNano(),
		Fee:       fee.MinTxFeeFloor,
	}, &reply)

	h.accept(t)

	// A credential the issuer signed, with the chain's default lifetime. The
	// signer and the chain must reach the SAME expiry from the same issuance,
	// or the signature is over a different credential.
	issuance := time.Now().UnixNano()
	cred := &Credential{
		Type:           []string{"VerifiableCredential"},
		Issuer:         issuerRecord.ID,
		Subject:        subjectRecord.ID,
		IssuanceDate:   time.Unix(0, issuance).UTC(),
		ExpirationDate: h.expiry(issuance, 0),
		Claims:         map[string]interface{}{"degree": "maths"},
	}
	cred.Signature = issuer.sign(t, cred.signable(), h.bind)
	cred.ID = tag("identityvm/credential", cred.signable())

	h.call(t, "SubmitCredential", &SubmitCredentialArgs{
		Type:      cred.Type,
		Issuer:    cred.Issuer.String(),
		Subject:   cred.Subject.String(),
		Issuance:  issuance,
		Claims:    cred.Claims,
		Signature: b64(cred.Signature),
		Fee:       fee.MinTxFeeFloor,
	}, &reply)
	require.Equal(t, cred.ID.String(), reply.ID)
	h.accept(t)

	var got CredentialReply
	h.call(t, "GetCredential", &IDArgs{ID: cred.ID.String()}, &got)
	require.Equal(t, CredentialActive, got.Status)
	require.Equal(t, "maths", got.Claims["degree"])

	var verified VerifyReply
	h.call(t, "VerifyCredential", &IDArgs{ID: cred.ID.String()}, &verified)
	require.True(t, verified.Valid)

	// A refusal is an ANSWER: the caller asked whether a credential is usable.
	h.call(t, "VerifyCredential", &IDArgs{ID: ids.GenerateTestID().String()}, &verified)
	require.False(t, verified.Valid)
	require.Contains(t, verified.Reason, "unknown credential")

	// Revoke it, signed by the subject.
	rev := h.revocation(t, subject, cred.ID, subjectRecord.ID)
	h.call(t, "SubmitRevocation", &SubmitRevocationArgs{
		CredentialID: cred.ID.String(),
		RevokedBy:    subjectRecord.ID.String(),
		RevokedAt:    rev.RevokedAt.UnixNano(),
		Reason:       rev.Reason,
		Signature:    b64(rev.Signature),
		Fee:          fee.MinTxFeeFloor,
	}, &reply)
	h.accept(t)

	h.call(t, "VerifyCredential", &IDArgs{ID: cred.ID.String()}, &verified)
	require.False(t, verified.Valid)
	require.Contains(t, verified.Reason, "revoked")

	var issuerReply IssuerReply
	h.call(t, "GetIssuer", &IDArgs{ID: issuerRecord.ID.String()}, &issuerReply)
	require.Equal(t, "registry", issuerReply.Name)

	var list ListIssuersReply
	h.call(t, "ListIssuers", &EmptyArgs{}, &list)
	require.Len(t, list.Issuers, 1)

	var health HealthReply
	h.call(t, "Health", &EmptyArgs{}, &health)
	require.True(t, health.Healthy)
	require.Equal(t, "1", health.Details["credentials"])

	// A proof artifact describes what the chain holds.
	var proof ProofReply
	h.call(t, "CreateProof", &ProofArgs{ID: cred.ID.String(), Disclosure: b64([]byte("selective"))}, &proof)
	require.Equal(t, cred.ID.String(), proof.CredentialID)
	require.Equal(t, didPrefix+issuerRecord.ID.String(), proof.IssuerDID)
	require.NotEmpty(t, proof.ClaimsCommitment)

	_ = ctx
}

// Every mutating call is gated on the fee, and every id argument is an id.
func TestServiceRefusals(t *testing.T) {
	h := newHarness(t)
	valid := ids.GenerateTestID().String()

	for _, tt := range []struct {
		method string
		args   interface{}
	}{
		{"SubmitIdentity", &SubmitIdentityArgs{}},
		{"SubmitIssuer", &SubmitIssuerArgs{}},
		{"SubmitCredential", &SubmitCredentialArgs{}},
		{"SubmitRevocation", &SubmitRevocationArgs{}},
	} {
		require.Contains(t, h.callFails(t, tt.method, tt.args), "fee", tt.method)
	}

	paid := fee.MinTxFeeFloor
	require.NotEmpty(t, h.callFails(t, "SubmitCredential", &SubmitCredentialArgs{Issuer: "nonsense", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitCredential", &SubmitCredentialArgs{Issuer: valid, Subject: "nonsense", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitCredential", &SubmitCredentialArgs{Issuer: valid, Subject: valid, Signature: "!!!", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitCredential", &SubmitCredentialArgs{Issuer: valid, Subject: valid, Fee: paid}))

	require.NotEmpty(t, h.callFails(t, "SubmitRevocation", &SubmitRevocationArgs{CredentialID: "nonsense", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitRevocation", &SubmitRevocationArgs{CredentialID: valid, RevokedBy: "nonsense", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitRevocation", &SubmitRevocationArgs{CredentialID: valid, RevokedBy: valid, Signature: "!!!", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitRevocation", &SubmitRevocationArgs{CredentialID: valid, RevokedBy: valid, Fee: paid}))

	require.NotEmpty(t, h.callFails(t, "SubmitIssuer", &SubmitIssuerArgs{PublicKey: "!!!", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitIssuer", &SubmitIssuerArgs{Signature: "!!!", Fee: paid}))
	require.NotEmpty(t, h.callFails(t, "SubmitIssuer", &SubmitIssuerArgs{Fee: paid}))

	require.NotEmpty(t, h.callFails(t, "GetCredential", &IDArgs{ID: "nonsense"}))
	require.NotEmpty(t, h.callFails(t, "GetCredential", &IDArgs{ID: valid}))
	require.NotEmpty(t, h.callFails(t, "VerifyCredential", &IDArgs{ID: "nonsense"}))
	require.NotEmpty(t, h.callFails(t, "GetIssuer", &IDArgs{ID: "nonsense"}))
	require.NotEmpty(t, h.callFails(t, "GetIssuer", &IDArgs{ID: valid}))
	require.NotEmpty(t, h.callFails(t, "CreateProof", &ProofArgs{ID: "nonsense"}))
	require.NotEmpty(t, h.callFails(t, "CreateProof", &ProofArgs{ID: valid, Disclosure: "!!!"}))
	require.NotEmpty(t, h.callFails(t, "CreateProof", &ProofArgs{ID: valid}))

	var list ListIssuersReply
	h.call(t, "ListIssuers", &EmptyArgs{}, &list)
	require.Empty(t, list.Issuers)
}

// The credential lifetime the caller names is used; a caller that names none
// gets the chain's default, measured from issuance.
func TestCredentialExpiry(t *testing.T) {
	h := newHarnessWith(t, &Config{CredentialTTL: 60})

	issuance := time.Unix(0, 1_000_000_000).UTC()
	require.Equal(t, issuance.Add(time.Minute), h.expiry(issuance.UnixNano(), 0))

	named := issuance.Add(time.Hour)
	require.Equal(t, named, h.expiry(issuance.UnixNano(), named.UnixNano()))

	// A lifetime the caller made negative used to be added to the clock
	// anyway, producing a credential that was expired the moment it existed —
	// which no block could ever carry, and nothing removed from the queue.
	require.Equal(t, issuance.Add(time.Minute), h.expiry(issuance.UnixNano(), -1))
}

// Issuers come back in id order. Map order is not an order, and an RPC that
// answers differently each call is one a client cannot page through.
func TestIssuersAreOrdered(t *testing.T) {
	h := newHarness(t)

	for i := 0; i < 8; i++ {
		h.accept(t, &Change{Issuer: h.issuer(t, newParty(t), fmt.Sprintf("issuer-%d", i))})
	}

	first := h.Issuers()
	require.Len(t, first, 8)
	for i := 1; i < len(first); i++ {
		require.Negative(t, first[i-1].ID.Compare(first[i].ID))
	}
	for i := 0; i < 16; i++ {
		require.Equal(t, first, h.Issuers())
	}
}
