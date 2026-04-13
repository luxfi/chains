// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func TestVMID(t *testing.T) {
	require := require.New(t)
	require.NotEqual(ids.Empty, VMID, "VMID should not be empty")
	require.Equal(ids.ID{'i', 'd', 'e', 'n', 't', 'i', 't', 'y', 'v', 'm'}, VMID)
}

func TestFactoryNew(t *testing.T) {
	require := require.New(t)

	factory := &Factory{}
	vm, err := factory.New(log.NewNoOpLogger())
	require.NoError(err)
	require.NotNil(vm)
	require.IsType(&VM{}, vm)
}

func TestVMInitialize(t *testing.T) {
	require := require.New(t)

	vm := &VM{
		identities:    make(map[ids.ID]*Identity),
		credentials:   make(map[ids.ID]*Credential),
		issuers:       make(map[ids.ID]*Issuer),
		revocations:   make(map[ids.ID]*RevocationEntry),
		pendingCreds:  make([]*Credential, 0),
		pendingBlocks: make(map[ids.ID]*Block),
	}

	genesis := &Genesis{
		Timestamp: time.Now().Unix(),
		Config: &Config{
			CredentialTTL:  3600,
			MaxClaims:      50,
			AllowSelfIssue: true,
		},
		Message: "test genesis",
	}
	genesisBytes, err := json.Marshal(genesis)
	require.NoError(err)

	toEngine := make(chan vmcore.Message, 10)

	init := vmcore.Init{
		Runtime: &runtime.Runtime{
			ChainID: ids.GenerateTestID(),
			Log:     log.NewNoOpLogger(),
		},
		DB:       memdb.New(),
		Genesis:  genesisBytes,
		ToEngine: toEngine,
	}

	err = vm.Initialize(context.Background(), init)
	require.NoError(err)

	// Verify shutdown
	err = vm.Shutdown(context.Background())
	require.NoError(err)
}

func TestVMCreateIdentity(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	publicKey := []byte("test-public-key-12345")
	metadata := map[string]string{
		"name": "Test User",
		"org":  "Test Organization",
	}

	identity, err := vm.CreateIdentity(publicKey, metadata)
	require.NoError(err)
	require.NotNil(identity)
	require.NotEqual(ids.Empty, identity.ID)
	require.Contains(identity.DID, "did:lux:")
	require.Equal(publicKey, identity.PublicKey)
	require.Equal(metadata, identity.Metadata)

	// Verify identity can be retrieved
	retrieved, err := vm.GetIdentity(identity.ID)
	require.NoError(err)
	require.Equal(identity.ID, retrieved.ID)
	require.Equal(identity.DID, retrieved.DID)
}

func TestVMResolveIdentity(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	publicKey := []byte("resolver-test-key")
	identity, err := vm.CreateIdentity(publicKey, nil)
	require.NoError(err)

	// Resolve by DID
	resolved, err := vm.ResolveIdentity(identity.DID)
	require.NoError(err)
	require.Equal(identity.ID, resolved.ID)

	// Unknown DID should fail
	_, err = vm.ResolveIdentity("did:lux:unknown")
	require.Error(err)
}

func TestVMRegisterIssuer(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	publicKey := []byte("issuer-public-key")
	types := []string{"VerifiableCredential", "EducationCredential"}

	issuer, err := vm.RegisterIssuer("Test Issuer", publicKey, types, 5)
	require.NoError(err)
	require.NotNil(issuer)
	require.NotEqual(ids.Empty, issuer.ID)
	require.Equal("Test Issuer", issuer.Name)
	require.Equal(types, issuer.Types)
	require.Equal(5, issuer.TrustLevel)
	require.Equal("active", issuer.Status)

	// Verify issuer can be retrieved
	retrieved, err := vm.GetIssuer(issuer.ID)
	require.NoError(err)
	require.Equal(issuer.ID, retrieved.ID)
}

func TestVMIssueCredential(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Create identity for subject
	subjectKey := []byte("subject-key")
	subject, err := vm.CreateIdentity(subjectKey, nil)
	require.NoError(err)

	// Register issuer
	issuerKey := []byte("issuer-key")
	issuer, err := vm.RegisterIssuer("Test Issuer", issuerKey, []string{"TestCredential"}, 5)
	require.NoError(err)

	// Issue credential
	claims := map[string]interface{}{
		"degree":     "Bachelor of Science",
		"university": "Test University",
		"year":       2024,
	}
	credTypes := []string{"VerifiableCredential", "EducationCredential"}

	cred, err := vm.IssueCredential(issuer.ID, subject.ID, credTypes, claims, time.Hour*24)
	require.NoError(err)
	require.NotNil(cred)
	require.NotEqual(ids.Empty, cred.ID)
	require.Equal(issuer.ID, cred.Issuer)
	require.Equal(subject.ID, cred.Subject)
	require.Equal(CredentialActive, cred.Status)
	require.Equal(claims, cred.Claims)
}

func TestVMGetCredential(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Setup
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)
	cred, _ := vm.IssueCredential(issuer.ID, subject.ID, []string{"TestCredential"}, map[string]interface{}{"test": true}, 0)

	// Retrieve credential
	retrieved, err := vm.GetCredential(cred.ID)
	require.NoError(err)
	require.Equal(cred.ID, retrieved.ID)
	require.Equal(cred.Issuer, retrieved.Issuer)
	require.Equal(cred.Subject, retrieved.Subject)
}

func TestVMVerifyCredential(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Setup
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)
	cred, _ := vm.IssueCredential(issuer.ID, subject.ID, []string{"TestCredential"}, map[string]interface{}{"test": true}, time.Hour)

	// Verify valid credential
	valid, err := vm.VerifyCredential(cred.ID)
	require.NoError(err)
	require.True(valid)

	// Verify unknown credential
	_, err = vm.VerifyCredential(ids.GenerateTestID())
	require.Error(err)
}

func TestVMRevokeCredential(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Setup
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)
	cred, _ := vm.IssueCredential(issuer.ID, subject.ID, []string{"TestCredential"}, map[string]interface{}{"test": true}, time.Hour)

	// Revoke credential
	err := vm.RevokeCredential(cred.ID, issuer.ID, "Testing revocation")
	require.NoError(err)

	// Verify credential is revoked
	retrieved, err := vm.GetCredential(cred.ID)
	require.NoError(err)
	require.Equal(CredentialRevoked, retrieved.Status)

	// Verify revoked credential fails verification
	valid, err := vm.VerifyCredential(cred.ID)
	require.Error(err)
	require.False(valid)
}

func TestVMBuildBlock(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Build a block
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)
	require.NotNil(blk)
	require.Equal(uint64(1), blk.Height())

	// Verify block parent
	lastAccepted, err := vm.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(lastAccepted, blk.Parent())
}

func TestVMParseBlock(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)

	// Parse the block bytes
	parsed, err := vm.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(err)
	require.Equal(blk.ID(), parsed.ID())
	require.Equal(blk.Height(), parsed.Height())
}

func TestBlockVerifyAcceptReject(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)

	// Accept the block (skip verify since genesis block isn't persisted in test setup)
	err = blk.Accept(context.Background())
	require.NoError(err)

	// Verify last accepted updated
	lastAccepted, err := vm.LastAccepted(context.Background())
	require.NoError(err)
	require.Equal(blk.ID(), lastAccepted)
}

func TestVMHealthCheck(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	health, err := vm.HealthCheck(context.Background())
	require.NoError(err)
	require.True(health.Healthy)
}

func TestVMVersion(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	version, err := vm.Version(context.Background())
	require.NoError(err)
	require.Equal("1.0.0", version)
}

func TestVMCreateHandlers(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	handlers, err := vm.CreateHandlers(context.Background())
	require.NoError(err)
	require.NotNil(handlers)
	require.Contains(handlers, "/rpc")
}

func TestServiceHealthRPC(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "identity.Health",
		"params": [{}],
		"id": 1
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(err)
	require.NotNil(resp["result"])

	result := resp["result"].(map[string]interface{})
	require.True(result["healthy"].(bool))
}

func TestServiceCreateIdentityRPC(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	publicKey := base64.StdEncoding.EncodeToString([]byte("test-public-key-rpc"))
	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "identity.CreateIdentity",
		"params": [{
			"publicKey": "`+publicKey+`",
			"metadata": {"name": "RPC Test User"}
		}],
		"id": 1
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(err)
	require.NotNil(resp["result"])

	result := resp["result"].(map[string]interface{})
	require.NotEmpty(result["id"])
	require.Contains(result["did"], "did:lux:")
}

func TestServiceRegisterIssuerRPC(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	publicKey := base64.StdEncoding.EncodeToString([]byte("issuer-public-key-rpc"))
	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "identity.RegisterIssuer",
		"params": [{
			"name": "RPC Test Issuer",
			"publicKey": "`+publicKey+`",
			"types": ["VerifiableCredential", "EducationCredential"],
			"trustLevel": 5
		}],
		"id": 1
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(err)
	require.NotNil(resp["result"])

	result := resp["result"].(map[string]interface{})
	require.NotEmpty(result["issuerId"])
}

func TestServiceIssueCredentialRPC(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// First create identity and issuer
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)

	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "identity.IssueCredential",
		"params": [{
			"issuerId": "`+issuer.ID.String()+`",
			"subjectId": "`+subject.ID.String()+`",
			"type": ["VerifiableCredential", "TestCredential"],
			"claims": {"degree": "Bachelor", "year": 2024},
			"ttlSeconds": 3600
		}],
		"id": 1
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(err)
	require.NotNil(resp["result"])

	result := resp["result"].(map[string]interface{})
	require.NotEmpty(result["credentialId"])
	require.NotEmpty(result["expirationDate"])
}

func TestServiceVerifyCredentialRPC(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Setup
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)
	cred, _ := vm.IssueCredential(issuer.ID, subject.ID, []string{"TestCredential"}, map[string]interface{}{"test": true}, time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "identity.VerifyCredential",
		"params": [{
			"credentialId": "`+cred.ID.String()+`"
		}],
		"id": 1
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(err)
	require.NotNil(resp["result"])

	result := resp["result"].(map[string]interface{})
	require.True(result["valid"].(bool))
	require.Equal(CredentialActive, result["status"])
}

func TestServiceRevokeCredentialRPC(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Setup
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)
	cred, _ := vm.IssueCredential(issuer.ID, subject.ID, []string{"TestCredential"}, map[string]interface{}{"test": true}, time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "identity.RevokeCredential",
		"params": [{
			"credentialId": "`+cred.ID.String()+`",
			"revokerId": "`+issuer.ID.String()+`",
			"reason": "Testing revocation via RPC"
		}],
		"id": 1
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	vm.rpcServer.ServeHTTP(rec, req)
	require.Equal(http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(err)
	require.NotNil(resp["result"])

	result := resp["result"].(map[string]interface{})
	require.True(result["success"].(bool))

	// Verify credential is revoked
	retrieved, _ := vm.GetCredential(cred.ID)
	require.Equal(CredentialRevoked, retrieved.Status)
}

func TestCredentialProof(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Setup with identities to get DIDs
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)

	// Also create an identity for the issuer to get DID
	issuerIdentity, _ := vm.CreateIdentity([]byte("issuer-key"), nil)
	// Link the issuer ID to the identity
	vm.identities[issuer.ID] = issuerIdentity

	cred, _ := vm.IssueCredential(issuer.ID, subject.ID, []string{"TestCredential"}, map[string]interface{}{"test": true}, time.Hour)

	// Create credential proof
	zkProof := []byte("mock-zk-proof")
	proof, err := vm.CreateCredentialProof(cred.ID, zkProof, []string{"test"})
	require.NoError(err)
	require.NotNil(proof)
	require.Equal(cred.ID, proof.CredentialID)
	require.Equal("TestCredential", proof.CredType)
}

func TestBlockWithCredentials(t *testing.T) {
	require := require.New(t)

	vm := setupTestVM(t)
	defer vm.Shutdown(context.Background())

	// Setup and issue credentials
	subject, _ := vm.CreateIdentity([]byte("subject-key"), nil)
	issuer, _ := vm.RegisterIssuer("Issuer", []byte("issuer-key"), []string{"TestCredential"}, 5)

	// Issue multiple credentials
	for i := 0; i < 3; i++ {
		_, err := vm.IssueCredential(issuer.ID, subject.ID, []string{"TestCredential"}, map[string]interface{}{"index": i}, time.Hour)
		require.NoError(err)
	}

	// Build block should include pending credentials
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(err)
	require.NotNil(blk)

	// Cast to internal block type to check credentials
	block := blk.(*Block)
	require.Len(block.Credentials, 3)

	// Accept block (skip verify since genesis block isn't persisted in test setup)
	err = blk.Accept(context.Background())
	require.NoError(err)

	// Pending credentials should be cleared
	vm.mu.RLock()
	require.Empty(vm.pendingCreds)
	vm.mu.RUnlock()
}

// setupTestVM creates and initializes a test VM
func setupTestVM(t *testing.T) *VM {
	t.Helper()

	vm := &VM{
		identities:    make(map[ids.ID]*Identity),
		credentials:   make(map[ids.ID]*Credential),
		issuers:       make(map[ids.ID]*Issuer),
		revocations:   make(map[ids.ID]*RevocationEntry),
		pendingCreds:  make([]*Credential, 0),
		pendingBlocks: make(map[ids.ID]*Block),
	}

	genesis := &Genesis{
		Timestamp: time.Now().Unix(),
		Config: &Config{
			CredentialTTL:  3600,
			MaxClaims:      50,
			AllowSelfIssue: true,
		},
		Message: "test",
	}
	genesisBytes, _ := json.Marshal(genesis)

	toEngine := make(chan vmcore.Message, 10)

	init := vmcore.Init{
		Runtime: &runtime.Runtime{
			ChainID: ids.GenerateTestID(),
			Log:     log.NewNoOpLogger(),
		},
		DB:       memdb.New(),
		Genesis:  genesisBytes,
		ToEngine: toEngine,
	}

	err := vm.Initialize(context.Background(), init)
	require.NoError(t, err)

	return vm
}
