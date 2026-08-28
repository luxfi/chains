// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// F-Chain's defining invariant: it coordinates confidential compute without
// ever holding the confidential part. No ciphertext body, no plaintext, no FHE
// secret key, no decryption share. These tests prove that STRUCTURALLY, two
// ways:
//
//  1. TestNoSecretFieldsInState walks the full type graph of everything F
//     persists or holds and fails if any reachable field could carry one of
//     those things — a private/secret key type, or a byte-bearing field named
//     like a body, a plaintext, or a share.
//
//  2. TestNoSecretProducingCalls scans the package's own source and fails if it
//     names any identifier by which F could generate a key, produce a share,
//     combine shares, or decrypt. The same scan forbids the FHE runtime's
//     Registry, whose writes are stamped with the wall clock and therefore
//     cannot back a state root — the reason F owns its persistence.

// secretTokens are substrings that, on a byte-bearing field, would indicate F
// is holding something it must not. "share" is included but only flags
// BYTE-bearing fields, so an integer count named …Shares is not flagged.
var secretTokens = []string{
	"private", "secret", "mnemonic", "seed", "share", "privkey",
	"plaintext", "cleartext", "body", "blob",
}

// isByteBearing reports whether a field can carry opaque bytes. Fixed-size byte
// arrays count: being id-sized is not being an id, and a scalar share is
// exactly 32 bytes.
func isByteBearing(ft reflect.Type) bool {
	switch ft.Kind() {
	case reflect.String:
		return true
	case reflect.Slice:
		e := ft.Elem()
		if e.Kind() == reflect.Uint8 { // []byte
			return true
		}
		if e.Kind() == reflect.Slice && e.Elem().Kind() == reflect.Uint8 { // [][]byte
			return true
		}
		return false
	case reflect.Array:
		return ft.Elem().Kind() == reflect.Uint8
	}
	return false
}

// walkType reports every violation reachable from typ. It returns them rather
// than failing, so the walker itself can be shown to reject a bad type.
func walkType(typ reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if typ == nil || seen[typ] {
		return nil
	}
	seen[typ] = true

	var bad []string
	switch typ.Kind() {
	case reflect.Interface:
		// A field typed as an interface holds whatever it is handed, which is
		// the opposite of an enumerable record.
		bad = append(bad, fmt.Sprintf("%s is an interface and can hold anything", path))
	case reflect.Ptr, reflect.Slice, reflect.Array:
		bad = append(bad, walkType(typ.Elem(), path, seen)...)
	case reflect.Map:
		bad = append(bad, walkType(typ.Key(), path, seen)...)
		bad = append(bad, walkType(typ.Elem(), path, seen)...)
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fp := path + "." + f.Name
			tn := f.Type.String()
			if strings.Contains(tn, "PrivateKey") || strings.Contains(tn, "SecretKey") {
				bad = append(bad, fmt.Sprintf("%s has secret-bearing type %s", fp, tn))
			}
			if isByteBearing(f.Type) {
				lower := strings.ToLower(f.Name)
				for _, tok := range secretTokens {
					if strings.Contains(lower, tok) {
						bad = append(bad, fmt.Sprintf("byte-bearing field %s (%s) is named like a secret (%q)", fp, tn, tok))
					}
				}
			}
			bad = append(bad, walkType(f.Type, fp, seen)...)
		}
	}
	return bad
}

// persistedTypes is exactly what F writes to its database. putCiphertext,
// putPermit, putDecrypt and putEpoch are the only writers of a record, and
// these are the four types they write.
func persistedTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(CiphertextRecord{}),
		reflect.TypeOf(PermitRecord{}),
		reflect.TypeOf(DecryptRecord{}),
		reflect.TypeOf(EpochRecord{}),
	}
}

// persistedSchema pins every field F persists, flattened through the embedded
// runtime types, with the type of each.
//
// The walk below is a name DENYLIST, and a denylist cannot be complete — a
// field called Material carries exactly as much as one called Secret. This pin
// is the check that actually holds: a field added, removed or retyped anywhere
// in a persisted record fails here until someone writes it down, at which point
// the question "should F be storing that?" is asked deliberately rather than
// answered by omission.
var persistedSchema = map[string][]string{
	"CiphertextRecord": {
		"Handle [32]uint8", "Owner [20]uint8", "Type uint8", "Level int",
		"Epoch uint64", "RegisteredAt int64", "Size uint32", "ChainID ids.ID",
		"Scheme string", "Digest [32]uint8",
	},
	"PermitRecord": {
		"PermitID [32]uint8", "Handle [32]uint8", "Grantee [20]uint8",
		"Grantor [20]uint8", "Operations uint32", "Expiry int64",
		"CreatedAt int64", "Attestation []uint8", "ChainID ids.ID",
		"Status string",
	},
	"DecryptRecord": {
		"RequestID [32]uint8", "CiphertextHandle [32]uint8", "Requester [20]uint8",
		"Callback [20]uint8", "CallbackSelector [4]uint8", "SourceChain ids.ID",
		"Epoch uint64", "Nonce uint64", "Expiry int64", "Status fhe.RequestStatus",
		"CreatedAt int64", "CompletedAt int64", "ResultHandle [32]uint8",
		"Error string", "PermitID [32]uint8", "Attestations []fhevm.Attestation",
	},
	"EpochRecord": {
		"Epoch uint64", "StartTime int64", "EndTime int64",
		"Committee []fhe.CommitteeMember", "Threshold int", "PublicKey []uint8",
		"Status fhe.EpochStatus", "Attestations []fhevm.Attestation",
	},
}

// flatten lists a struct's fields, descending through embedded structs so an
// embedded runtime type cannot hide a field behind its own name.
func flatten(typ reflect.Type) []string {
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			out = append(out, flatten(f.Type)...)
			continue
		}
		out = append(out, f.Name+" "+f.Type.String())
	}
	return out
}

func TestPersistedSchemaIsPinned(t *testing.T) {
	require.Len(t, persistedSchema, len(persistedTypes()))
	for _, typ := range persistedTypes() {
		want, ok := persistedSchema[typ.Name()]
		require.Truef(t, ok, "%s is persisted but not pinned", typ.Name())
		require.Equalf(t, want, flatten(typ),
			"%s no longer stores what it was written down as storing.\n"+
				"If the change is intended, update persistedSchema — and while you are\n"+
				"there, answer the question it exists to force: should F be storing that?",
			typ.Name())
	}
}

// TestNoSecretFieldsInState walks everything F SERIALIZES — what it persists,
// what it accepts on the wire, and what it reads from genesis. Those are the
// shapes that must be enumerable: each field is a coordinate F chose to keep,
// and none of them may be, or hold, the encrypted part.
func TestNoSecretFieldsInState(t *testing.T) {
	roots := append(persistedTypes(),
		reflect.TypeOf(Attestation{}),
		reflect.TypeOf(RegisterPayload{}),
		reflect.TypeOf(GrantPayload{}),
		reflect.TypeOf(RevokePayload{}),
		reflect.TypeOf(RequestPayload{}),
		reflect.TypeOf(FulfillPayload{}),
		reflect.TypeOf(AdvancePayload{}),
		reflect.TypeOf(Transaction{}),
		reflect.TypeOf(Genesis{}),
	)
	seen := make(map[reflect.Type]bool)
	var bad []string
	for _, r := range roots {
		bad = append(bad, walkType(r, r.Name(), seen)...)
	}
	require.Emptyf(t, bad, "F-Chain state can reach secret material:\n%s", strings.Join(bad, "\n"))
}

// TestBlockHoldsOnlyItsHeaderAndItsTransactions pins Block by hand rather than
// walking it. A Block carries a back-pointer to the VM, so a walk of its type
// graph reaches every piece of runtime plumbing the VM holds — loggers,
// databases, an RPC server — and says nothing about the block. What matters
// about a Block is that it holds a header, its transactions, and nothing else.
func TestBlockHoldsOnlyItsHeaderAndItsTransactions(t *testing.T) {
	require.Equal(t, []string{
		"id ids.ID",
		"parentID ids.ID",
		"height uint64",
		"timestamp time.Time",
		"transactions []*fhevm.Transaction",
		"vm *fhevm.VM",
	}, flatten(reflect.TypeOf(Block{})))
}

// TestWalkerRejectsSecretBearingType is the control for the test above: a walk
// that flags nothing proves nothing unless the walker can be shown to flag
// something.
func TestWalkerRejectsSecretBearingType(t *testing.T) {
	type withNamedSecret struct {
		Handle         [32]byte
		CiphertextBody []byte // a ciphertext body is the one thing F must never hold
	}
	type withShare struct {
		Share []byte
	}
	type withIdSizedShare struct {
		SecretShare [32]byte // a scalar share is exactly 32 bytes
	}
	type withInterface struct {
		Extra any // holds whatever it is handed
	}
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"named body", reflect.TypeOf(withNamedSecret{})},
		{"named share", reflect.TypeOf(withShare{})},
		{"id-sized share", reflect.TypeOf(withIdSizedShare{})},
		{"interface field", reflect.TypeOf(withInterface{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotEmpty(t, walkType(tc.typ, tc.name, map[reflect.Type]bool{}),
				"the walker must reject this shape, or it proves nothing about the real types")
		})
	}
}

func TestNoSecretProducingCalls(t *testing.T) {
	// Forbidden IDENTIFIERS: any function or type by which F could generate a
	// key, produce or combine shares, decrypt, or persist through the FHE
	// runtime's wall-clock Registry. The check runs over the AST (identifiers
	// only), so a doc comment that NAMES one of these to explain the invariant
	// is not flagged — only real code is.
	exact := map[string]string{
		"GenerateKey":   "key generation",
		"NewSecretKey":  "secret key construction",
		"Decapsulate":   "KEM decapsulation uses the private key",
		"Encapsulate":   "F performs no cryptographic compute",
		"Sign":          "signing uses a private key; F only verifies",
		"Zeroize":       "only needed if secret material were held",
		"Reconstruct":   "share reconstruction",
		"CombineShares": "share combination",
		"RecoverSecret": "secret recovery",

		// The FHE runtime's secret-bearing entry points. F wraps the runtime's
		// vocabulary, never its key machinery.
		"SetSecretKey":               "would put an FHE secret key in the VM",
		"GenerateShare":              "would make this node a share producer",
		"ContributeShare":            "would make this node a share consumer",
		"InitiateDecryption":         "decryption happens off-chain, on the committee",
		"NewThresholdDecryptor":      "decryption happens off-chain, on the committee",
		"NewFHEDecryptionService":    "decryption happens off-chain, on the committee",
		"NewThresholdFHEIntegration": "F holds no evaluation session",

		// The runtime's Registry stamps time.Now(), so its writes cannot back a
		// state root: two validators replaying one block would diverge. F owns
		// its persistence for exactly this reason, and must keep owning it.
		"NewRegistry":                  "the runtime Registry is wall-clock stamped and cannot back a state root",
		"NewInMemoryCiphertextStorage": "F stores no ciphertext body",
		"NewRelayer":                   "relaying is an off-chain concern",
	}
	// markers: substrings catching any private/secret key type, plus plaintext.
	// "PublicKey" and "VerifySignature" contain none of them, so the public
	// path is unaffected.
	markers := []string{"PrivateKey", "SecretKey", "Plaintext"}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		require.NoError(t, err)

		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if why, forbidden := exact[id.Name]; forbidden {
				t.Errorf("%s references %q at %s — %s", name, id.Name, fset.Position(id.Pos()), why)
			}
			for _, m := range markers {
				if strings.Contains(id.Name, m) {
					t.Errorf("%s references %q (marker %q) at %s", name, id.Name, m, fset.Position(id.Pos()))
				}
			}
			return true
		})
		scanned++
	}
	require.Greater(t, scanned, 5, "expected to scan the fhevm package sources")
}

// TestVMExposesNoSecretAccessor asserts the VM's public method set offers no
// way to ask it for something it must not have. Decrypt is present and named
// for what it returns — the RECORD of a decryption request — so the check is
// against the things a caller could mistake for the plaintext itself.
func TestVMExposesNoSecretAccessor(t *testing.T) {
	bad := []string{"PrivateKey", "SecretKey", "Plaintext", "Share", "Seed", "Body", "Reconstruct"}
	vt := reflect.TypeOf(&VM{})
	for i := 0; i < vt.NumMethod(); i++ {
		m := vt.Method(i).Name
		for _, b := range bad {
			require.Falsef(t, strings.Contains(m, b),
				"VM exposes method %q which suggests access to material it does not hold", m)
		}
	}
}

// TestServiceExposesNoDecryptEndpoint asserts the RPC surface has no method
// that performs a decryption or hands back a plaintext. Decryption is a
// consensus transaction answered by the committee, never a synchronous call.
func TestServiceExposesNoDecryptEndpoint(t *testing.T) {
	st := reflect.TypeOf(&Service{})
	for i := 0; i < st.NumMethod(); i++ {
		m := st.Method(i).Name
		for _, b := range []string{"Plaintext", "Reencrypt", "Evaluate", "PrivateKey", "SecretKey"} {
			require.Falsef(t, strings.Contains(m, b), "Service exposes %q", m)
		}
	}
	// The one Decrypt-named method is a read of the request record.
	_, ok := st.MethodByName("GetDecrypt")
	require.True(t, ok)
}
