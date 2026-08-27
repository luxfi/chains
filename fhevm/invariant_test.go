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

// idSizes are the byte-array lengths F legitimately uses for identifiers: a
// selector, an address, and a hash. A byte array of any other length is treated
// as a potential opaque carrier and must not be named like a secret.
var idSizes = map[int]bool{4: true, 20: true, 32: true}

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
		return ft.Elem().Kind() == reflect.Uint8 && !idSizes[ft.Len()]
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

func TestNoSecretFieldsInState(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(CiphertextRecord{}),
		reflect.TypeOf(PermitRecord{}),
		reflect.TypeOf(DecryptRecord{}),
		reflect.TypeOf(EpochRecord{}),
		reflect.TypeOf(Attestation{}),
		reflect.TypeOf(RegisterPayload{}),
		reflect.TypeOf(GrantPayload{}),
		reflect.TypeOf(RequestPayload{}),
		reflect.TypeOf(FulfillPayload{}),
		reflect.TypeOf(AdvancePayload{}),
		reflect.TypeOf(Transaction{}),
		reflect.TypeOf(Block{}),
		reflect.TypeOf(Genesis{}),
		reflect.TypeOf(VM{}), // the VM itself must hold no secret field
	}
	seen := make(map[reflect.Type]bool)
	var bad []string
	for _, r := range roots {
		bad = append(bad, walkType(r, r.Name(), seen)...)
	}
	require.Emptyf(t, bad, "F-Chain state can reach secret material:\n%s", strings.Join(bad, "\n"))
}

// TestWalkerRejectsSecretBearingType is the control for the test above: a walk
// that flags nothing proves nothing unless the walker can be shown to flag
// something. These two shapes are exactly what the invariant forbids.
func TestWalkerRejectsSecretBearingType(t *testing.T) {
	type withNamedSecret struct {
		Handle         [32]byte
		CiphertextBody []byte // a ciphertext body is the one thing F must never hold
	}
	type withShare struct {
		Share []byte
	}
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"named body", reflect.TypeOf(withNamedSecret{})},
		{"named share", reflect.TypeOf(withShare{})},
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
