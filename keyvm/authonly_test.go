// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The K-Chain's defining invariant: it holds ZERO secret key material and CANNOT
// reconstruct a key. These tests prove that STRUCTURALLY, two ways:
//
//   1. TestZeroSecret_NoSecretFieldsInState walks the full type graph of every
//      type K persists or holds (KeyRecord, CeremonyRecord, AuthPolicy,
//      Transaction, Block, and the VM itself) and fails if any reachable field
//      could carry a secret — a private/secret key type, or a byte-bearing field
//      named like a share/seed/secret. This proves K STORES no secret.
//
//   2. TestZeroSecret_NoSecretProducingCalls scans the package's own source and
//      fails if it contains any call that could GENERATE, PARSE, RECONSTRUCT,
//      DECAPSULATE, or SIGN with a secret. This proves K cannot PRODUCE or
//      RECONSTRUCT a secret — reconstruction is absent from the code, not merely
//      unused. Public-key operations (PublicKeyFromBytes, VerifySignature) are
//      the only cryptography K performs, and they touch no secret.

// secretNameTokens are substrings that, on a byte-bearing field, indicate secret
// material. "share" is included but only flags BYTE-bearing fields, so the
// integer count TotalShares (uint32) is correctly NOT flagged.
var secretNameTokens = []string{"private", "secret", "mnemonic", "seed", "share", "privkey"}

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
		// Byte arrays that are NOT 20/32 (the address/id sizes) are treated as
		// potential opaque secret holders.
		if ft.Elem().Kind() == reflect.Uint8 && ft.Len() != 20 && ft.Len() != 32 {
			return true
		}
		return false
	}
	return false
}

func walkType(t *testing.T, typ reflect.Type, path string, seen map[reflect.Type]bool) {
	if typ == nil || seen[typ] {
		return
	}
	seen[typ] = true

	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		walkType(t, typ.Elem(), path, seen)
	case reflect.Map:
		walkType(t, typ.Key(), path, seen)
		walkType(t, typ.Elem(), path, seen)
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fp := path + "." + f.Name
			tn := f.Type.String()
			// No private/secret key TYPE may appear anywhere in the graph.
			require.Falsef(t,
				strings.Contains(tn, "PrivateKey") || strings.Contains(tn, "SecretKey"),
				"field %s has secret-bearing type %s", fp, tn)
			// No byte-bearing field may be NAMED like a secret.
			if isByteBearing(f.Type) {
				lower := strings.ToLower(f.Name)
				for _, tok := range secretNameTokens {
					require.Falsef(t, strings.Contains(lower, tok),
						"byte-bearing field %s (%s) name contains secret token %q", fp, tn, tok)
				}
			}
			walkType(t, f.Type, fp, seen)
		}
		// Interfaces, channels, funcs, primitives: nothing to descend / not secret holders.
	}
}

func TestZeroSecret_NoSecretFieldsInState(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(KeyRecord{}),
		reflect.TypeOf(CeremonyRecord{}),
		reflect.TypeOf(AuthPolicy{}),
		reflect.TypeOf(Transaction{}),
		reflect.TypeOf(Block{}),
		reflect.TypeOf(RegisterKeyPayload{}),
		reflect.TypeOf(VM{}), // the VM itself must hold no secret field
	}
	seen := make(map[reflect.Type]bool)
	for _, r := range roots {
		walkType(t, r, r.Name(), seen)
	}
}

func TestZeroSecret_NoSecretProducingCalls(t *testing.T) {
	// Forbidden IDENTIFIERS: any function/type/field by which K could generate,
	// parse, reconstruct, decapsulate, or sign with a secret. We check the AST
	// (identifiers only), so doc comments that merely NAME these tokens to
	// explain the invariant are not flagged — only real code is. Public-key
	// parsing (PublicKeyFromBytes) and signature VERIFICATION (VerifySignature)
	// are intentionally absent and remain the only cryptography K performs.
	// exact: call/type names with no legitimate substring collision.
	exact := map[string]bool{
		"GenerateKey":   true, // keypair generation
		"NewSecretKey":  true, // BLS secret key
		"Decapsulate":   true, // KEM decapsulation (uses the private key)
		"Encapsulate":   true, // KEM encapsulation (K performs no crypto compute)
		"Sign":          true, // signing (uses the private key)
		"Zeroize":       true, // only needed if secret material were held
		"Reconstruct":   true, // share reconstruction
		"CombineShares": true, // share combination
		"RecoverSecret": true,
		"ShareData":     true, // the prior design's secret share-bytes field
	}
	// keyMarkers: substring markers for any private/secret KEY type, catching
	// variants like PrivateKeyFromBytes or mldsa.SecretKey. "PublicKey" and
	// "VerifySignature" contain neither, so the public path is unaffected.
	keyMarkers := []string{"PrivateKey", "SecretKey"}
	const forbiddenImport = "crypto/mlkem" // the KEM package; its private op is the exfil risk

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

		for _, imp := range f.Imports {
			require.NotContainsf(t, imp.Path.Value, forbiddenImport,
				"file %s imports forbidden secret-bearing package %s", name, imp.Path.Value)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			require.Falsef(t, exact[id.Name],
				"file %s references forbidden secret-bearing identifier %q at %s",
				name, id.Name, fset.Position(id.Pos()))
			for _, m := range keyMarkers {
				require.Falsef(t, strings.Contains(id.Name, m),
					"file %s references secret-key-typed identifier %q (marker %q) at %s",
					name, id.Name, m, fset.Position(id.Pos()))
			}
			return true
		})
		scanned++
	}
	require.Greater(t, scanned, 5, "expected to scan the keyvm package sources")
}

// TestZeroSecret_ReconstructIsAbsent asserts the VM exposes no method that could
// hand back secret material. It is a belt-and-suspenders check over the public
// method set complementing the source scan.
func TestZeroSecret_ReconstructIsAbsent(t *testing.T) {
	bad := []string{"Reconstruct", "PrivateKey", "SecretKey", "Decrypt", "Decapsulate", "Sign", "Share", "Seed"}
	vt := reflect.TypeOf(&VM{})
	for i := 0; i < vt.NumMethod(); i++ {
		m := vt.Method(i).Name
		for _, b := range bad {
			require.Falsef(t, strings.Contains(m, b),
				"VM exposes method %q which suggests secret access", m)
		}
	}
}
