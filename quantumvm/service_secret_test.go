// Copyright 2026 Lux Industries, Inc. All Rights Reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// This service is reachable without a credential, so an argument it declares is
// an invitation. A field named for a secret is one a caller will fill in, and the
// body is decoded before any handler runs — so refusing the request afterwards
// does not stop the secret arriving. Nothing here should ask for one.
func TestNoRPCArgumentAsksForASecret(t *testing.T) {
	fs := token.NewFileSet()
	pkg, err := parser.ParseDir(fs, ".", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	secret := []string{"privatekey", "secretkey", "seed", "mnemonic", "passphrase", "password"}

	for _, p := range pkg {
		ast.Inspect(p, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !strings.HasSuffix(ts.Name.Name, "Args") {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, f := range st.Fields.List {
				for _, name := range f.Names {
					low := strings.ToLower(name.Name)
					for _, s := range secret {
						if strings.Contains(low, s) {
							t.Errorf("%s.%s asks a caller to send a secret to an endpoint that needs no credential", ts.Name.Name, name.Name)
						}
					}
				}
			}
			return true
		})
	}
}
