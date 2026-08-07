// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package slot pins which VM plugin slots this module is allowed to claim.
//
// luxd loads a VM by executing the binary at <PluginDir>/<VMID>; the VMID alone
// decides which chain that binary drives. A slot admits exactly one artifact, so
// a second binary built for the same slot is not a spare — it is a coin flip
// settled by whichever image wrote the file last.
//
// The D-Chain slot is the case that motivated this package. Its id is the ASCII
// name "dexvm" zero-padded to 32 bytes, and the artifact that fills it is
// luxfi/dex cmd/dexd — the matcher VM that runs the order book inside consensus.
// This module used to ship a SECOND binary for that same slot: a proxy whose wire
// spoke clob_* while the venue answered dex_*. It loaded, reported healthy, and
// answered nothing — a failure that reads as a working node. The proxy is gone;
// these tests keep it gone.
//
// The checks read the AST rather than the file text, so they judge what the code
// DECLARES. A comment may discuss the D slot or the dead wire freely; only a
// declaration claims them.
package slot

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luxfi/ids"
)

// dSlot is the canonical D-Chain VM id, derived rather than pasted: a chain's
// VMID is its name in ASCII, zero-padded to 32 bytes.
var dSlot = func() ids.ID {
	var id ids.ID
	copy(id[:], "dexvm")
	return id
}()

// moduleRoot is this module's root directory (two levels up from internal/slot).
const moduleRoot = "../.."

// eachFile parses every .go file in the module and hands the AST to visit, keyed
// by module-relative path. Vendored trees and build output are skipped: neither
// is source this module ships.
func eachFile(t *testing.T, visit func(path string, file *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	n := 0
	err := filepath.WalkDir(moduleRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "build", "node_modules", "testdata":
				return filepath.SkipDir
			}
			// This package carries the patterns it looks for; a checker does not
			// judge its own pattern table.
			if path == filepath.Join(moduleRoot, "internal", "slot") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(moduleRoot, path)
		if rerr != nil {
			return rerr
		}
		n++
		visit(rel, f)
		return nil
	})
	if err != nil {
		t.Fatalf("parsing module source: %v", err)
	}
	if n == 0 {
		t.Fatal("parsed no .go files — the walk is broken, not the invariant")
	}
}

// vmIDLiteral reports the VM id a composite literal declares, for literals of the
// form ids.ID{...}. Elements are read as untyped byte constants, so a claim spelled
// in characters, decimals or hex is recognised the same way. ok is false for any
// literal that is not a fully constant ids.ID.
func vmIDLiteral(node ast.Node) (id ids.ID, ok bool) {
	lit, isComposite := node.(*ast.CompositeLit)
	if !isComposite {
		return id, false
	}
	sel, isSel := lit.Type.(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name != "ID" {
		return id, false
	}
	pkg, isIdent := sel.X.(*ast.Ident)
	if !isIdent || pkg.Name != "ids" {
		return id, false
	}
	if len(lit.Elts) > len(id) {
		return id, false
	}
	for i, elt := range lit.Elts {
		b, isBasic := elt.(*ast.BasicLit)
		if !isBasic {
			return id, false // not a constant claim; nothing to judge
		}
		switch b.Kind {
		case token.CHAR:
			r, _, _, uerr := strconv.UnquoteChar(strings.Trim(b.Value, "'"), '\'')
			if uerr != nil || r > 0xFF {
				return id, false
			}
			id[i] = byte(r)
		case token.INT:
			v, cerr := strconv.ParseUint(b.Value, 0, 8)
			if cerr != nil {
				return id, false
			}
			id[i] = byte(v)
		default:
			return id, false
		}
	}
	return id, true
}

// wireMethod reports whether s is shaped like a wire method name rather than
// prose that happens to mention one. A method name is a bare lowercase token; a
// log line or format string is not, and flagging those would train readers to
// ignore this check.
func wireMethod(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return s != ""
}

// stringLit returns the value of a string literal node.
func stringLit(node ast.Node) (string, bool) {
	b, ok := node.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(b.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// TestClaimsNoDChainSlot asserts no package in this module declares the D-Chain
// VM id. The D VM is not here: it is luxfi/dex cmd/dexd, which the node Dockerfile
// builds straight into the slot. A declaration of this id inside chains is a
// package positioning itself to be installed over the real matcher.
//
// Both spellings are checked because both are installable: the byte literal is how
// Go code claims the id, and the CB58 form names the plugin FILE on disk.
func TestClaimsNoDChainSlot(t *testing.T) {
	cb58 := dSlot.String()
	eachFile(t, func(path string, f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := vmIDLiteral(n); ok && id == dSlot {
				t.Errorf("%s declares the canonical D-Chain VM id. That slot belongs to "+
					"luxfi/dex cmd/dexd; a second artifact for it replaces the matcher "+
					"with whatever this package serves", path)
			}
			if s, ok := stringLit(n); ok && s == cb58 {
				t.Errorf("%s names the D-Chain plugin file %s. That path is the install "+
					"target of the real matcher", path, cb58)
			}
			return true
		})
	})
}

// TestCarriesNoDeadDexWire asserts this module declares no clob_* wire method.
//
// A VM in the D slot is reachable only through the names it answers. The venue
// registers dex_* (luxfi/dex pkg/zapwire); clob_* was the deleted proxy's wire and
// matches nothing on either side. Names that match nothing are precisely what made
// the proxy dangerous: the node loads, health passes, and every order is a no-op.
func TestCarriesNoDeadDexWire(t *testing.T) {
	eachFile(t, func(path string, f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := stringLit(n); ok && strings.HasPrefix(s, "clob_") && wireMethod(s) {
				t.Errorf("%s declares the wire method %q. Nothing answers that namespace — "+
					"the venue registers dex_*, so this name reaches no matcher", path, s)
			}
			return true
		})
	})
}

// TestPublishesNoDChainImage asserts the release matrix ships no image for the
// D-Chain slot. .github/images.json is the whole publish plan: release.yml maps
// each entry to `go build ./<vm>/cmd/plugin` and pushes it as an image named for
// the vm. An entry here is not a latent risk — it is CI handing operators a binary
// that lands in the canonical slot on install.
func TestPublishesNoDChainImage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(moduleRoot, ".github", "images.json"))
	if err != nil {
		t.Fatalf("reading the release image matrix: %v", err)
	}
	var images []struct {
		VM    string `json:"vm"`
		Image string `json:"image"`
	}
	if err := json.Unmarshal(raw, &images); err != nil {
		t.Fatalf("parsing the release image matrix: %v", err)
	}
	if len(images) == 0 {
		t.Fatal("the release image matrix parsed empty — the parse is broken, not the invariant")
	}
	// The slot's identity IS its name: the VMID is "dexvm" in ASCII, and release.yml
	// names both the build target and the published image after that string.
	slotName := strings.TrimRight(string(dSlot[:]), "\x00")
	for _, img := range images {
		if img.VM == slotName {
			t.Errorf("the release matrix publishes %q as %s — that binary loads into the "+
				"canonical D-Chain slot %s, which luxfi/dex cmd/dexd already fills",
				img.VM, img.Image, dSlot)
		}
	}
}
