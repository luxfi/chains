// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
)

// methods are the HTTP verbs an OpenAPI path item may carry. A key that is not
// one of these is metadata (parameters, summary, servers) and is not an
// operation.
var methods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

var errNoPaths = errors.New("document has no paths")

// document is the slice of OpenAPI this generator reads. Everything else in the
// file is irrelevant to what capability exists.
type document struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

// derive turns an OpenAPI document into a catalog: one group per top-level path
// segment, each committing to the operations it holds.
//
// An operation is identified by "METHOD path", uppercased and taken verbatim, so
// two surfaces holding the same routes produce the same digest and a surface that
// gains, loses or renames one does not. The identifiers are sorted before folding
// so the digest does not depend on the order the document happened to list them.
func derive(doc []byte, version uint32, prefix string) (agentvm.Catalog, error) {
	var parsed document
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return agentvm.Catalog{}, err
	}
	if len(parsed.Paths) == 0 {
		return agentvm.Catalog{}, errNoPaths
	}

	type acc struct {
		paths int
		ops   []string
	}
	byGroup := map[string]*acc{}

	for path, item := range parsed.Paths {
		name := group(path, prefix)
		if name == "" {
			continue
		}
		g, seen := byGroup[name]
		if !seen {
			g = &acc{}
			byGroup[name] = g
		}
		g.paths++
		for method := range item {
			if !methods[strings.ToLower(method)] {
				continue
			}
			g.ops = append(g.ops, strings.ToUpper(method)+" "+path)
		}
	}

	names := make([]string, 0, len(byGroup))
	for name := range byGroup {
		names = append(names, name)
	}
	sort.Strings(names)

	cat := agentvm.Catalog{Version: version, Groups: make([]agentvm.Group, 0, len(names))}
	for _, name := range names {
		g := byGroup[name]
		if len(g.ops) == 0 {
			// A path with no operations describes nothing to serve.
			continue
		}
		sort.Strings(g.ops)
		cat.Groups = append(cat.Groups, agentvm.Group{
			Name:   name,
			Paths:  uint32(g.paths),
			Ops:    uint32(len(g.ops)),
			Digest: fold(g.ops),
		})
	}
	return cat, cat.Validate()
}

// group is the capability a path belongs to: its first segment after the version
// prefix. A path outside the prefix is grouped by its own first segment, so a
// document that does not use one still produces a catalog.
func group(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimPrefix(rest, "/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	// A path whose first segment is a parameter names no capability.
	if strings.HasPrefix(rest, "{") {
		return ""
	}
	return rest
}

// fold commits to a group's operations. Each identifier is length-framed before
// it is absorbed, so no two lists of operations can concatenate to the same bytes.
func fold(ops []string) common.Hash {
	buf := make([]byte, 0, len(ops)*32)
	buf = append(buf, byte(len(ops)>>24), byte(len(ops)>>16), byte(len(ops)>>8), byte(len(ops)))
	for _, op := range ops {
		n := len(op)
		buf = append(buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		buf = append(buf, op...)
	}
	return common.BytesToHash(crypto.Keccak256([]byte(agentvm.DomainGroup), buf))
}
