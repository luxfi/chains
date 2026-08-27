// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command catalog derives an AgentVM capability catalog from an OpenAPI document.
//
// The catalog is DERIVED, never transcribed. An API surface of a couple of
// thousand operations is not something to hand-copy into Go: it changes, and a
// hand-copy drifts silently. What the chain stores is a digest per group and a
// digest over the whole surface, so adding an operation is a version bump and a
// new digest rather than a code change.
//
// Usage:
//
//	catalog -in openapi.json -version 1 [-out catalog.json] [-prefix /v1]
//
// The input is an OpenAPI 3 document in JSON. Groups are the first path segment
// after the version prefix, which is how this surface is already organised:
// /v1/ai/... is the ai group, /v1/iam/... is iam.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/luxfi/chains/agentvm"
)

func main() {
	in := flag.String("in", "", "OpenAPI 3 document, in JSON")
	out := flag.String("out", "", "where to write the catalog; stdout if empty")
	version := flag.Uint("version", 0, "catalog version to stamp")
	prefix := flag.String("prefix", "/v1", "path prefix to strip before grouping")
	flag.Parse()

	if *in == "" || *version == 0 {
		fmt.Fprintln(os.Stderr, "catalog: -in and a non-zero -version are required")
		os.Exit(2)
	}

	doc, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog: read %s: %v\n", *in, err)
		os.Exit(1)
	}

	cat, err := derive(doc, uint32(*version), *prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog: derive: %v\n", err)
		os.Exit(1)
	}

	body, err := json.MarshalIndent(struct {
		agentvm.Catalog
		Digest string `json:"digest"`
		Paths  uint32 `json:"totalPaths"`
		Ops    uint32 `json:"totalOps"`
	}{cat, cat.Digest().Hex(), cat.Paths(), cat.Ops()}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog: encode: %v\n", err)
		os.Exit(1)
	}
	body = append(body, '\n')

	if *out == "" {
		os.Stdout.Write(body)
		return
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "catalog: write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "catalog v%d: %d groups, %d paths, %d operations, digest %s\n",
		cat.Version, len(cat.Groups), cat.Paths(), cat.Ops(), cat.Digest().Hex())
}
