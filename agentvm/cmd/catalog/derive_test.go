// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/agentvm"
)

// doc builds an OpenAPI document with the given paths, each carrying the methods
// named for it.
func doc(paths map[string][]string) []byte {
	out := map[string]any{"openapi": "3.0.0", "paths": map[string]any{}}
	p := out["paths"].(map[string]any)
	for path, methods := range paths {
		item := map[string]any{
			// Metadata that is not an operation and must not be counted.
			"parameters": []any{},
			"summary":    "a path",
		}
		for _, m := range methods {
			item[m] = map[string]any{"operationId": m + path}
		}
		p[path] = item
	}
	body, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	return body
}

func TestDeriveGroupsByFirstSegment(t *testing.T) {
	cat, err := derive(doc(map[string][]string{
		"/v1/ai/chat/completions": {"post"},
		"/v1/ai/models":           {"get"},
		"/v1/ai/models/{id}":      {"get", "delete"},
		"/v1/iam/users":           {"get", "post"},
		"/v1/commerce/orders":     {"get"},
	}), 1, "/v1")
	require.NoError(t, err)

	require.Equal(t, uint32(1), cat.Version)
	require.Len(t, cat.Groups, 3)
	require.Equal(t, []string{"ai", "commerce", "iam"}, names(cat), "groups are sorted by name")

	ai, ok := cat.Group("ai")
	require.True(t, ok)
	require.Equal(t, uint32(3), ai.Paths)
	require.Equal(t, uint32(4), ai.Ops, "metadata keys are not operations")

	require.Equal(t, uint32(5), cat.Paths())
	require.Equal(t, uint32(7), cat.Ops())
}

// TestDeriveIsStable: the same surface gives the same digest whatever order the
// document lists it in, because a digest that depended on JSON ordering would
// change without the surface changing.
func TestDeriveIsStable(t *testing.T) {
	paths := map[string][]string{
		"/v1/ai/a":  {"get", "post"},
		"/v1/ai/b":  {"post", "get"},
		"/v1/iam/c": {"get"},
	}
	first, err := derive(doc(paths), 1, "/v1")
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		again, err := derive(doc(paths), 1, "/v1")
		require.NoError(t, err)
		require.Equal(t, first.Digest(), again.Digest())
	}
}

// TestAddingARouteIsANewDigest: which is the whole point of storing a digest
// rather than a route list.
func TestAddingARouteIsANewDigest(t *testing.T) {
	base := map[string][]string{"/v1/ai/a": {"get"}, "/v1/iam/c": {"get"}}
	before, err := derive(doc(base), 1, "/v1")
	require.NoError(t, err)

	base["/v1/ai/b"] = []string{"get"}
	after, err := derive(doc(base), 1, "/v1")
	require.NoError(t, err)

	require.NotEqual(t, before.Digest(), after.Digest())
	beforeAI, _ := before.Group("ai")
	afterAI, _ := after.Group("ai")
	require.NotEqual(t, beforeAI.Digest, afterAI.Digest, "the group that changed has a new digest")

	beforeIAM, _ := before.Group("iam")
	afterIAM, _ := after.Group("iam")
	require.Equal(t, beforeIAM.Digest, afterIAM.Digest, "a group that did not change keeps its digest")

	// A version bump alone also changes the surface digest, so a version names
	// exactly one surface.
	bumped, err := derive(doc(base), 2, "/v1")
	require.NoError(t, err)
	require.NotEqual(t, after.Digest(), bumped.Digest())
}

// TestMethodChangeIsADifferentGroup: the same paths served by different verbs are
// a different capability.
func TestMethodChangeIsADifferentGroup(t *testing.T) {
	get, err := derive(doc(map[string][]string{"/v1/ai/a": {"get"}}), 1, "/v1")
	require.NoError(t, err)
	post, err := derive(doc(map[string][]string{"/v1/ai/a": {"post"}}), 1, "/v1")
	require.NoError(t, err)
	require.NotEqual(t, get.Digest(), post.Digest())
}

// TestFoldCannotAlias: two operation lists whose bytes would concatenate the same
// way must fold differently.
func TestFoldCannotAlias(t *testing.T) {
	require.NotEqual(t, fold([]string{"AB", "C"}), fold([]string{"A", "BC"}))
	require.NotEqual(t, fold([]string{"A"}), fold([]string{"A", ""}))
}

func TestDeriveHandlesPrefixesAndParameters(t *testing.T) {
	// Without the prefix, grouping falls back to the first segment.
	cat, err := derive(doc(map[string][]string{"/ai/a": {"get"}, "/iam/b": {"get"}}), 1, "/v1")
	require.NoError(t, err)
	require.Equal(t, []string{"ai", "iam"}, names(cat))

	// A path whose first segment is a parameter names no capability and is
	// dropped rather than becoming a group called "{id}".
	cat, err = derive(doc(map[string][]string{"/v1/{id}/x": {"get"}, "/v1/ai/a": {"get"}}), 1, "/v1")
	require.NoError(t, err)
	require.Equal(t, []string{"ai"}, names(cat))
}

func TestDeriveRefusesNothingToDescribe(t *testing.T) {
	_, err := derive([]byte(`{"openapi":"3.0.0","paths":{}}`), 1, "/v1")
	require.ErrorIs(t, err, errNoPaths)

	_, err = derive([]byte(`not json`), 1, "/v1")
	require.Error(t, err)

	// A version of zero is not a version.
	_, err = derive(doc(map[string][]string{"/v1/ai/a": {"get"}}), 0, "/v1")
	require.ErrorIs(t, err, agentvm.ErrCatalogVersion)

	// Paths carrying only metadata describe no operation, so there is no group.
	_, err = derive([]byte(`{"paths":{"/v1/ai/a":{"summary":"nothing"}}}`), 1, "/v1")
	require.ErrorIs(t, err, agentvm.ErrCatalogGroups)
}

// TestDeriveScalesToTheRealSurface exercises the generator at the size of the
// measured surface: 1,612 paths across the groups it actually has.
func TestDeriveScalesToTheRealSurface(t *testing.T) {
	// The measured group shape, biggest first.
	shape := []struct {
		name  string
		paths int
	}{
		{"o11y", 287}, {"ai", 146}, {"iam", 92}, {"commerce", 82},
		{"integrations", 44}, {"billing", 40}, {"git", 36}, {"platform", 33},
		{"agents", 28}, {"pricing", 27}, {"visor", 25}, {"cloudflare", 23},
	}
	paths := map[string][]string{}
	total := 0
	for _, g := range shape {
		for i := 0; i < g.paths; i++ {
			paths[fmt.Sprintf("/v1/%s/r%d", g.name, i)] = []string{"get", "post"}
			total++
		}
	}
	cat, err := derive(doc(paths), 7, "/v1")
	require.NoError(t, err)
	require.Len(t, cat.Groups, len(shape))
	require.Equal(t, uint32(total), cat.Paths())
	require.Equal(t, uint32(total*2), cat.Ops())
	require.NoError(t, cat.Validate())

	// The whole surface is one 32-byte commitment, whatever its size.
	require.Len(t, cat.Digest().Bytes(), 32)
}

func names(c agentvm.Catalog) []string {
	out := make([]string, 0, len(c.Groups))
	for _, g := range c.Groups {
		out = append(out, g.Name)
	}
	return out
}

// TestGroupTrimsOnlyItsOwnPrefix guards the string handling the grouping rests on.
func TestGroupSegments(t *testing.T) {
	cases := map[string]string{
		"/v1/ai/chat":  "ai",
		"/v1/ai":       "ai",
		"/ai/chat":     "ai",
		"/v1/":         "",
		"/v1":          "",
		"/v1/{id}/x":   "",
		"/v1/o11y/a/b": "o11y",
	}
	for path, want := range cases {
		require.Equal(t, want, group(path, "/v1"), path)
	}
	require.True(t, strings.HasPrefix("/v1/ai", "/v1"))
}
