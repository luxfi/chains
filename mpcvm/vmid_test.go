// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"testing"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
)

// canonicalVMIDCB58 is M-Chain's vmID in the encoding the node's plugin
// registry uses. The plugin binary MUST be installed under exactly this
// filename; the registry resolves a CreateChainTx's vmID to an implementation
// by looking for a file with this name in the plugin directory.
//
// It is written out literally rather than computed so that a change to the
// vmID — for any reason, including an "obviously equivalent" refactor of the
// constant — fails this test instead of silently producing a chain that no
// node can start. A vmID is an immutable one-way door: it is baked into the
// genesis CreateChainTx and stored by the P-Chain forever.
const canonicalVMIDCB58 = "qCURact1n41FcoNBch8iMVBwc9AWie48D118ZNJ5tBdWrvryS"

// staleThresholdVMCB58 is what this VM used to declare. The package was split
// into mpcvm (M-Chain) and fhevm (F-Chain) per LP-7050, but the private
// `thresholdvm` literal survived in factory.go and the node's Dockerfile
// installed the plugin under this name while genesis declared MPCVMID. The two
// never met, so M-Chain could not have started. Pinned here so the dead name
// can never come back by accident.
const staleThresholdVMCB58 = "tGVBwRxpmD2aFdg3iYjgRvrCe8Jcmq9UNKxyHMus2NZ8WcD8t"

func TestVMID_IsCanonicalAndStable(t *testing.T) {
	if VMID != constants.MPCVMID {
		t.Fatalf("VMID = %s, want constants.MPCVMID = %s", VMID, constants.MPCVMID)
	}
	if got := VMID.String(); got != canonicalVMIDCB58 {
		t.Fatalf("VMID CB58 = %q, want %q\n"+
			"A vmID cannot change after a chain is created with it. If this is an\n"+
			"intentional pre-launch change, every declaration must move together:\n"+
			"  luxfi/constants        vm_ids.go MPCVMID\n"+
			"  node/genesis/builder   registry.go M-Chain row\n"+
			"  node/node              vms.go OptionalVMs\n"+
			"  node/Dockerfile        plugin build -o, verify list, runtime COPY\n"+
			"  node/scripts           publish_plugin_set.sh\n"+
			"  chains/mpcvm           factory.go, this test",
			got, canonicalVMIDCB58)
	}
	if VMID.String() == staleThresholdVMCB58 {
		t.Fatal("VMID regressed to the retired thresholdvm identifier")
	}
	if VMID == ids.Empty {
		t.Fatal("VMID is the empty id")
	}
}

// The bytes themselves, spelled out: an ASCII name left-padded into 32 bytes.
func TestVMID_Bytes(t *testing.T) {
	want := ids.ID{'m', 'p', 'c', 'v', 'm'}
	if VMID != want {
		t.Fatalf("VMID bytes = %v, want %v", VMID[:8], want[:8])
	}
}

// -----------------------------------------------------------------------------
// The k-vs-t fix, at the M-Chain level
// -----------------------------------------------------------------------------

// A custody key registered as 3-of-5 must be a degree-2 key. This is the same
// property the types package asserts for ceremonies, checked here on the record
// that actually governs signature verification.
func TestKeyRecord_ThreeOfFiveIsDegreeTwo(t *testing.T) {
	rec := &KeyRecord{
		KeyID:          "custody",
		Kind:           KindCGGMP21,
		Policy:         quorum.MustNew(3, 5),
		Participants:   sortedParties("a", "b", "c", "d", "e"),
		GroupPublicKey: make([]byte, 33),
		Address:        make([]byte, 20),
	}
	if got := rec.Degree(); got != 2 {
		t.Fatalf("3-of-5 custody key Degree() = %d, want 2", got)
	}
	if got := rec.Policy.K; got != 3 {
		t.Fatalf("3-of-5 needs %d signers, want 3", got)
	}
	if err := rec.Validate(); err != nil {
		t.Fatalf("a well-formed 3-of-5 record must validate, got: %v", err)
	}
}

// Validate is the gate every key crosses before entering consensus state, so
// each structural invariant it enforces is load-bearing for a later signature
// check. Prove each one actually rejects.
func TestKeyRecord_ValidateRejectsMalformed(t *testing.T) {
	good := func() *KeyRecord {
		return &KeyRecord{
			KeyID:          "custody",
			Kind:           KindCGGMP21,
			Policy:         quorum.MustNew(3, 5),
			Participants:   sortedParties("a", "b", "c", "d", "e"),
			GroupPublicKey: make([]byte, 33),
			Address:        make([]byte, 20),
		}
	}
	for _, tc := range []struct {
		name  string
		mutup func(*KeyRecord)
	}{
		{"no key id", func(r *KeyRecord) { r.KeyID = "" }},
		{"no protocol kind", func(r *KeyRecord) { r.Kind = "" }},
		{"unset policy", func(r *KeyRecord) { r.Policy = quorum.Policy{} }},
		{"1-of-n is not a threshold policy", func(r *KeyRecord) { r.Policy = quorum.Policy{K: 1, N: 5} }},
		{"two disjoint quorums", func(r *KeyRecord) { r.Policy = quorum.Policy{K: 2, N: 5} }},
		{"participant count disagrees with N", func(r *KeyRecord) { r.Participants = sortedParties("a", "b", "c") }},
		{"participants not canonical", func(r *KeyRecord) { r.Participants = sortedParties("e", "d", "c", "b", "a") }},
		{"duplicate participant", func(r *KeyRecord) { r.Participants = sortedParties("a", "a", "c", "d", "e") }},
		{"uncompressed group key", func(r *KeyRecord) { r.GroupPublicKey = make([]byte, 65) }},
		{"short address", func(r *KeyRecord) { r.Address = make([]byte, 19) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good()
			tc.mutup(r)
			if err := r.Validate(); err == nil {
				t.Fatalf("Validate accepted a record with %s", tc.name)
			}
		})
	}
}

// The degree a key was generated with is never stored as its own field, so it
// cannot disagree with the policy. Assert the property holds across the range
// M-Chain will realistically deploy.
func TestKeyRecord_DegreeIsAlwaysKMinusOne(t *testing.T) {
	for n := 2; n <= 12; n++ {
		for k := 2; k <= n; k++ {
			p := quorum.MustNew(k, n)
			rec := &KeyRecord{Policy: p}
			if got, want := rec.Degree(), k-1; got != want {
				t.Fatalf("%s: Degree() = %d, want %d", p, got, want)
			}
		}
	}
}

// sortedParties builds a canonical participant list. Participants must be
// sorted and unique so every validator hashes the same bytes for a record.
func sortedParties(names ...string) []party.ID {
	out := make([]party.ID, len(names))
	for i, n := range names {
		out[i] = party.ID(n)
	}
	return out
}
