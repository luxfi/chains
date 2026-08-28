// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"context"
	"testing"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	upstream "github.com/luxfi/relay/vm"
	"github.com/luxfi/vm/chain"
)

// canonicalVMIDCB58 is R-Chain's vmID in the encoding the node's plugin
// registry uses. The plugin binary MUST be installed under exactly this
// filename; the registry resolves a CreateChainTx's vmID to an implementation
// by looking for a file with this name in the plugin directory.
//
// Written out literally rather than computed, so that a change to the vmID —
// for any reason, including an "obviously equivalent" refactor — fails here
// instead of silently producing a chain no node can start.
const canonicalVMIDCB58 = "sP6dLqrrBR9w3soP18fbJ3YzZecZdD7DDdfH2cFhhLq7Hy9bz"

// The three declarations of R-Chain's vmID must be one value.
//
// luxfi/relay declares its own private literal, `ids.ID{'r','e','l','a','y',
// 'v','m'}` at vm/factory.go. luxfi/constants declares RelayVMID. They agree
// today and nothing in either repo makes them. This repo builds the plugin
// binary whose FILENAME is that id, so this is the layer where the agreement
// is checked; if luxfi/relay's literal ever moves, a node would look for a
// plugin under one name while genesis named the other, and the chain would
// simply never appear.
func TestVMID_IsCanonicalAndStable(t *testing.T) {
	if VMID != constants.RelayVMID {
		t.Fatalf("VMID = %s, want constants.RelayVMID = %s", VMID, constants.RelayVMID)
	}
	if VMID != upstream.VMID {
		t.Fatalf("VMID = %s, but luxfi/relay/vm.VMID = %s\n"+
			"The upstream private literal has drifted from constants.RelayVMID.\n"+
			"The plugin binary this repo builds is named after constants; the VM\n"+
			"inside it believes the other value.", VMID, upstream.VMID)
	}
	if got := VMID.String(); got != canonicalVMIDCB58 {
		t.Fatalf("VMID CB58 = %q, want %q\n"+
			"A vmID cannot change after a chain is created with it. If this is an\n"+
			"intentional pre-launch change, every declaration must move together:\n"+
			"  luxfi/constants  vm_ids.go RelayVMID\n"+
			"  luxfi/relay      vm/factory.go VMID\n"+
			"  chains/relayvm   relayvm.go, this test",
			got, canonicalVMIDCB58)
	}
	if VMID == ids.Empty {
		t.Fatal("VMID is the empty id")
	}
}

// The bytes themselves, spelled out: an ASCII name left-padded into 32 bytes.
func TestVMID_Bytes(t *testing.T) {
	want := ids.ID{'r', 'e', 'l', 'a', 'y', 'v', 'm'}
	if VMID != want {
		t.Fatalf("VMID bytes = %v, want %v", VMID[:9], want[:9])
	}
}

// R-Chain and O-Chain are different chains, so their ids are different values.
// The two shims are near-copies of each other; a copy that kept the wrong id
// would still compile, still pass its own byte test if that were copied too,
// and produce two plugins racing for one filename.
func TestVMID_IsNotAnotherChains(t *testing.T) {
	for name, other := range map[string]ids.ID{
		"OracleVMID":   constants.OracleVMID,
		"BridgeVMID":   constants.BridgeVMID,
		"MPCVMID":      constants.MPCVMID,
		"IdentityVMID": constants.IdentityVMID,
	} {
		if VMID == other {
			t.Fatalf("relayvm.VMID equals constants.%s (%s)", name, other)
		}
	}
}

// What the Factory builds is what the plugin serves.
//
// Factory.New satisfies the node's vms.Factory, so it returns interface{} and
// the value's real type is checked nowhere at compile time. relayvm.go asserts
// *VM implements chain.ChainVM; this asserts the Factory actually produces a
// *VM. Together they are the whole claim, and the plugin needs no runtime
// check of its own.
func TestFactoryBuildsTheVMThePluginServes(t *testing.T) {
	raw, err := (&Factory{}).New(log.Root())
	if err != nil {
		t.Fatalf("Factory.New: %v", err)
	}
	vm, ok := raw.(*VM)
	if !ok {
		t.Fatalf("Factory.New built a %T, want *relayvm.VM", raw)
	}
	if vm == nil {
		t.Fatal("Factory.New built a nil *VM")
	}
	if _, ok := raw.(chain.ChainVM); !ok {
		t.Fatalf("Factory.New built a %T, which is not a chain.ChainVM — "+
			"the plugin cannot serve it", raw)
	}
}

// A VM reports its own version, and the plugin prints that rather than a
// second copy of the number. Two declarations of one version disagree the
// first time either is bumped, and the one an operator reads is the plugin's.
func TestTheVMReportsAVersion(t *testing.T) {
	raw, err := (&Factory{}).New(log.Root())
	if err != nil {
		t.Fatalf("Factory.New: %v", err)
	}
	v, err := raw.(chain.ChainVM).Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v == "" {
		t.Fatal("the VM reports an empty version; the plugin would print none")
	}
}
