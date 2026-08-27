// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"testing"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
)

// canonicalVMIDCB58 is F-Chain's vmID in the encoding the node's plugin
// registry uses. The plugin binary MUST be installed under exactly this
// filename; the registry resolves a CreateChainTx's vmID to an implementation
// by looking for a file with this name in the plugin directory.
//
// It is written out literally rather than computed so that a change to the
// vmID — for any reason, including an "obviously equivalent" refactor of the
// constant — fails this test instead of silently producing a chain that no
// node can start. A vmID is an immutable one-way door: it is baked into the
// genesis CreateChainTx and stored by the P-Chain forever.
const canonicalVMIDCB58 = "n6sSsSfbpQBrU9sY4R29U6z8VrmnTo2CntW6da4rRS7qmnGdv"

func TestVMID_IsCanonicalAndStable(t *testing.T) {
	if VMID != constants.FHEVMID {
		t.Fatalf("VMID = %s, want constants.FHEVMID = %s", VMID, constants.FHEVMID)
	}
	if got := VMID.String(); got != canonicalVMIDCB58 {
		t.Fatalf("VMID CB58 = %q, want %q\n"+
			"A vmID cannot change after a chain is created with it. If this is an\n"+
			"intentional pre-launch change, every declaration must move together:\n"+
			"  luxfi/constants        vm_ids.go FHEVMID\n"+
			"  node/node              vms.go OptionalVMs\n"+
			"  node/Dockerfile        plugin build -o, verify list, runtime COPY\n"+
			"  chains/fhevm           factory.go, cmd/plugin/main.go, this test",
			got, canonicalVMIDCB58)
	}
	if VMID == ids.Empty {
		t.Fatal("VMID is the empty id")
	}
	// M-Chain and F-Chain were split out of the retired thresholdvm package
	// (LP-7050). They are separate chains and must never share an id.
	if VMID == constants.MPCVMID {
		t.Fatal("F-Chain's vmID collides with M-Chain's")
	}
}

// The bytes themselves, spelled out: an ASCII name left-padded into 32 bytes.
func TestVMID_Bytes(t *testing.T) {
	want := ids.ID{'f', 'h', 'e', 'v', 'm'}
	if VMID != want {
		t.Fatalf("VMID bytes = %v, want %v", VMID[:8], want[:8])
	}
}

// TestVMID_NameResolves proves luxfi/constants maps this id back to the plugin
// name the node scans --plugin-dir for. If the two ever disagree, luxd looks
// for a binary nobody builds and the chain silently never starts.
func TestVMID_NameResolves(t *testing.T) {
	if got := constants.VMName(VMID); got != VMName {
		t.Fatalf("constants.VMName(VMID) = %q, want %q", got, VMName)
	}
}
