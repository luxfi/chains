// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"github.com/luxfi/node/vms/types/fee"
)

// gateUserBridgeFee refuses a bridge transfer whose declared fee does not meet
// the chain's declared floor (LP-0130 §8: B-Chain fees). Called on the user-tx
// entry before any M-Chain signing capacity is consumed.
func (vm *VM) gateUserBridgeFee(paid uint64) error { return vm.fee.Admit(paid) }

// FeePolicy exposes the chain's declared fee policy for diagnostics and the
// boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.fee.Policy() }

// mpcGroupPublicKey returns the serialized CGGMP21 custody group public key
// (established by M-Chain's dealerless keygen), or nil if there is not one.
// B-Chain never holds a custody secret — only this public point.
//
// A group with no shares in it sums to the identity, which marshals to a
// perfectly well-formed 33 bytes. Handing that back as a key made an empty
// config look like a finished keygen: the node reported itself ready to
// attest, and bridge_getInfo said the same, on a chain that could verify
// nothing. The identity is not a key.
func (vm *VM) mpcGroupPublicKey() []byte {
	if vm.mpcConfig == nil {
		return nil
	}
	pt := vm.mpcConfig.PublicPoint()
	if pt == nil || pt.IsIdentity() {
		return nil
	}
	b, err := pt.MarshalBinary()
	if err != nil {
		return nil
	}
	return b
}
