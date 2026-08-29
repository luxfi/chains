// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

// security.go — the crossing path for paper that is a security.
//
// The fungible path releases by minting: a confirmed lock on the source
// authorises N units to an account on the destination, and nothing else has to
// be true. A security cannot land that way. Whether the position may exist on
// the destination at all is the destination register's question — is this holder
// verified, do their claims satisfy the token, does a holding period follow the
// paper across — and that question is asked by the token, in the block that
// lands it, not by this chain.
//
// So what B does here is narrower than what it does for a fungible asset. It
// carries a crossing that M has attested, and hands it to the destination
// register as an ARRIVAL. The register accepts or refuses on its own terms. B
// never decides that a security may land; it only decides that this attestation
// is genuine and says what it claims to say.

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/ids"
)

var (
	errSecurityHolderLen   = errors.New("bridgevm: security holder must be 20 bytes")
	errSecurityIdentityLen = errors.New("bridgevm: security identity must be 20 bytes")
	errSecurityNoDst       = errors.New("bridgevm: security crossing missing destination chain id")
	errSecurityNoQuantity  = errors.New("bridgevm: security crossing has no quantity")
	errSecurityQuantityBig = errors.New("bridgevm: security quantity exceeds uint256")
)

// SecurityRequest is a consensus record of a security leaving one register.
//
// Separate from BridgeRequest rather than a flag on it. The two are released by
// different calls onto the destination — a mint against a register that has not
// been asked anything is exactly the failure this path exists to prevent — and a
// type that could be either would leave that difference to a branch somebody has
// to remember to write.
type SecurityRequest struct {
	ID          ids.ID `json:"id"`
	SourceChain string `json:"sourceChain"`
	DestChain   string `json:"destChain"`

	SrcChainID uint32 `json:"srcChainId"`
	DstChainID uint32 `json:"dstChainId"`
	Nonce      uint64 `json:"nonce"`

	// Security is the canonical cross-chain id of the paper, not the token
	// address on either side: the same security has a different address on
	// every register it appears on.
	Security ids.ID `json:"security"`

	// Quantity is the full uint256 the source impounded. A uint64 would cap a
	// crossing at about 18.4 tokens at eighteen decimals.
	Quantity *big.Int `json:"quantity"`

	// Holder is the account the position lands on.
	Holder []byte `json:"holder"`

	// Identity is the holder's ONCHAINID on the SOURCE register, and Acquired
	// is when they first received there. Both travel because the destination
	// cannot ask the source anything, and both may be absent — a source that
	// registered no identity has none to send. Absent is not zero-as-a-value:
	// the destination reads them as unknown and applies its own rule.
	Identity []byte `json:"identity"`
	Acquired uint64 `json:"acquired"`

	SourceTxID    ids.ID              `json:"sourceTxId"`
	Confirmations uint32              `json:"confirmations"`
	Status        BridgeRequestStatus `json:"status"`
	CreatedAt     int64               `json:"createdAt"`
}

// crossing maps a consensus security request to the canonical, domain-bound
// value M signs and the destination register verifies.
//
// Everything the digest commits to is validated here rather than trusted: a
// malformed request that reached a signature would produce an attestation
// authorising an arrival nobody can make sense of.
func (r *SecurityRequest) crossing() (bridgeattest.SecurityCrossing, error) {
	var zero bridgeattest.SecurityCrossing

	if len(r.Holder) != 20 {
		return zero, fmt.Errorf("%w, got %d", errSecurityHolderLen, len(r.Holder))
	}
	if r.DstChainID == 0 {
		return zero, errSecurityNoDst
	}
	if r.Quantity == nil || r.Quantity.Sign() <= 0 {
		return zero, errSecurityNoQuantity
	}
	// FillBytes panics rather than truncating on overflow, and a silently
	// truncated quantity is a position that arrives smaller than it left.
	if r.Quantity.BitLen() > 256 {
		return zero, errSecurityQuantityBig
	}
	// An identity is twenty bytes or absent. A short one is a malformed request,
	// not an absence — treating it as absent would let a truncated field pass
	// for "this holder had no identity".
	if len(r.Identity) != 0 && len(r.Identity) != 20 {
		return zero, fmt.Errorf("%w, got %d", errSecurityIdentityLen, len(r.Identity))
	}

	var holder, identity [20]byte
	copy(holder[:], r.Holder)
	copy(identity[:], r.Identity)

	var quantity [32]byte
	r.Quantity.FillBytes(quantity[:])

	return bridgeattest.SecurityCrossing{
		SrcChainID: r.SrcChainID,
		DstChainID: r.DstChainID,
		Security:   [32]byte(r.Security),
		Quantity:   quantity,
		Holder:     holder,
		Identity:   identity,
		Acquired:   r.Acquired,
		Nonce:      r.Nonce,
	}, nil
}
