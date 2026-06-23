// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"errors"

	"github.com/luxfi/ids"
)

// fakeChain is a REAL ChainVerifier backed by an in-memory snapshot of what exists
// on-chain. It is not a stub: it returns "real" only for entries that were
// explicitly seeded, and an error otherwise — so the registry's rejection paths
// (TestNoSyntheticAssetCanRegister, etc.) exercise genuine refusal, not a verifier
// rigged to always succeed. This is the in-test analogue of the production
// JSON-RPC / local-chain-state verifier.
type fakeChain struct {
	// erc20[networkID][cChainID][20-byte-addr-hex] = decimals
	erc20 map[uint32]map[ids.ID]map[string]uint8
	// native[networkID][cChainID] = decimals (presence == this is the real C-Chain)
	native map[uint32]map[ids.ID]uint8
	// utxo[networkID][sourceChainID][assetID] = decimals
	utxo map[uint32]map[ids.ID]map[ids.ID]uint8
}

func newFakeChain() *fakeChain {
	return &fakeChain{
		erc20:  map[uint32]map[ids.ID]map[string]uint8{},
		native: map[uint32]map[ids.ID]uint8{},
		utxo:   map[uint32]map[ids.ID]map[ids.ID]uint8{},
	}
}

// seedERC20 records a real ERC-20 deployment at addr on (networkID, cChainID).
func (f *fakeChain) seedERC20(networkID uint32, cChainID ids.ID, addr []byte, decimals uint8) {
	if f.erc20[networkID] == nil {
		f.erc20[networkID] = map[ids.ID]map[string]uint8{}
	}
	if f.erc20[networkID][cChainID] == nil {
		f.erc20[networkID][cChainID] = map[string]uint8{}
	}
	f.erc20[networkID][cChainID][string(addr)] = decimals
}

// seedNative records that cChainID is the real C-Chain for networkID.
func (f *fakeChain) seedNative(networkID uint32, cChainID ids.ID, decimals uint8) {
	if f.native[networkID] == nil {
		f.native[networkID] = map[ids.ID]uint8{}
	}
	f.native[networkID][cChainID] = decimals
}

// seedUTXO records a real UTXO asset on (networkID, sourceChainID).
func (f *fakeChain) seedUTXO(networkID uint32, sourceChainID, assetID ids.ID, decimals uint8) {
	if f.utxo[networkID] == nil {
		f.utxo[networkID] = map[ids.ID]map[ids.ID]uint8{}
	}
	if f.utxo[networkID][sourceChainID] == nil {
		f.utxo[networkID][sourceChainID] = map[ids.ID]uint8{}
	}
	f.utxo[networkID][sourceChainID][assetID] = decimals
}

var errNotOnChain = errors.New("fakechain: no such object on this network/chain")

func (f *fakeChain) VerifyERC20(networkID uint32, cChainID ids.ID, addr []byte) (uint8, error) {
	d, ok := f.erc20[networkID][cChainID][string(addr)]
	if !ok {
		return 0, errNotOnChain
	}
	return d, nil
}

func (f *fakeChain) VerifyEVMNative(networkID uint32, cChainID ids.ID) (uint8, error) {
	d, ok := f.native[networkID][cChainID]
	if !ok {
		return 0, errNotOnChain
	}
	return d, nil
}

func (f *fakeChain) VerifyUTXOAsset(networkID uint32, sourceChainID, assetID ids.ID) (uint8, error) {
	d, ok := f.utxo[networkID][sourceChainID][assetID]
	if !ok {
		return 0, errNotOnChain
	}
	return d, nil
}

// addr20 builds a deterministic non-zero 20-byte token address from a seed byte.
func addr20(seed byte) []byte {
	b := make([]byte, 20)
	for i := range b {
		b[i] = seed + byte(i) + 1 // +1 keeps it non-zero even for seed 0
	}
	return b
}

// idBytes returns the 32-byte slice of an ids.ID. The parameter is a copy (and thus
// addressable), so this works on a function-return id where id[:] directly would not.
func idBytes(id ids.ID) []byte { return id[:] }
