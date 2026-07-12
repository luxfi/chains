// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/zap"
)

func TestWireRoundTrip_Operation(t *testing.T) {
	require := require.New(t)
	op := &Operation{
		Type: OpTypeSign, SessionID: "sess-1", KeyID: "key-1",
		Protocol: "cggmp21", RequestingChain: "C",
		MessageHash: []byte("hash"), Signature: []byte("sig"),
		Timestamp: 1_700_000_000, Success: true, Error: "",
	}
	b := marshalOperation(op)
	msg, err := zap.Parse(b)
	require.NoError(err)
	require.Equal(op, readOperation(msg.Root()))
}

func TestWireRoundTrip_Block(t *testing.T) {
	require := require.New(t)
	blk := &Block{
		ID_:            ids.ID{9}, // derived; must NOT affect wire
		ParentID_:      ids.ID{1, 2, 3},
		BlockHeight:    42,
		BlockTimestamp: 1_700_000_000,
		Operations: []*Operation{
			{Type: OpTypeKeygen, SessionID: "s1", KeyID: "k1", Timestamp: 1},
			{Type: OpTypeSign, SessionID: "s2", KeyID: "k2", MessageHash: []byte("m"), Success: true, Timestamp: 2},
		},
	}
	b, err := blk.Marshal()
	require.NoError(err)
	var got Block
	require.NoError(parseBlockBytes(b, &got))
	require.Equal(blk.ParentID_, got.ParentID_)
	require.Equal(blk.BlockHeight, got.BlockHeight)
	require.Equal(blk.BlockTimestamp, got.BlockTimestamp)
	require.Equal(blk.Operations, got.Operations)
	// canonical: trailing byte rejected
	require.Error(parseBlockBytes(append(b, 0), &got))
	// empty-operations block: Operations stays nil
	empty := &Block{ParentID_: ids.ID{5}, BlockHeight: 1}
	eb, err := empty.Marshal()
	require.NoError(err)
	var egot Block
	require.NoError(parseBlockBytes(eb, &egot))
	require.Nil(egot.Operations)
}

func TestWireRoundTrip_ManagedKey(t *testing.T) {
	require := require.New(t)
	k := &ManagedKey{
		KeyID: "key-1", KeyType: "secp256k1",
		PublicKey: []byte("pubkey"), Address: []byte("0xADDR"),
		Threshold: 2, TotalParties: 3, Generation: 5,
		CreatedAt:  time.Unix(1_700_000_000, 0).UTC(),
		LastUsedAt: time.Unix(1_700_000_500, 0).UTC(),
		SignCount:  17, Status: "active",
		PartyIDs: []party.ID{"p1", "p2", "p3"},
	}
	b, err := k.Marshal()
	require.NoError(err)
	var got ManagedKey
	require.NoError(parseManagedKey(b, &got))
	require.Equal(k, &got)
	require.Error(parseManagedKey(append(b, 0), &got))
}

func TestWireRoundTrip_CrossChainMPCRequest(t *testing.T) {
	require := require.New(t)
	r := &CrossChainMPCRequest{
		Type: "sign", RequestingChain: "C", KeyID: "key-1",
		KeyType: "secp256k1", MessageHash: []byte("h"), MessageType: "eth_sign",
	}
	b, err := r.Marshal()
	require.NoError(err)
	var got CrossChainMPCRequest
	require.NoError(parseCrossChainMPCRequest(b, &got))
	require.Equal(r, &got)
}
