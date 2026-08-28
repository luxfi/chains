// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func jsonBody(s string) io.Reader { return strings.NewReader(s) }

// TestServiceGetBlockAnswersOnlyForBlocksHeld. The block id comes off the wire,
// so the two ways it can be wrong — unparseable, and parseable but unknown —
// both have to be refusals rather than an empty reply that reads as a block.
func TestServiceGetBlockAnswersOnlyForBlocksHeld(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	svc := &Service{vm: vm}
	blk := advance(t, vm, 1)

	var reply GetBlockReply
	require.NoError(t, svc.GetBlock(nil, &GetBlockArgs{BlockID: blk.id.String()}, &reply))
	require.Equal(t, uint64(1), reply.Height)
	require.Equal(t, blk.timestamp.Unix(), reply.Timestamp)
	require.False(t, reply.QuantumSig, "blocks carry no stamp on the wire")

	require.Equal(t, blk.id.String(), reply.Block.ID)
	require.Equal(t, blk.parentID.String(), reply.Block.ParentID)
	require.Equal(t, blk.height, reply.Block.Height)

	require.Error(t, svc.GetBlock(nil, &GetBlockArgs{BlockID: "not-an-id"}, &reply))
	require.Error(t, svc.GetBlock(nil, &GetBlockArgs{BlockID: ids.GenerateTestID().String()}, &reply))
}

// TestServiceGenerateCoronaKeyHonoursTheSwitch: a chain running without Corona
// must not hand out Corona keys, and one running with it hands out a key of the
// width its algorithm says.
func TestServiceGenerateCoronaKeyHonoursTheSwitch(t *testing.T) {
	vm, _ := bootVM(t, quietConfig()) // Corona off
	svc := &Service{vm: vm}

	var reply GenerateCoronaKeyReply
	require.Error(t, svc.GenerateCoronaKey(nil, &GenerateCoronaKeyArgs{}, &reply))
	require.Empty(t, reply.PublicKey, "a refused request still produced key material")

	vm.Config.CoronaEnabled = true
	require.NoError(t, svc.GenerateCoronaKey(nil, &GenerateCoronaKeyArgs{}, &reply))
	require.Equal(t, vm.quantumSigner.GetPublicKeySize(), reply.KeySize)
	require.Len(t, reply.PublicKey, reply.KeySize*2, "the key is reported as hex")
}

// TestServiceVerifyQuantumSignature reports the verdict rather than failing the
// call: a caller asking whether a signature is good gets an answer either way,
// and the answer is the signer's.
func TestServiceVerifyQuantumSignature(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	svc := &Service{vm: vm}

	var reply VerifyQuantumSignatureReply
	require.Error(t, svc.VerifyQuantumSignature(nil,
		&VerifyQuantumSignatureArgs{Message: "m", Signature: json.RawMessage(`{}`)}, &reply),
		"stamps are off, so the endpoint refuses rather than answering")

	vm.Config.QuantumStampEnabled = true
	msg := []byte("the message that was signed")
	key, err := vm.quantumSigner.GenerateCoronaKey()
	require.NoError(t, err)
	sig, err := vm.quantumSigner.Sign(msg, key)
	require.NoError(t, err)
	raw, err := json.Marshal(sig)
	require.NoError(t, err)

	require.NoError(t, svc.VerifyQuantumSignature(nil,
		&VerifyQuantumSignatureArgs{Message: string(msg), Signature: raw}, &reply))
	require.True(t, reply.Valid)
	require.Equal(t, sig.Algorithm, reply.Algorithm)

	// The same signature over other bytes is not valid, and says so.
	require.NoError(t, svc.VerifyQuantumSignature(nil,
		&VerifyQuantumSignatureArgs{Message: "other bytes entirely", Signature: raw}, &reply))
	require.False(t, reply.Valid)

	// Bytes that are not a signature at all are a bad request, not a verdict.
	require.Error(t, svc.VerifyQuantumSignature(nil,
		&VerifyQuantumSignatureArgs{Message: "m", Signature: json.RawMessage(`not json`)}, &reply))
}

// TestServiceGetPendingTransactionsIsBounded. The limit comes off the wire, so
// a caller asking for everything must not be able to make the node serialize
// the whole mempool in one reply.
func TestServiceGetPendingTransactionsIsBounded(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	svc := &Service{vm: vm}

	for i := 0; i < 7; i++ {
		require.NoError(t, vm.txPool.AddTransaction(stampedTx(uint64(i), "op")))
	}

	var reply GetPendingTransactionsReply
	require.NoError(t, svc.GetPendingTransactions(nil, &GetPendingTransactionsArgs{Limit: 3}, &reply))
	require.Equal(t, 3, reply.Count)
	require.Len(t, reply.Transactions, 3)

	for _, limit := range []int{0, -1, 1 << 20} {
		require.NoError(t, svc.GetPendingTransactions(nil, &GetPendingTransactionsArgs{Limit: limit}, &reply))
		require.Equal(t, 7, reply.Count, "limit %d did not settle on the pool's size", limit)
	}

	require.NotEmpty(t, reply.Transactions[0].ID)
	require.Equal(t, chainTime.Unix(), reply.Transactions[0].Timestamp)
}

// TestServiceGetHealthAndConfigReportTheRunningVM, not a copy of the defaults.
func TestServiceGetHealthAndConfigReportTheRunningVM(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	svc := &Service{vm: vm}
	require.NoError(t, vm.txPool.AddTransaction(stampedTx(1, "op")))

	var health GetHealthReply
	require.NoError(t, svc.GetHealth(nil, &GetHealthArgs{}, &health))
	require.True(t, health.Healthy)
	require.Equal(t, Version, health.Version)
	require.Equal(t, 1, health.PendingTxCount)
	require.Equal(t, vm.Config.MaxParallelTxs, health.ParallelWorkers)
	require.False(t, health.QuantumEnabled)
	require.False(t, health.CoronaEnabled)

	var cfg GetConfigReply
	require.NoError(t, svc.GetConfig(nil, &GetConfigArgs{}, &cfg))
	require.Equal(t, vm.Config.MaxParallelTxs, cfg.MaxParallelTxs)
	require.Equal(t, vm.Config.ParallelBatchSize, cfg.ParallelBatchSize)
	require.Equal(t, vm.Config.QuantumAlgorithmVersion, cfg.QuantumAlgorithmVersion)

	// A shut-down VM says so rather than reporting itself healthy.
	require.NoError(t, vm.Shutdown(context.Background()))
	require.NoError(t, svc.GetHealth(nil, &GetHealthArgs{}, &health))
	require.False(t, health.Healthy)
}

// TestServiceRepliesCarryNoSecrets. GenerateCoronaKey mints a keypair; the
// caller gets the public half. The private half leaving here would hand every
// unauthenticated caller a validator identity.
func TestServiceRepliesCarryNoSecrets(t *testing.T) {
	vm, _ := bootVM(t, quietConfig())
	vm.Config.CoronaEnabled = true
	svc := &Service{vm: vm}

	var reply GenerateCoronaKeyReply
	require.NoError(t, svc.GenerateCoronaKey(nil, &GenerateCoronaKeyArgs{}, &reply))

	raw, err := json.Marshal(reply)
	require.NoError(t, err)
	require.NotContains(t, strings.ToLower(string(raw)), "private")

	// And the signature type the service echoes back holds no secret either.
	sigRaw, err := json.Marshal(&quantum.QuantumSignature{Signature: []byte{1}})
	require.NoError(t, err)
	require.NotContains(t, strings.ToLower(string(sigRaw)), "private")
}
