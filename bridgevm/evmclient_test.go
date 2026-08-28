// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/common/hexutil"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// The EVM client is where this chain touches money: it is the thing that
// broadcasts a release. These tests drive it against a real JSON-RPC endpoint
// — an httptest server speaking the subset of the protocol the client uses —
// so the wire encoding, the signing, and the endpoint fan-out are exercised
// rather than described.

// evmNode is an Ethereum JSON-RPC endpoint answering exactly what this client
// asks it.
type evmNode struct {
	mu sync.Mutex

	chainID   *big.Int
	head      uint64
	nonce     uint64
	gasPrice  *big.Int
	receipt   map[common.Hash]*types.Receipt
	logs      []types.Log
	processed bool

	sent    []*types.Transaction
	sendErr error
	fail    map[string]string // method -> error message
}

func newEVMNode(chainID uint64) *evmNode {
	return &evmNode{
		chainID:  new(big.Int).SetUint64(chainID),
		head:     1000,
		gasPrice: big.NewInt(1_000_000_000),
		receipt:  map[common.Hash]*types.Receipt{},
		fail:     map[string]string{},
	}
}

func (n *evmNode) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(n.handle))
	t.Cleanup(srv.Close)
	return srv.URL
}

type rpcCall struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

func (n *evmNode) handle(w http.ResponseWriter, r *http.Request) {
	var call rpcCall
	if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, rpcErr := n.answer(&call)
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(call.ID)}
	if rpcErr != "" {
		out["error"] = map[string]any{"code": -32000, "message": rpcErr}
	} else {
		out["result"] = result
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (n *evmNode) answer(call *rpcCall) (any, string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if msg, bad := n.fail[call.Method]; bad {
		return nil, msg
	}
	switch call.Method {
	case "eth_chainId":
		return hexutil.EncodeBig(n.chainID), ""
	case "eth_blockNumber":
		return hexutil.Uint64(n.head).String(), ""
	case "eth_gasPrice":
		return hexutil.EncodeBig(n.gasPrice), ""
	case "eth_getTransactionCount":
		return hexutil.Uint64(n.nonce).String(), ""
	case "eth_getTransactionReceipt":
		var h common.Hash
		_ = json.Unmarshal(call.Params[0], &h)
		rcpt, ok := n.receipt[h]
		if !ok {
			return nil, ""
		}
		return marshalReceipt(rcpt), ""
	case "eth_getLogs":
		return n.logs, ""
	case "eth_call":
		out := make([]byte, 32)
		if n.processed {
			out[31] = 1
		}
		return hexutil.Encode(out), ""
	case "eth_sendRawTransaction":
		if n.sendErr != nil {
			return nil, n.sendErr.Error()
		}
		var raw hexutil.Bytes
		_ = json.Unmarshal(call.Params[0], &raw)
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			return nil, err.Error()
		}
		n.sent = append(n.sent, tx)
		return tx.Hash(), ""
	}
	return nil, "unsupported method " + call.Method
}

// marshalReceipt renders the receipt fields ethclient reads back.
func marshalReceipt(r *types.Receipt) map[string]any {
	return map[string]any{
		"type":              hexutil.Uint64(0).String(),
		"status":            hexutil.Uint64(r.Status).String(),
		"cumulativeGasUsed": hexutil.Uint64(0).String(),
		"logsBloom":         hexutil.Bytes(make([]byte, 256)),
		"logs":              []any{},
		"transactionHash":   r.TxHash,
		"contractAddress":   nil,
		"gasUsed":           hexutil.Uint64(0).String(),
		"blockHash":         common.Hash{1},
		"blockNumber":       hexutil.EncodeBig(r.BlockNumber),
		"transactionIndex":  hexutil.Uint64(0).String(),
		"effectiveGasPrice": hexutil.Uint64(1).String(),
	}
}

func relayerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key
}

func chainCfg(name string, id uint64, endpoints ...string) ExternalChainConfig {
	return ExternalChainConfig{
		Name:          name,
		ChainID:       id,
		RPCEndpoints:  endpoints,
		Gateway:       "0x00000000000000000000000000000000000000aa",
		CustodySigner: "0x00000000000000000000000000000000000000bb",
		MinGasPrice:   "2000000000",
		GasKeyKMSPath: "kms://bridge/relayer",
	}
}

func dial(t *testing.T, node *evmNode, cfg ExternalChainConfig) *evmChainClient {
	t.Helper()
	c, err := newEVMChainClient(context.Background(), cfg, relayerKey(t), log.NewNoOpLogger())
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, ep := range c.endpoints {
			ep.Close()
		}
	})
	_ = node
	return c
}

// A client refuses a configuration it cannot act on, before it is wired to
// anything: a half-configured relayer that dials anyway broadcasts to the
// wrong place.
func TestAnEVMClientRefusesAConfigurationItCannotAct(t *testing.T) {
	ctx := context.Background()
	node := newEVMNode(uint64(dstChain))
	url := node.serve(t)
	key := relayerKey(t)

	base := chainCfg("zoo", uint64(dstChain), url)

	noID := base
	noID.ChainID = 0
	_, err := newEVMChainClient(ctx, noID, key, nil)
	require.ErrorContains(t, err, "chainId required")

	noEndpoints := base
	noEndpoints.RPCEndpoints = nil
	_, err = newEVMChainClient(ctx, noEndpoints, key, nil)
	require.ErrorContains(t, err, "at least one RPC endpoint")

	badGateway := base
	badGateway.Gateway = "not-an-address"
	_, err = newEVMChainClient(ctx, badGateway, key, nil)
	require.ErrorContains(t, err, "invalid gateway address")

	badCustody := base
	badCustody.CustodySigner = "not-an-address"
	_, err = newEVMChainClient(ctx, badCustody, key, nil)
	require.ErrorContains(t, err, "invalid custody signer")

	_, err = newEVMChainClient(ctx, base, nil, nil)
	require.ErrorContains(t, err, "gas-paying key not resolved")

	badGas := base
	badGas.MinGasPrice = "twelve"
	_, err = newEVMChainClient(ctx, badGas, key, nil)
	require.ErrorContains(t, err, "invalid minGasPrice")

	unreachable := base
	unreachable.RPCEndpoints = []string{"http://127.0.0.1:1/"}
	_, err = newEVMChainClient(ctx, unreachable, key, nil)
	require.Error(t, err)
}

// TestAnEVMClientRefusesTheWrongNetwork. A relayer pointed at the wrong RPC
// would sign releases for one chain and broadcast them on another.
func TestAnEVMClientRefusesTheWrongNetwork(t *testing.T) {
	node := newEVMNode(999)
	cfg := chainCfg("zoo", uint64(dstChain), node.serve(t))
	_, err := newEVMChainClient(context.Background(), cfg, relayerKey(t), nil)
	require.ErrorContains(t, err, "endpoint reports chainId")

	node.fail["eth_chainId"] = "no"
	_, err = newEVMChainClient(context.Background(), cfg, relayerKey(t), nil)
	require.ErrorContains(t, err, "eth_chainId")
}

// A release is broadcast to every endpoint, because a Lux-family destination
// may not gossip its mempool: one accept is success.
func TestAReleaseIsBroadcastToEveryEndpoint(t *testing.T) {
	node := newEVMNode(uint64(dstChain))
	url := node.serve(t)
	cfg := chainCfg("zoo", uint64(dstChain), url, url, url)
	c := dial(t, node, cfg)

	transfer := transferFor(1, 5_000)
	txID, err := c.SendTransaction(context.Background(), &ReleaseCall{
		Transfer:  transfer,
		Signature: make([]byte, 65),
	})
	require.NoError(t, err)
	require.NotEqual(t, ids.Empty, txID)

	node.mu.Lock()
	defer node.mu.Unlock()
	require.Len(t, node.sent, 3, "one endpoint was not told")
	tx := node.sent[0]
	require.Equal(t, c.gateway, *tx.To())
	require.Equal(t, ids.ID(tx.Hash()), txID)

	// The gas price is at least the configured floor.
	require.GreaterOrEqual(t, tx.GasPrice().Int64(), int64(2_000_000_000))

	// And the calldata is the transfer, so what was signed is what is released.
	args, err := parsedGatewayABI.Methods["release"].Inputs.Unpack(tx.Data()[4:])
	require.NoError(t, err)
	require.Equal(t, transfer.SrcChainID, args[0])
	require.Equal(t, transfer.DstChainID, args[1])
	require.Equal(t, transfer.Amount, args[3].(*big.Int).Uint64())
	require.Equal(t, common.BytesToAddress(transfer.Recipient[:]), args[4])
	require.Equal(t, transfer.Nonce, args[5])
}

// TestAReleaseIsNotBroadcastToTheWrongChain. The client holds its own chain
// id, so a transfer routed to it by mistake is refused rather than released
// on a network the attestation does not authorise.
func TestAReleaseIsNotBroadcastToTheWrongChain(t *testing.T) {
	node := newEVMNode(uint64(dstChain))
	c := dial(t, node, chainCfg("zoo", uint64(dstChain), node.serve(t)))

	misrouted := transferFor(1, 5_000)
	misrouted.DstChainID = 4242
	_, err := c.SendTransaction(context.Background(), &ReleaseCall{
		Transfer: misrouted, Signature: make([]byte, 65),
	})
	require.ErrorContains(t, err, "wrong client")
	require.Empty(t, node.sent)
}

func TestAReleaseNeedsASignatureOfTheRightShape(t *testing.T) {
	node := newEVMNode(uint64(dstChain))
	c := dial(t, node, chainCfg("zoo", uint64(dstChain), node.serve(t)))

	for _, n := range []int{0, 64, 66} {
		_, err := c.SendTransaction(context.Background(), &ReleaseCall{
			Transfer: transferFor(1, 5_000), Signature: make([]byte, n),
		})
		require.ErrorContains(t, err, "must be 65 bytes")
	}

	_, err := c.SendTransaction(context.Background(), "not a release call")
	require.ErrorContains(t, err, "expects *ReleaseCall")
	require.Empty(t, node.sent)
}

// An endpoint that already has the transaction is not a failure: the signed
// transaction has one hash, so a duplicate submit is a no-op success.
func TestAlreadyKnownIsSuccess(t *testing.T) {
	require.True(t, isAlreadyKnown(nil))
	for _, msg := range []string{
		"already known", "ALREADY KNOWN", "already in the pool",
		"nonce too low", "known transaction: 0xabc",
	} {
		require.True(t, isAlreadyKnown(errors.New(msg)), msg)
	}
	require.False(t, isAlreadyKnown(errors.New("insufficient funds")))
}

func TestAReleaseRefusedByEveryEndpointIsAnError(t *testing.T) {
	node := newEVMNode(uint64(dstChain))
	url := node.serve(t)
	c := dial(t, node, chainCfg("zoo", uint64(dstChain), url, url))

	node.mu.Lock()
	node.sendErr = errors.New("insufficient funds for gas")
	node.mu.Unlock()

	_, err := c.SendTransaction(context.Background(), &ReleaseCall{
		Transfer: transferFor(1, 5_000), Signature: make([]byte, 65),
	})
	require.ErrorContains(t, err, "rejected by all 2 endpoints")

	// One endpoint saying it already has it is enough.
	node.mu.Lock()
	node.sendErr = errors.New("already known")
	node.mu.Unlock()
	_, err = c.SendTransaction(context.Background(), &ReleaseCall{
		Transfer: transferFor(1, 5_000), Signature: make([]byte, 65),
	})
	require.NoError(t, err)
}

func TestABroadcastNeedsANonceAndAGasPrice(t *testing.T) {
	node := newEVMNode(uint64(dstChain))
	c := dial(t, node, chainCfg("zoo", uint64(dstChain), node.serve(t)))
	call := &ReleaseCall{Transfer: transferFor(1, 5_000), Signature: make([]byte, 65)}

	node.mu.Lock()
	node.fail["eth_getTransactionCount"] = "no"
	node.mu.Unlock()
	_, err := c.SendTransaction(context.Background(), call)
	require.ErrorContains(t, err, "pending nonce")

	node.mu.Lock()
	delete(node.fail, "eth_getTransactionCount")
	node.fail["eth_gasPrice"] = "no"
	node.mu.Unlock()
	_, err = c.SendTransaction(context.Background(), call)
	require.ErrorContains(t, err, "suggest gas price")
}

// TestConfirmationsComeFromThisNodesOwnView is the trust gap this client
// closed: the depth of a source lock is read here, not taken from whoever
// submitted the request.
func TestConfirmationsComeFromThisNodesOwnView(t *testing.T) {
	node := newEVMNode(uint64(srcChain))
	c := dial(t, node, chainCfg("lux", uint64(srcChain), node.serve(t)))

	txHash := common.Hash{0xAB}
	node.mu.Lock()
	node.head = 1_000
	node.receipt[txHash] = &types.Receipt{
		Status: types.ReceiptStatusSuccessful, TxHash: txHash, BlockNumber: big.NewInt(990),
	}
	node.mu.Unlock()

	conf, err := c.GetConfirmations(context.Background(), ids.ID(txHash))
	require.NoError(t, err)
	require.Equal(t, uint32(11), conf)

	rcpt, err := c.GetTransaction(context.Background(), ids.ID(txHash))
	require.NoError(t, err)
	require.NotNil(t, rcpt)

	head, err := c.HeadBlock(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(1_000), head)

	// A receipt this node has not seen is not zero confirmations, it is an
	// unanswerable question.
	_, err = c.GetConfirmations(context.Background(), ids.GenerateTestID())
	require.Error(t, err)
}

// A reverted lock never happened, so its depth is not a number to compare.
func TestARevertedSourceTransactionHasNoConfirmations(t *testing.T) {
	node := newEVMNode(uint64(srcChain))
	c := dial(t, node, chainCfg("lux", uint64(srcChain), node.serve(t)))

	txHash := common.Hash{0xCD}
	node.mu.Lock()
	node.receipt[txHash] = &types.Receipt{
		Status: types.ReceiptStatusFailed, TxHash: txHash, BlockNumber: big.NewInt(10),
	}
	node.mu.Unlock()

	_, err := c.GetConfirmations(context.Background(), ids.ID(txHash))
	require.ErrorContains(t, err, "reverted")
}

// A chain whose head this node cannot read reports nothing rather than zero.
func TestAnUnreadableHeadIsAnError(t *testing.T) {
	node := newEVMNode(uint64(srcChain))
	c := dial(t, node, chainCfg("lux", uint64(srcChain), node.serve(t)))

	txHash := common.Hash{0xEF}
	node.mu.Lock()
	node.receipt[txHash] = &types.Receipt{
		Status: types.ReceiptStatusSuccessful, TxHash: txHash, BlockNumber: big.NewInt(10),
	}
	node.fail["eth_blockNumber"] = "no"
	node.mu.Unlock()

	_, err := c.GetConfirmations(context.Background(), ids.ID(txHash))
	require.Error(t, err)
	_, err = c.HeadBlock(context.Background())
	require.Error(t, err)
}

// A receipt from a block the node has not caught up to yet is zero deep, not
// a negative number wrapped into a very large one.
func TestAReceiptAheadOfTheHeadIsZeroDeep(t *testing.T) {
	node := newEVMNode(uint64(srcChain))
	c := dial(t, node, chainCfg("lux", uint64(srcChain), node.serve(t)))

	txHash := common.Hash{0x11}
	node.mu.Lock()
	node.head = 5
	node.receipt[txHash] = &types.Receipt{
		Status: types.ReceiptStatusSuccessful, TxHash: txHash, BlockNumber: big.NewInt(99),
	}
	node.mu.Unlock()

	conf, err := c.GetConfirmations(context.Background(), ids.ID(txHash))
	require.NoError(t, err)
	require.Zero(t, conf)
}

func TestValidateAddress(t *testing.T) {
	node := newEVMNode(uint64(dstChain))
	c := dial(t, node, chainCfg("zoo", uint64(dstChain), node.serve(t)))
	require.NoError(t, c.ValidateAddress(make([]byte, 20)))
	require.ErrorContains(t, c.ValidateAddress(make([]byte, 19)), "20 bytes")
	require.ErrorContains(t, c.ValidateAddress(nil), "20 bytes")
}

// TestLockedEventsAreDecodedFromTheChain is the inbound half: a Locked event
// becomes the exact transfer the digest binds.
func TestLockedEventsAreDecodedFromTheChain(t *testing.T) {
	node := newEVMNode(uint64(srcChain))
	c := dial(t, node, chainCfg("lux", uint64(srcChain), node.serve(t)))

	want := transferFor(77, 4_242)
	node.mu.Lock()
	node.logs = []types.Log{lockedLog(t, want, 900, common.Hash{0x55})}
	node.mu.Unlock()

	locks, err := c.FetchLockEvents(context.Background(), big.NewInt(1), big.NewInt(1000))
	require.NoError(t, err)
	require.Len(t, locks, 1)
	require.Equal(t, want, locks[0].Transfer)
	require.Equal(t, uint64(900), locks[0].Block)
	require.Equal(t, ids.ID(common.Hash{0x55}), locks[0].TxID)

	node.mu.Lock()
	node.fail["eth_getLogs"] = "no"
	node.mu.Unlock()
	_, err = c.FetchLockEvents(context.Background(), big.NewInt(1), big.NewInt(2))
	require.ErrorContains(t, err, "filter Locked logs")
}

// An amount that does not fit the width the attestation digest binds cannot be
// carried, and reading it as its low 64 bits would authorise a different
// transfer than the one that was locked.
func TestALockedAmountMustFitTheDigest(t *testing.T) {
	node := newEVMNode(uint64(srcChain))
	c := dial(t, node, chainCfg("lux", uint64(srcChain), node.serve(t)))

	huge := new(big.Int).Lsh(big.NewInt(1), 70)
	node.mu.Lock()
	node.logs = []types.Log{lockedLogAmount(t, transferFor(1, 0), huge, 900, common.Hash{0x66})}
	node.mu.Unlock()

	_, err := c.FetchLockEvents(context.Background(), big.NewInt(1), big.NewInt(1000))
	require.ErrorContains(t, err, "decode Locked log")

	// And bytes that are not a Locked event at all.
	_, err = decodeLockedLog(&types.Log{Data: []byte{1, 2, 3}})
	require.Error(t, err)
}

// TestIsProcessedAsksTheGateway is the on-chain replay guard, read before any
// attestation is requested.
func TestIsProcessedAsksTheGateway(t *testing.T) {
	node := newEVMNode(uint64(dstChain))
	c := dial(t, node, chainCfg("zoo", uint64(dstChain), node.serve(t)))
	transfer := transferFor(1, 5_000)

	done, err := c.IsProcessed(context.Background(), transfer)
	require.NoError(t, err)
	require.False(t, done)

	node.mu.Lock()
	node.processed = true
	node.mu.Unlock()
	done, err = c.IsProcessed(context.Background(), transfer)
	require.NoError(t, err)
	require.True(t, done)

	node.mu.Lock()
	node.fail["eth_call"] = "no"
	node.mu.Unlock()
	_, err = c.IsProcessed(context.Background(), transfer)
	require.ErrorContains(t, err, "eth_call processed")
}

// An answer the gateway ABI cannot read is not a "no": it is an unanswered
// question, and treating it as "not processed" would release again.
func TestAnUnreadableProcessedAnswerIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call rpcCall
		_ = json.NewDecoder(r.Body).Decode(&call)
		result := any(hexutil.Encode(make([]byte, 32)))
		if call.Method == "eth_chainId" {
			result = hexutil.EncodeBig(new(big.Int).SetUint64(uint64(dstChain)))
		} else if call.Method == "eth_call" {
			result = "0x00" // one byte: not a bool
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": json.RawMessage(call.ID), "result": result,
		})
	}))
	defer srv.Close()

	c, err := newEVMChainClient(context.Background(),
		chainCfg("zoo", uint64(dstChain), srv.URL), relayerKey(t), log.NewNoOpLogger())
	require.NoError(t, err)
	defer func() {
		for _, ep := range c.endpoints {
			ep.Close()
		}
	}()

	_, err = c.IsProcessed(context.Background(), transferFor(1, 5_000))
	require.ErrorContains(t, err, "unpack processed")
}

// lockedLog renders a Locked event the way the gateway emits it.
func lockedLog(t *testing.T, bt bridgeattest.BridgeTransfer, block uint64, tx common.Hash) types.Log {
	t.Helper()
	return lockedLogAmount(t, bt, new(big.Int).SetUint64(bt.Amount), block, tx)
}

func lockedLogAmount(t *testing.T, bt bridgeattest.BridgeTransfer, amount *big.Int, block uint64, tx common.Hash) types.Log {
	t.Helper()
	ev := parsedGatewayABI.Events["Locked"]
	data, err := ev.Inputs.Pack(bt.SrcChainID, bt.DstChainID, bt.Asset, amount,
		common.BytesToAddress(bt.Recipient[:]), bt.Nonce)
	require.NoError(t, err)
	return types.Log{
		Address:     common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		Topics:      []common.Hash{ev.ID},
		Data:        data,
		BlockNumber: block,
		TxHash:      tx,
	}
}

// The gateway ABI this client packs against must be the one the contract
// exposes; a drift here is a release call the gateway rejects, or worse, one
// it reads differently.
func TestTheGatewayABIIsTheContractsABI(t *testing.T) {
	require.Contains(t, parsedGatewayABI.Methods, "release")
	require.Contains(t, parsedGatewayABI.Methods, "processed")
	require.Contains(t, parsedGatewayABI.Events, "Locked")

	release := parsedGatewayABI.Methods["release"]
	var got []string
	for _, in := range release.Inputs {
		got = append(got, in.Type.String())
	}
	require.Equal(t, []string{"uint32", "uint32", "bytes32", "uint256", "address", "uint64", "bytes"}, got)

	locked := parsedGatewayABI.Events["Locked"]
	got = got[:0]
	for _, in := range locked.Inputs {
		got = append(got, in.Type.String())
		require.False(t, in.Indexed, "an indexed field is not in the log data this client decodes")
	}
	require.Equal(t, []string{"uint32", "uint32", "bytes32", "uint256", "address", "uint64"}, got)
}

func TestReleaseCallStringer(t *testing.T) {
	// The client names itself in every error, so an operator reading a log
	// knows which chain refused.
	node := newEVMNode(uint64(dstChain))
	c := dial(t, node, chainCfg("zoo-testnet", uint64(dstChain), node.serve(t)))
	_, err := c.SendTransaction(context.Background(), 42)
	require.ErrorContains(t, err, "zoo-testnet")
	require.Equal(t, fmt.Sprintf("%s", "zoo-testnet"), c.name)
	require.NotNil(t, c.primary())
	require.False(t, strings.Contains(c.name, "kms"))
}
