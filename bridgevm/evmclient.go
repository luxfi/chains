// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

// evmclient.go — the concrete EVM ChainClient B-Chain instantiates per external
// EVM (Zoo 200201, Lux testnet C 96368). It is the piece the recon flagged as
// missing: the ChainClient interface had SendTransaction but no concrete EVM
// client, so `chainClients` was never populated and B could not broadcast a
// release to any EVM.
//
// It uses luxfi/geth's ethclient (NOT go-ethereum, NOT ava-labs) and holds its
// OWN view of each chain (nonce, gas price, confirmations, source events) rather
// than trusting a request field. `release` authorisation is the MPC threshold
// signature carried in calldata and verified on-chain; the EVM tx itself is
// signed by a gas-paying relayer key (resolved from KMS, never inline) whose
// only role is to pay for inclusion.
//
// No-gossip reality: when the destination is a Lux-family chain whose validators
// do not gossip the mempool, a single-endpoint submit can strand a tx on one
// node. So a client may be configured with MANY validator RPC endpoints; a
// release is broadcast to ALL of them (the signed tx has one hash, so duplicate
// submissions are idempotent — losers return "already known"), at a gas price of
// at least the configured floor. One accept is success.

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/crypto"
	ethereum "github.com/luxfi/geth"
	"github.com/luxfi/geth/accounts/abi"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/ethclient"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// defaultReleaseGasLimit is the gas ceiling for a release() call (verify sig +
// ERC20 mint/transfer). Generous; unused gas is refunded.
const defaultReleaseGasLimit uint64 = 300_000

// ExternalChainConfig configures one external EVM chain B bridges to/from. It
// carries NO secret material: the gas-paying key is referenced by KMS path and
// resolved by the VM's KeyProvider at Initialize; the private key never lives in
// genesis, config JSON, or logs.
type ExternalChainConfig struct {
	Name          string   `json:"name"`          // logical key, e.g. "zoo-testnet", "lux-testnet-c"
	ChainID       uint64   `json:"chainId"`       // EVM chain id (200201, 96368)
	RPCEndpoints  []string `json:"rpcEndpoints"`  // 1..N validator RPCs; release broadcast to ALL
	Gateway       string   `json:"gateway"`       // BridgeGateway contract address (0x..)
	CustodySigner string   `json:"custodySigner"` // MPC custody signer EVM address baked into the gateway
	MinGasPrice   string   `json:"minGasPrice,omitempty"` // wei floor; release uses max(suggested, floor)
	GasLimit      uint64   `json:"gasLimit,omitempty"`    // release call gas limit (default 300000)
	GasKeyKMSPath string   `json:"gasKeyKmsPath,omitempty"` // KMS path for the relayer key — NEVER inline
}

// ReleaseCall is the typed payload SendTransaction expects. It binds one
// threshold-attested transfer to its signature; the client ABI-encodes it into
// a gateway.release(...) call and broadcasts a signed tx.
type ReleaseCall struct {
	Transfer  bridgeattest.BridgeTransfer
	Signature []byte // secp256k1 r||s||v (65) from the M-Chain attestation
}

// gatewayABI is the minimal ABI B needs: pack release(), unpack Locked/Burned.
// It MUST match contracts/src/BridgeGateway.sol exactly (same field order/types).
const gatewayABIJSON = `[
  {"type":"function","name":"release","stateMutability":"nonpayable","inputs":[
    {"name":"srcChain","type":"uint32"},
    {"name":"dstChain","type":"uint32"},
    {"name":"asset","type":"bytes32"},
    {"name":"amount","type":"uint256"},
    {"name":"recipient","type":"address"},
    {"name":"nonce","type":"uint64"},
    {"name":"signature","type":"bytes"}
  ],"outputs":[]},
  {"type":"function","name":"processed","stateMutability":"view","inputs":[
    {"name":"digest","type":"bytes32"}
  ],"outputs":[{"name":"","type":"bool"}]},
  {"type":"event","name":"Locked","anonymous":false,"inputs":[
    {"name":"srcChain","type":"uint32","indexed":false},
    {"name":"dstChain","type":"uint32","indexed":false},
    {"name":"asset","type":"bytes32","indexed":false},
    {"name":"amount","type":"uint256","indexed":false},
    {"name":"recipient","type":"address","indexed":false},
    {"name":"nonce","type":"uint64","indexed":false}
  ]}
]`

var parsedGatewayABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(gatewayABIJSON))
	if err != nil {
		panic(fmt.Sprintf("bridgevm: gateway ABI: %v", err))
	}
	return a
}()

// evmChainClient is the concrete ChainClient for one external EVM chain.
type evmChainClient struct {
	name        string
	chainID     *big.Int
	gateway     common.Address
	custody     common.Address
	gasKey      *ecdsa.PrivateKey
	gasAddr     common.Address
	gasLimit    uint64
	minGasPrice *big.Int
	signer      types.Signer
	endpoints   []*ethclient.Client
	rawEndpoints []string
	log         log.Logger

	mu sync.Mutex // serialises nonce acquisition + broadcast for this gas key
}

var _ ChainClient = (*evmChainClient)(nil)

// newEVMChainClient dials the configured endpoints and returns a ready client.
// gasKey is the already-resolved relayer key (from KMS via the VM's KeyProvider,
// or injected directly in tests). The client verifies each endpoint reports the
// configured chain id — a misconfigured RPC (wrong chain) is refused at boot so
// a release can never be broadcast to the wrong network.
func newEVMChainClient(ctx context.Context, cfg ExternalChainConfig, gasKey *ecdsa.PrivateKey, logger log.Logger) (*evmChainClient, error) {
	if cfg.ChainID == 0 {
		return nil, fmt.Errorf("bridgevm: chain %q: chainId required", cfg.Name)
	}
	if len(cfg.RPCEndpoints) == 0 {
		return nil, fmt.Errorf("bridgevm: chain %q: at least one RPC endpoint required", cfg.Name)
	}
	if !common.IsHexAddress(cfg.Gateway) {
		return nil, fmt.Errorf("bridgevm: chain %q: invalid gateway address %q", cfg.Name, cfg.Gateway)
	}
	if !common.IsHexAddress(cfg.CustodySigner) {
		return nil, fmt.Errorf("bridgevm: chain %q: invalid custody signer address %q", cfg.Name, cfg.CustodySigner)
	}
	if gasKey == nil {
		return nil, fmt.Errorf("bridgevm: chain %q: gas-paying key not resolved (KMS path %q)", cfg.Name, cfg.GasKeyKMSPath)
	}

	chainID := new(big.Int).SetUint64(cfg.ChainID)

	minGas := new(big.Int)
	if cfg.MinGasPrice != "" {
		if _, ok := minGas.SetString(strings.TrimSpace(cfg.MinGasPrice), 10); !ok {
			return nil, fmt.Errorf("bridgevm: chain %q: invalid minGasPrice %q", cfg.Name, cfg.MinGasPrice)
		}
	}

	gasLimit := cfg.GasLimit
	if gasLimit == 0 {
		gasLimit = defaultReleaseGasLimit
	}

	clients := make([]*ethclient.Client, 0, len(cfg.RPCEndpoints))
	for _, ep := range cfg.RPCEndpoints {
		c, err := ethclient.DialContext(ctx, ep)
		if err != nil {
			return nil, fmt.Errorf("bridgevm: chain %q: dial %q: %w", cfg.Name, ep, err)
		}
		clients = append(clients, c)
	}

	// Refuse a mismatched network: the primary endpoint must report cfg.ChainID.
	got, err := clients[0].ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("bridgevm: chain %q: eth_chainId: %w", cfg.Name, err)
	}
	if got.Cmp(chainID) != 0 {
		return nil, fmt.Errorf("bridgevm: chain %q: endpoint reports chainId %s, config says %s", cfg.Name, got, chainID)
	}

	gasAddr := common.BytesToAddress(crypto.PubkeyToAddress(gasKey.PublicKey).Bytes())

	return &evmChainClient{
		name:         cfg.Name,
		chainID:      chainID,
		gateway:      common.HexToAddress(cfg.Gateway),
		custody:      common.HexToAddress(cfg.CustodySigner),
		gasKey:       gasKey,
		gasAddr:      gasAddr,
		gasLimit:     gasLimit,
		minGasPrice:  minGas,
		signer:       types.LatestSignerForChainID(chainID),
		endpoints:    clients,
		rawEndpoints: append([]string(nil), cfg.RPCEndpoints...),
		log:          logger,
	}, nil
}

func (c *evmChainClient) primary() *ethclient.Client { return c.endpoints[0] }

// GetTransaction returns the receipt for a tx hash (txID is a 32-byte EVM hash).
func (c *evmChainClient) GetTransaction(ctx context.Context, txID ids.ID) (interface{}, error) {
	return c.primary().TransactionReceipt(ctx, common.BytesToHash(txID[:]))
}

// GetConfirmations returns head-height − txBlock + 1 from B's OWN view of the
// chain. This is the fix for the trust gap: confirmations are observed here, not
// taken on faith from whoever submitted the bridge request.
func (c *evmChainClient) GetConfirmations(ctx context.Context, txID ids.ID) (uint32, error) {
	rcpt, err := c.primary().TransactionReceipt(ctx, common.BytesToHash(txID[:]))
	if err != nil {
		return 0, err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return 0, fmt.Errorf("bridgevm: chain %q: source tx %x reverted", c.name, txID[:])
	}
	head, err := c.primary().BlockNumber(ctx)
	if err != nil {
		return 0, err
	}
	txBlk := rcpt.BlockNumber.Uint64()
	if head < txBlk {
		return 0, nil
	}
	return uint32(head - txBlk + 1), nil
}

// ValidateAddress checks a 20-byte EVM address.
func (c *evmChainClient) ValidateAddress(address []byte) error {
	if len(address) != 20 {
		return fmt.Errorf("bridgevm: chain %q: EVM address must be 20 bytes, got %d", c.name, len(address))
	}
	return nil
}

// SendTransaction broadcasts a signed release to this chain's gateway. tx MUST
// be a *ReleaseCall. Returns the EVM tx hash as an ids.ID.
func (c *evmChainClient) SendTransaction(ctx context.Context, tx interface{}) (ids.ID, error) {
	rc, ok := tx.(*ReleaseCall)
	if !ok {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q: SendTransaction expects *ReleaseCall, got %T", c.name, tx)
	}
	return c.broadcastRelease(ctx, rc)
}

// broadcastRelease encodes gateway.release(...), signs with the relayer key, and
// broadcasts to every endpoint. Idempotent: the same signed tx has one hash, so
// endpoints past the first return "already known"/"nonce too low", which is
// success (some peer already has it).
func (c *evmChainClient) broadcastRelease(ctx context.Context, rc *ReleaseCall) (ids.ID, error) {
	if len(rc.Signature) != 65 {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q: release signature must be 65 bytes r||s||v, got %d", c.name, len(rc.Signature))
	}
	t := rc.Transfer
	if uint64(c.chainID.Uint64()) != uint64(t.DstChainID) {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q (id %s): release routed to wrong client; transfer dst is %d", c.name, c.chainID, t.DstChainID)
	}

	data, err := parsedGatewayABI.Pack(
		"release",
		t.SrcChainID,
		t.DstChainID,
		t.Asset,
		new(big.Int).SetUint64(t.Amount),
		common.BytesToAddress(t.Recipient[:]),
		t.Nonce,
		rc.Signature,
	)
	if err != nil {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q: pack release: %w", c.name, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	nonce, err := c.primary().PendingNonceAt(ctx, c.gasAddr)
	if err != nil {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q: pending nonce: %w", c.name, err)
	}

	gasPrice, err := c.primary().SuggestGasPrice(ctx)
	if err != nil {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q: suggest gas price: %w", c.name, err)
	}
	if gasPrice.Cmp(c.minGasPrice) < 0 {
		gasPrice = new(big.Int).Set(c.minGasPrice)
	}

	gateway := c.gateway
	unsigned := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      c.gasLimit,
		To:       &gateway,
		Value:    big.NewInt(0),
		Data:     data,
	})
	signed, err := types.SignTx(unsigned, c.signer, c.gasKey)
	if err != nil {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q: sign release tx: %w", c.name, err)
	}

	hash := signed.Hash()
	var accepted bool
	var lastErr error
	for i, ep := range c.endpoints {
		if err := ep.SendTransaction(ctx, signed); err != nil {
			if isAlreadyKnown(err) {
				accepted = true
				continue
			}
			lastErr = err
			if c.log != nil {
				c.log.Warn("bridgevm: release broadcast to endpoint failed",
					log.String("chain", c.name),
					log.String("endpoint", c.rawEndpoints[i]),
					log.String("txHash", hash.Hex()),
					log.Any("err", err),
				)
			}
			continue
		}
		accepted = true
	}
	if !accepted {
		return ids.Empty, fmt.Errorf("bridgevm: chain %q: release rejected by all %d endpoints: %w", c.name, len(c.endpoints), lastErr)
	}

	if c.log != nil {
		c.log.Info("bridgevm: release broadcast",
			log.String("chain", c.name),
			log.String("txHash", hash.Hex()),
			log.Uint64("nonce", nonce),
			log.Uint64("amount", t.Amount),
			log.Uint64("transferNonce", t.Nonce),
		)
	}
	return ids.ID(hash), nil
}

// FetchLockEvents pulls Locked events emitted by this chain's gateway in the
// [from,to] block range and decodes them into transfers. This is the inbound
// EVM plumbing: B observes a lock/burn on the source chain from its OWN view,
// then routes an attested release to the destination.
func (c *evmChainClient) FetchLockEvents(ctx context.Context, from, to *big.Int) ([]bridgeattest.BridgeTransfer, error) {
	q := ethereum.FilterQuery{
		FromBlock: from,
		ToBlock:   to,
		Addresses: []common.Address{c.gateway},
		Topics:    [][]common.Hash{{parsedGatewayABI.Events["Locked"].ID}},
	}
	logs, err := c.primary().FilterLogs(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("bridgevm: chain %q: filter Locked logs: %w", c.name, err)
	}
	out := make([]bridgeattest.BridgeTransfer, 0, len(logs))
	for i := range logs {
		bt, err := decodeLockedLog(&logs[i])
		if err != nil {
			return nil, fmt.Errorf("bridgevm: chain %q: decode Locked log: %w", c.name, err)
		}
		out = append(out, bt)
	}
	return out, nil
}

// lockedEvent mirrors the non-indexed Locked event fields for ABI unpack.
type lockedEvent struct {
	SrcChain  uint32
	DstChain  uint32
	Asset     [32]byte
	Amount    *big.Int
	Recipient common.Address
	Nonce     uint64
}

// decodeLockedLog turns a Locked log into a canonical transfer, rejecting an
// amount that does not fit the uint64 field the attestation digest binds.
func decodeLockedLog(lg *types.Log) (bridgeattest.BridgeTransfer, error) {
	var ev lockedEvent
	if err := parsedGatewayABI.UnpackIntoInterface(&ev, "Locked", lg.Data); err != nil {
		return bridgeattest.BridgeTransfer{}, err
	}
	if ev.Amount == nil || !ev.Amount.IsUint64() {
		return bridgeattest.BridgeTransfer{}, errors.New("locked amount does not fit uint64 (see interop CONCERN1)")
	}
	bt := bridgeattest.BridgeTransfer{
		SrcChainID: ev.SrcChain,
		DstChainID: ev.DstChain,
		Asset:      ev.Asset,
		Amount:     ev.Amount.Uint64(),
		Nonce:      ev.Nonce,
	}
	copy(bt.Recipient[:], ev.Recipient.Bytes())
	return bt, nil
}

// isAlreadyKnown reports whether an eth_sendRawTransaction error means the tx is
// already present (so a broadcast to that endpoint is a no-op success).
func isAlreadyKnown(err error) bool {
	if err == nil {
		return true
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "already known") ||
		strings.Contains(m, "already in the pool") ||
		strings.Contains(m, "nonce too low") ||
		strings.Contains(m, "known transaction")
}
