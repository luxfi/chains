// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client reads one M-Chain node over its JSON-RPC endpoint: the custody
// registry, the ceremony log, the state root, and what the node itself is.
type Client struct {
	endpoint   string
	chainID    string // Requesting chain's ID
	httpClient *http.Client
}

// NewClient builds a client bound to one endpoint, identifying itself as
// chainID for the RPCs that report per-chain quota.
func NewClient(endpoint, chainID string) *Client {
	return &Client{
		endpoint: endpoint,
		chainID:  chainID,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// RPCClient wraps the underlying transport for JSON-RPC calls
type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (c *Client) call(ctx context.Context, method string, params interface{}, result interface{}) error {
	reqBody := rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/rpc", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if result != nil && len(rpcResp.Result) > 0 {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return nil
}

// =============================================================================
// Ceremonies
// =============================================================================

// CeremonyInfo is one ceremony as the chain records it: what was signed, by
// whom, and the signature it produced. It is the shape returned both by a
// ceremony that just ran and by a lookup in the replicated ceremony log, so a
// caller parses one thing.
//
// Height is 0 for a ceremony that has completed but whose block has not been
// accepted yet — the signature is valid, it just has no place in history yet.
type CeremonyInfo struct {
	CeremonyID string `json:"ceremonyId"`
	Kind       string `json:"kind"` // keygen | sign
	KeyID      string `json:"keyId"`
	Digest     string `json:"digest"`    // 0x-hex, 32 bytes
	Signature  string `json:"signature"` // 0x-hex, 65 bytes r‖s‖v
	R          string `json:"r,omitempty"`
	S          string `json:"s,omitempty"`
	V          int    `json:"v,omitempty"`
	// Signers is the participating quorum, canonically ordered.
	Signers         []string `json:"signers"`
	RequestingChain string   `json:"requestingChain,omitempty"`
	Height          uint64   `json:"height,omitempty"`
}

// This client READS. It does not run ceremonies: a ceremony is requested BY a
// chain over the cross-chain transport that authenticates which chain is
// asking, and HTTP authenticates nobody. There were a Keygen and a Sign method
// here calling threshold_keygen and threshold_sign, which the server refuses
// unconditionally — two entry points that could only ever return an error, and
// an invitation to make the server stop refusing.

// GetCeremony reads one recorded ceremony from replicated state.
func (c *Client) GetCeremony(ctx context.Context, ceremonyID string) (*CeremonyInfo, error) {
	var result CeremonyInfo
	if err := c.call(ctx, "mpc_getCeremony", map[string]string{"ceremonyId": ceremonyID}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListCeremonies reads the whole ceremony log.
func (c *Client) ListCeremonies(ctx context.Context) ([]CeremonyInfo, error) {
	var result []CeremonyInfo
	if err := c.call(ctx, "mpc_listCeremonies", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// StateRoot returns the chain's custody state root — the value two validators
// compare to know whether they agree about custody.
func (c *Client) StateRoot(ctx context.Context) (string, error) {
	var result map[string]string
	if err := c.call(ctx, "mpc_getStateRoot", nil, &result); err != nil {
		return "", err
	}
	return result["stateRoot"], nil
}

// =============================================================================
// Custody registry
// =============================================================================

// KeyInfo is a custody key's replicated public record. It carries no secret and
// no per-node bookkeeping: every field here is identical on every validator.
type KeyInfo struct {
	KeyID string `json:"keyId"`
	Kind  string `json:"kind"` // threshold protocol that generated it, e.g. cggmp21
	// Policy is the operator form, "3-of-5". Degree is the polynomial degree
	// (K-1) it was generated with, reported so the two can be checked against
	// each other rather than inferred.
	Policy         string   `json:"policy"`
	Degree         int      `json:"degree"`
	GroupPublicKey string   `json:"groupPublicKey"` // 0x-hex, 33-byte compressed
	Address        string   `json:"address"`        // 0x-hex, 20-byte custody address
	Participants   []string `json:"participants"`
	Generation     uint64   `json:"generation"`
	CreatedHeight  uint64   `json:"createdHeight"`
}

// ListKeys lists every registered custody key.
func (c *Client) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	var result []KeyInfo
	if err := c.call(ctx, "mpc_listKeys", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetKey retrieves one custody key's record.
func (c *Client) GetKey(ctx context.Context, keyID string) (*KeyInfo, error) {
	var result KeyInfo
	if err := c.call(ctx, "mpc_getKey", map[string]string{"keyId": keyID}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPublicKey retrieves the public key for a key ID
func (c *Client) GetPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	params := map[string]string{
		"keyId": keyID,
	}

	var result map[string]string
	if err := c.call(ctx, "threshold_getPublicKey", params, &result); err != nil {
		return nil, err
	}

	pubKeyHex := result["publicKey"]
	if len(pubKeyHex) >= 2 && pubKeyHex[:2] == "0x" {
		pubKeyHex = pubKeyHex[2:]
	}

	return hex.DecodeString(pubKeyHex)
}

// GetAddress retrieves the address for a key ID
func (c *Client) GetAddress(ctx context.Context, keyID string) ([]byte, error) {
	params := map[string]string{
		"keyId": keyID,
	}

	var result map[string]string
	if err := c.call(ctx, "threshold_getAddress", params, &result); err != nil {
		return nil, err
	}

	addrHex := result["address"]
	if len(addrHex) >= 2 && addrHex[:2] == "0x" {
		addrHex = addrHex[2:]
	}

	return hex.DecodeString(addrHex)
}

// =============================================================================
// Network Information
// =============================================================================

// ThresholdInfo describes one M-Chain node: what the chain agrees on (policy,
// authorized chains, key count, state root) and what is true of THIS node
// (party id, shares held, staged ceremonies). The two are reported separately
// because conflating them is how an operator concludes the chain is broken
// when in fact this one validator holds no share.
type ThresholdInfo struct {
	Version          string   `json:"version"`
	NodeID           string   `json:"nodeId"`
	ChainID          string   `json:"chainId"`
	PartyID          string   `json:"partyId"`
	Policy           string   `json:"policy"` // default quorum, "3-of-5"
	AuthorizedChains []string `json:"authorizedChains"`
	TotalKeys        int      `json:"totalKeys"`
	SharesHeld       int      `json:"sharesHeld"`
	StagedCeremonies int      `json:"stagedCeremonies"`
	StateRoot        string   `json:"stateRoot"`
}

// GetInfo retrieves M-Chain information.
func (c *Client) GetInfo(ctx context.Context) (*ThresholdInfo, error) {
	var result ThresholdInfo
	if err := c.call(ctx, "threshold_getInfo", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// NetworkStats counts what this node did: ceremonies it completed, and the
// ceremonies it has finished but not yet gotten into a block.
type NetworkStats struct {
	TotalSignatures   uint64            `json:"totalSignatures"`
	TotalKeygens      uint64            `json:"totalKeygens"`
	StagedCeremonies  int               `json:"stagedCeremonies"`
	SignaturesByChain map[string]uint64 `json:"signaturesByChain"`
}

// GetStats retrieves this node's ceremony counters.
func (c *Client) GetStats(ctx context.Context) (*NetworkStats, error) {
	var result NetworkStats
	if err := c.call(ctx, "threshold_getStats", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// QuotaInfo contains quota information
type QuotaInfo struct {
	ChainID    string `json:"chainId"`
	DailyLimit uint64 `json:"dailyLimit"`
	UsedToday  uint64 `json:"usedToday"`
	Remaining  uint64 `json:"remaining"`
	ResetTime  int64  `json:"resetTime"`
}

// GetQuota retrieves quota information for this chain
func (c *Client) GetQuota(ctx context.Context) (*QuotaInfo, error) {
	params := map[string]string{
		"chainId": c.chainID,
	}

	var result QuotaInfo
	if err := c.call(ctx, "threshold_getQuota", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// =============================================================================
// Health
// =============================================================================

// Health retrieves M-Chain health status.
func (c *Client) Health(ctx context.Context) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.call(ctx, "threshold_health", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}
