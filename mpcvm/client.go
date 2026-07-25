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

// Client provides access to mpcvm services. Per LP-134, this serves
// M-Chain (MPC mode) and F-Chain (FHE mode); legacy T-Chain MPC routes here.
type Client struct {
	endpoint   string
	chainID    string // Requesting chain's ID
	httpClient *http.Client
}

// NewClient creates a new T-Chain client
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

// KeygenRequest contains parameters for key generation.
type KeygenRequest struct {
	KeyID string `json:"keyId"`
	// Policy is the quorum in operator form, "3-of-5". Empty means the chain's
	// default.
	Policy string `json:"policy,omitempty"`
}

// KeygenResponse is a COMPLETED key generation.
type KeygenResponse struct {
	Ceremony CeremonyInfo `json:"ceremony"`
	Key      KeyInfo      `json:"key"`
}

// Keygen runs a distributed key generation and returns when the key exists.
// There is no status to poll afterwards: the ceremony either produced a
// registered key or returned an error.
func (c *Client) Keygen(ctx context.Context, req KeygenRequest) (*KeygenResponse, error) {
	params := map[string]interface{}{
		"keyId":       req.KeyID,
		"requestedBy": c.chainID,
	}
	if req.Policy != "" {
		params["policy"] = req.Policy
	}

	var result KeygenResponse
	if err := c.call(ctx, "threshold_keygen", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignRequest contains parameters for signing.
type SignRequest struct {
	KeyID string `json:"keyId"`
	// MessageHash is the exact 32 bytes to sign. The caller owns its signing
	// domain; M-Chain signs what it is given and never re-hashes.
	MessageHash []byte `json:"messageHash"`
}

// Sign runs a threshold signing ceremony and returns the finished signature.
//
// The call blocks for the duration of the ceremony. The returned CeremonyID is
// the durable handle: GetCeremony re-reads the same signature from replicated
// state once the block carrying it is accepted.
func (c *Client) Sign(ctx context.Context, req SignRequest) (*CeremonyInfo, error) {
	params := map[string]interface{}{
		"keyId":           req.KeyID,
		"messageHash":     hex.EncodeToString(req.MessageHash),
		"requestingChain": c.chainID,
	}

	var result CeremonyInfo
	if err := c.call(ctx, "threshold_sign", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

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
// Protocol Information
// =============================================================================

// ProtocolInfo contains protocol information
type ProtocolInfo struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	SupportedCurves []string `json:"supportedCurves"`
	KeySize         int      `json:"keySize"`
	SignatureSize   int      `json:"signatureSize"`
	IsPostQuantum   bool     `json:"isPostQuantum"`
	SupportsReshare bool     `json:"supportsReshare"`
	SupportsRefresh bool     `json:"supportsRefresh"`
}

// GetProtocols retrieves all supported protocols
func (c *Client) GetProtocols(ctx context.Context) ([]ProtocolInfo, error) {
	var result []ProtocolInfo
	if err := c.call(ctx, "threshold_getProtocols", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetProtocolInfo retrieves info for a specific protocol
func (c *Client) GetProtocolInfo(ctx context.Context, protocol string) (*ProtocolInfo, error) {
	params := map[string]string{
		"protocol": protocol,
	}

	var result ProtocolInfo
	if err := c.call(ctx, "threshold_getProtocolInfo", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
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

// GetStats retrieves T-Chain statistics
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
