// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client provides access to T-Chain MPC services
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
// Key Generation
// =============================================================================

// KeygenRequest contains parameters for key generation
type KeygenRequest struct {
	KeyID        string `json:"keyId"`
	Protocol     string `json:"protocol"`     // lss, cggmp21, bls, ringtail
	Threshold    int    `json:"threshold"`    // Optional
	TotalParties int    `json:"totalParties"` // Optional
}

// KeygenResponse contains the keygen result
type KeygenResponse struct {
	SessionID    string `json:"sessionId"`
	KeyID        string `json:"keyId"`
	Protocol     string `json:"protocol"`
	Status       string `json:"status"`
	Threshold    int    `json:"threshold"`
	TotalParties int    `json:"totalParties"`
	StartedAt    int64  `json:"startedAt"`
}

// Keygen initiates key generation on T-Chain
func (c *Client) Keygen(ctx context.Context, req KeygenRequest) (*KeygenResponse, error) {
	params := map[string]interface{}{
		"keyId":       req.KeyID,
		"protocol":    req.Protocol,
		"requestedBy": c.chainID,
	}
	if req.Threshold > 0 {
		params["threshold"] = req.Threshold
	}
	if req.TotalParties > 0 {
		params["totalParties"] = req.TotalParties
	}

	var result KeygenResponse
	if err := c.call(ctx, "threshold_keygen", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetKeygenStatus retrieves the status of a keygen session
func (c *Client) GetKeygenStatus(ctx context.Context, sessionID string) (*KeygenResponse, error) {
	params := map[string]string{
		"sessionId": sessionID,
	}

	var result KeygenResponse
	if err := c.call(ctx, "threshold_getKeygenStatus", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WaitForKeygen waits for keygen to complete
func (c *Client) WaitForKeygen(ctx context.Context, sessionID string, timeout time.Duration) (*KeygenResponse, error) {
	deadline := time.Now().Add(timeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		status, err := c.GetKeygenStatus(ctx, sessionID)
		if err != nil {
			return nil, err
		}

		switch status.Status {
		case "completed":
			return status, nil
		case "failed":
			return nil, fmt.Errorf("keygen failed: session %s", sessionID)
		default:
			// Still running, wait and retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pollInterval):
			}
		}
	}

	return nil, errors.New("keygen timed out")
}

// =============================================================================
// Signing
// =============================================================================

// SignRequest contains parameters for signing
type SignRequest struct {
	KeyID       string `json:"keyId"`
	MessageHash []byte `json:"messageHash"`
	MessageType string `json:"messageType"` // raw, eth_sign, typed_data
}

// SignResponse contains the signing session info
type SignResponse struct {
	SessionID string `json:"sessionId"`
	KeyID     string `json:"keyId"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

// SignatureResponse contains a completed signature
type SignatureResponse struct {
	SessionID     string   `json:"sessionId"`
	Status        string   `json:"status"`
	Signature     string   `json:"signature,omitempty"`
	R             string   `json:"r,omitempty"`
	S             string   `json:"s,omitempty"`
	V             int      `json:"v,omitempty"`
	SignerParties []string `json:"signerParties,omitempty"`
	CompletedAt   int64    `json:"completedAt,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// Sign requests a signature from T-Chain
func (c *Client) Sign(ctx context.Context, req SignRequest) (*SignResponse, error) {
	params := map[string]interface{}{
		"keyId":           req.KeyID,
		"messageHash":     hex.EncodeToString(req.MessageHash),
		"messageType":     req.MessageType,
		"requestingChain": c.chainID,
	}

	var result SignResponse
	if err := c.call(ctx, "threshold_sign", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetSignature retrieves a signature from T-Chain
func (c *Client) GetSignature(ctx context.Context, sessionID string) (*SignatureResponse, error) {
	params := map[string]string{
		"sessionId": sessionID,
	}

	var result SignatureResponse
	if err := c.call(ctx, "threshold_getSignature", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WaitForSignature waits for signature to complete
func (c *Client) WaitForSignature(ctx context.Context, sessionID string, timeout time.Duration) (*SignatureResponse, error) {
	deadline := time.Now().Add(timeout)
	pollInterval := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		sig, err := c.GetSignature(ctx, sessionID)
		if err != nil {
			return nil, err
		}

		switch sig.Status {
		case "completed":
			return sig, nil
		case "failed":
			return nil, fmt.Errorf("signing failed: %s", sig.Error)
		default:
			// Still signing, wait and retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pollInterval):
			}
		}
	}

	return nil, errors.New("signing timed out")
}

// SignAndWait signs a message and waits for completion
func (c *Client) SignAndWait(ctx context.Context, req SignRequest, timeout time.Duration) (*SignatureResponse, error) {
	// Start signing
	resp, err := c.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	// Wait for completion
	return c.WaitForSignature(ctx, resp.SessionID, timeout)
}

// BatchSign requests multiple signatures
func (c *Client) BatchSign(ctx context.Context, keyID string, messageHashes [][]byte) ([]string, error) {
	hashes := make([]string, len(messageHashes))
	for i, h := range messageHashes {
		hashes[i] = hex.EncodeToString(h)
	}

	params := map[string]interface{}{
		"keyId":           keyID,
		"messageHashes":   hashes,
		"requestingChain": c.chainID,
	}

	var result struct {
		SessionIDs []string `json:"sessionIds"`
	}
	if err := c.call(ctx, "threshold_batchSign", params, &result); err != nil {
		return nil, err
	}
	return result.SessionIDs, nil
}

// =============================================================================
// Key Management
// =============================================================================

// KeyInfo contains key information
type KeyInfo struct {
	KeyID        string   `json:"keyId"`
	Protocol     string   `json:"protocol"`
	PublicKey    string   `json:"publicKey"`
	Address      string   `json:"address,omitempty"`
	Threshold    int      `json:"threshold"`
	TotalParties int      `json:"totalParties"`
	Generation   uint64   `json:"generation"`
	Status       string   `json:"status"`
	SignCount    uint64   `json:"signCount"`
	CreatedAt    int64    `json:"createdAt"`
	LastUsedAt   int64    `json:"lastUsedAt,omitempty"`
	PartyIDs     []string `json:"partyIds"`
}

// ListKeys lists all keys on T-Chain
func (c *Client) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	var result []KeyInfo
	if err := c.call(ctx, "threshold_listKeys", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetKey retrieves key information
func (c *Client) GetKey(ctx context.Context, keyID string) (*KeyInfo, error) {
	params := map[string]string{
		"keyId": keyID,
	}

	var result KeyInfo
	if err := c.call(ctx, "threshold_getKey", params, &result); err != nil {
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

// Reshare triggers key resharing
func (c *Client) Reshare(ctx context.Context, keyID string, newPartyIDs []string, newThreshold int) (*KeygenResponse, error) {
	params := map[string]interface{}{
		"keyId":        keyID,
		"newPartyIds":  newPartyIDs,
		"newThreshold": newThreshold,
		"requestedBy":  c.chainID,
	}

	var result KeygenResponse
	if err := c.call(ctx, "threshold_reshare", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Refresh triggers key refresh
func (c *Client) Refresh(ctx context.Context, keyID string) (*KeygenResponse, error) {
	params := map[string]interface{}{
		"keyId":       keyID,
		"requestedBy": c.chainID,
	}

	var result KeygenResponse
	if err := c.call(ctx, "threshold_refresh", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
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

// ThresholdInfo contains T-Chain information
type ThresholdInfo struct {
	Version            string   `json:"version"`
	NodeID             string   `json:"nodeId"`
	ChainID            string   `json:"chainId"`
	MPCReady           bool     `json:"mpcReady"`
	ActiveKeyID        string   `json:"activeKeyId,omitempty"`
	Threshold          int      `json:"threshold"`
	TotalParties       int      `json:"totalParties"`
	SupportedProtocols []string `json:"supportedProtocols"`
	AuthorizedChains   []string `json:"authorizedChains"`
	TotalKeys          int      `json:"totalKeys"`
	ActiveSessions     int      `json:"activeSessions"`
}

// GetInfo retrieves T-Chain information
func (c *Client) GetInfo(ctx context.Context) (*ThresholdInfo, error) {
	var result ThresholdInfo
	if err := c.call(ctx, "threshold_getInfo", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// NetworkStats contains network statistics
type NetworkStats struct {
	TotalSignatures    uint64            `json:"totalSignatures"`
	TotalKeygens       uint64            `json:"totalKeygens"`
	ActiveSessions     int               `json:"activeSessions"`
	SignaturesByChain  map[string]uint64 `json:"signaturesByChain"`
	AverageSigningTime int64             `json:"averageSigningTime"` // nanoseconds
	SuccessRate        float64           `json:"successRate"`
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

// Health retrieves T-Chain health status
func (c *Client) Health(ctx context.Context) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.call(ctx, "threshold_health", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// IsReady checks if T-Chain MPC is ready
func (c *Client) IsReady(ctx context.Context) (bool, error) {
	info, err := c.GetInfo(ctx)
	if err != nil {
		return false, err
	}
	return info.MPCReady, nil
}
