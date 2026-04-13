// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/luxfi/threshold/pkg/party"
)

// RPCRequest represents a JSON-RPC request
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// RPCResponse represents a JSON-RPC response
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface
func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// Error codes
const (
	RPCErrorInvalidRequest   = -32600
	RPCErrorMethodNotFound   = -32601
	RPCErrorInvalidParams    = -32602
	RPCErrorInternal         = -32603
	RPCErrorMPCNotReady      = -32001
	RPCErrorUnauthorized     = -32002
	RPCErrorQuotaExceeded    = -32003
	RPCErrorSessionNotFound  = -32004
	RPCErrorKeyNotFound      = -32005
	RPCErrorProtocolNotFound = -32006
	RPCErrorKeygenInProgress = -32007
	RPCErrorInvalidProtocol  = -32008
)

// createRPCHandler creates the JSON-RPC handler
func (vm *VM) createRPCHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			writeRPCError(w, nil, RPCErrorInvalidRequest, "Method not allowed", nil)
			return
		}

		var req RPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRPCError(w, nil, RPCErrorInvalidRequest, "Invalid JSON", nil)
			return
		}

		result, err := vm.handleRPCMethod(req.Method, req.Params)
		if err != nil {
			rpcErr, ok := err.(*RPCError)
			if !ok {
				rpcErr = &RPCError{Code: RPCErrorInternal, Message: err.Error()}
			}
			writeRPCResponse(w, req.ID, nil, rpcErr)
			return
		}

		writeRPCResponse(w, req.ID, result, nil)
	})
}

func writeRPCResponse(w http.ResponseWriter, id interface{}, result interface{}, err *RPCError) {
	resp := RPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
		Error:   err,
	}
	json.NewEncoder(w).Encode(resp)
}

func writeRPCError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
	writeRPCResponse(w, id, nil, &RPCError{Code: code, Message: message, Data: data})
}

// handleRPCMethod dispatches RPC method calls
func (vm *VM) handleRPCMethod(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	// Key Generation
	case "threshold_keygen":
		return vm.rpcKeygen(params)
	case "threshold_getKeygenStatus":
		return vm.rpcGetKeygenStatus(params)

	// Signing
	case "threshold_sign":
		return vm.rpcSign(params)
	case "threshold_getSignature":
		return vm.rpcGetSignature(params)
	case "threshold_batchSign":
		return vm.rpcBatchSign(params)

	// Key Management
	case "threshold_reshare":
		return vm.rpcReshare(params)
	case "threshold_refresh":
		return vm.rpcRefresh(params)
	case "threshold_listKeys":
		return vm.rpcListKeys()
	case "threshold_getKey":
		return vm.rpcGetKey(params)
	case "threshold_getPublicKey":
		return vm.rpcGetPublicKey(params)
	case "threshold_getAddress":
		return vm.rpcGetAddress(params)

	// Protocol Information
	case "threshold_getProtocols":
		return vm.rpcGetProtocols()
	case "threshold_getProtocolInfo":
		return vm.rpcGetProtocolInfo(params)

	// Session Management
	case "threshold_getSessions":
		return vm.rpcGetSessions(params)
	case "threshold_cancelSession":
		return vm.rpcCancelSession(params)

	// Network Information
	case "threshold_getInfo":
		return vm.rpcGetInfo()
	case "threshold_getStats":
		return vm.rpcGetStats()
	case "threshold_getParties":
		return vm.rpcGetParties()
	case "threshold_getQuota":
		return vm.rpcGetQuota(params)

	// Authorization
	case "threshold_getAuthorizedChains":
		return vm.rpcGetAuthorizedChains()
	case "threshold_getChainPermissions":
		return vm.rpcGetChainPermissions(params)

	// Health
	case "threshold_health":
		return vm.rpcHealthCheck()

	default:
		return nil, &RPCError{Code: RPCErrorMethodNotFound, Message: fmt.Sprintf("method not found: %s", method)}
	}
}

// =============================================================================
// Key Generation RPCs
// =============================================================================

// KeygenParams contains parameters for key generation
type KeygenParams struct {
	KeyID        string `json:"keyId"`
	Protocol     string `json:"protocol"`     // lss, cggmp21, bls, ringtail
	RequestedBy  string `json:"requestedBy"`  // Chain ID
	Threshold    int    `json:"threshold"`    // Optional override
	TotalParties int    `json:"totalParties"` // Optional override
}

// KeygenResult contains the result of key generation
type KeygenResult struct {
	SessionID    string `json:"sessionId"`
	KeyID        string `json:"keyId"`
	Protocol     string `json:"protocol"`
	Status       string `json:"status"`
	Threshold    int    `json:"threshold"`
	TotalParties int    `json:"totalParties"`
	StartedAt    int64  `json:"startedAt"`
}

func (vm *VM) rpcKeygen(params json.RawMessage) (*KeygenResult, error) {
	var p KeygenParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	// Default protocol
	protocol := Protocol(p.Protocol)
	if protocol == "" {
		protocol = ProtocolLSS
	}

	// Validate protocol
	if _, err := vm.protocolRegistry.Get(protocol); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidProtocol, Message: err.Error()}
	}

	// Use configured values if not overridden
	threshold := p.Threshold
	if threshold == 0 {
		threshold = vm.config.Threshold
	}
	totalParties := p.TotalParties
	if totalParties == 0 {
		totalParties = vm.config.TotalParties
	}

	session, err := vm.StartKeygenWithProtocol(p.KeyID, string(protocol), p.RequestedBy, threshold, totalParties)
	if err != nil {
		switch err {
		case ErrUnauthorizedChain:
			return nil, &RPCError{Code: RPCErrorUnauthorized, Message: err.Error()}
		case ErrKeygenInProgress:
			return nil, &RPCError{Code: RPCErrorKeygenInProgress, Message: err.Error()}
		default:
			return nil, &RPCError{Code: RPCErrorInternal, Message: err.Error()}
		}
	}

	return &KeygenResult{
		SessionID:    session.SessionID,
		KeyID:        session.KeyID,
		Protocol:     session.KeyType,
		Status:       session.Status,
		Threshold:    session.Threshold,
		TotalParties: session.TotalParties,
		StartedAt:    session.StartedAt.Unix(),
	}, nil
}

// GetKeygenStatusParams contains parameters for getting keygen status
type GetKeygenStatusParams struct {
	SessionID string `json:"sessionId"`
}

func (vm *VM) rpcGetKeygenStatus(params json.RawMessage) (*KeygenResult, error) {
	var p GetKeygenStatusParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	vm.mu.RLock()
	session, ok := vm.keygenSessions[p.SessionID]
	vm.mu.RUnlock()

	if !ok {
		return nil, &RPCError{Code: RPCErrorSessionNotFound, Message: "session not found"}
	}

	result := &KeygenResult{
		SessionID:    session.SessionID,
		KeyID:        session.KeyID,
		Protocol:     session.KeyType,
		Status:       session.Status,
		Threshold:    session.Threshold,
		TotalParties: session.TotalParties,
		StartedAt:    session.StartedAt.Unix(),
	}

	return result, nil
}

// =============================================================================
// Signing RPCs
// =============================================================================

// SignParams contains parameters for signing
type SignParams struct {
	KeyID           string `json:"keyId"`
	MessageHash     string `json:"messageHash"`     // Hex encoded
	MessageType     string `json:"messageType"`     // raw, eth_sign, typed_data
	RequestingChain string `json:"requestingChain"` // Chain ID requesting signature
}

// SignResult contains the signing session info
type SignResult struct {
	SessionID       string `json:"sessionId"`
	KeyID           string `json:"keyId"`
	Status          string `json:"status"`
	RequestingChain string `json:"requestingChain"`
	CreatedAt       int64  `json:"createdAt"`
	ExpiresAt       int64  `json:"expiresAt"`
}

func (vm *VM) rpcSign(params json.RawMessage) (*SignResult, error) {
	var p SignParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	messageHash, err := hex.DecodeString(stripHexPrefix(p.MessageHash))
	if err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid message hash"}
	}

	session, err := vm.RequestSignature(p.RequestingChain, p.KeyID, messageHash, p.MessageType)
	if err != nil {
		switch err {
		case ErrUnauthorizedChain:
			return nil, &RPCError{Code: RPCErrorUnauthorized, Message: err.Error()}
		case ErrQuotaExceeded:
			return nil, &RPCError{Code: RPCErrorQuotaExceeded, Message: err.Error()}
		case ErrKeyNotFound:
			return nil, &RPCError{Code: RPCErrorKeyNotFound, Message: err.Error()}
		case ErrNotInitialized:
			return nil, &RPCError{Code: RPCErrorMPCNotReady, Message: err.Error()}
		default:
			return nil, &RPCError{Code: RPCErrorInternal, Message: err.Error()}
		}
	}

	return &SignResult{
		SessionID:       session.SessionID,
		KeyID:           session.KeyID,
		Status:          session.Status,
		RequestingChain: session.RequestingChain,
		CreatedAt:       session.CreatedAt.Unix(),
		ExpiresAt:       session.ExpiresAt.Unix(),
	}, nil
}

// GetSignatureParams contains parameters for getting a signature
type GetSignatureParams struct {
	SessionID string `json:"sessionId"`
}

// SignatureResult contains the completed signature
type SignatureResult struct {
	SessionID     string   `json:"sessionId"`
	Status        string   `json:"status"`
	Signature     string   `json:"signature,omitempty"` // Hex encoded
	R             string   `json:"r,omitempty"`         // Hex encoded
	S             string   `json:"s,omitempty"`         // Hex encoded
	V             int      `json:"v,omitempty"`         // Recovery ID
	SignerParties []string `json:"signerParties,omitempty"`
	CompletedAt   int64    `json:"completedAt,omitempty"`
	Error         string   `json:"error,omitempty"`
}

func (vm *VM) rpcGetSignature(params json.RawMessage) (*SignatureResult, error) {
	var p GetSignatureParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	session, err := vm.GetSignature(p.SessionID)
	if err != nil {
		switch err {
		case ErrSessionNotFound:
			return nil, &RPCError{Code: RPCErrorSessionNotFound, Message: err.Error()}
		case ErrSessionExpired:
			return nil, &RPCError{Code: RPCErrorSessionNotFound, Message: err.Error()}
		default:
			return nil, &RPCError{Code: RPCErrorInternal, Message: err.Error()}
		}
	}

	result := &SignatureResult{
		SessionID: session.SessionID,
		Status:    session.Status,
		Error:     session.Error,
	}

	if session.Status == "completed" && session.Signature != nil {
		result.Signature = "0x" + hex.EncodeToString(append(session.Signature.R, session.Signature.S...))
		result.R = "0x" + hex.EncodeToString(session.Signature.R)
		result.S = "0x" + hex.EncodeToString(session.Signature.S)
		result.V = int(session.Signature.V)
		result.CompletedAt = session.CompletedAt.Unix()

		signerParties := make([]string, len(session.SignerParties))
		for i, p := range session.SignerParties {
			signerParties[i] = string(p)
		}
		result.SignerParties = signerParties
	}

	return result, nil
}

// BatchSignParams contains parameters for batch signing
type BatchSignParams struct {
	KeyID           string   `json:"keyId"`
	MessageHashes   []string `json:"messageHashes"` // Hex encoded
	RequestingChain string   `json:"requestingChain"`
}

// BatchSignResult contains batch signing results
type BatchSignResult struct {
	SessionIDs []string `json:"sessionIds"`
	Status     string   `json:"status"`
}

func (vm *VM) rpcBatchSign(params json.RawMessage) (*BatchSignResult, error) {
	var p BatchSignParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	sessionIDs := make([]string, 0, len(p.MessageHashes))
	for _, hashHex := range p.MessageHashes {
		messageHash, err := hex.DecodeString(stripHexPrefix(hashHex))
		if err != nil {
			continue
		}

		session, err := vm.RequestSignature(p.RequestingChain, p.KeyID, messageHash, "raw")
		if err != nil {
			continue
		}
		sessionIDs = append(sessionIDs, session.SessionID)
	}

	return &BatchSignResult{
		SessionIDs: sessionIDs,
		Status:     "submitted",
	}, nil
}

// =============================================================================
// Key Management RPCs
// =============================================================================

// ReshareParams contains parameters for key resharing
type ReshareParams struct {
	KeyID        string   `json:"keyId"`
	NewPartyIDs  []string `json:"newPartyIds"`
	NewThreshold int      `json:"newThreshold"`
	RequestedBy  string   `json:"requestedBy"`
}

func (vm *VM) rpcReshare(params json.RawMessage) (*KeygenResult, error) {
	var p ReshareParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	newPartyIDs := make([]party.ID, len(p.NewPartyIDs))
	for i, pid := range p.NewPartyIDs {
		newPartyIDs[i] = party.ID(pid)
	}

	session, err := vm.ReshareKey(p.KeyID, newPartyIDs, p.RequestedBy)
	if err != nil {
		switch err {
		case ErrUnauthorizedChain:
			return nil, &RPCError{Code: RPCErrorUnauthorized, Message: err.Error()}
		case ErrKeyNotFound:
			return nil, &RPCError{Code: RPCErrorKeyNotFound, Message: err.Error()}
		default:
			return nil, &RPCError{Code: RPCErrorInternal, Message: err.Error()}
		}
	}

	return &KeygenResult{
		SessionID:    session.SessionID,
		KeyID:        session.KeyID,
		Protocol:     session.KeyType,
		Status:       session.Status,
		TotalParties: session.TotalParties,
		StartedAt:    session.StartedAt.Unix(),
	}, nil
}

// RefreshParams contains parameters for key refresh
type RefreshParams struct {
	KeyID       string `json:"keyId"`
	RequestedBy string `json:"requestedBy"`
}

func (vm *VM) rpcRefresh(params json.RawMessage) (*KeygenResult, error) {
	var p RefreshParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	session, err := vm.RefreshKey(p.KeyID, p.RequestedBy)
	if err != nil {
		return nil, &RPCError{Code: RPCErrorInternal, Message: err.Error()}
	}

	return &KeygenResult{
		SessionID: session.SessionID,
		KeyID:     session.KeyID,
		Status:    session.Status,
		StartedAt: session.StartedAt.Unix(),
	}, nil
}

// Note: KeyInfo type is defined in client.go

func (vm *VM) rpcListKeys() ([]KeyInfo, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	keys := make([]KeyInfo, 0, len(vm.keys))
	for _, key := range vm.keys {
		partyIDs := make([]string, len(key.PartyIDs))
		for i, p := range key.PartyIDs {
			partyIDs[i] = string(p)
		}

		info := KeyInfo{
			KeyID:        key.KeyID,
			Protocol:     key.KeyType,
			PublicKey:    "0x" + hex.EncodeToString(key.PublicKey),
			Threshold:    key.Threshold,
			TotalParties: key.TotalParties,
			Generation:   key.Generation,
			Status:       key.Status,
			SignCount:    key.SignCount,
			CreatedAt:    key.CreatedAt.Unix(),
			PartyIDs:     partyIDs,
		}

		if len(key.Address) > 0 {
			info.Address = "0x" + hex.EncodeToString(key.Address)
		}
		if !key.LastUsedAt.IsZero() {
			info.LastUsedAt = key.LastUsedAt.Unix()
		}

		keys = append(keys, info)
	}

	return keys, nil
}

// GetKeyParams contains parameters for getting a key
type GetKeyParams struct {
	KeyID string `json:"keyId"`
}

func (vm *VM) rpcGetKey(params json.RawMessage) (*KeyInfo, error) {
	var p GetKeyParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	vm.mu.RLock()
	key, ok := vm.keys[p.KeyID]
	vm.mu.RUnlock()

	if !ok {
		return nil, &RPCError{Code: RPCErrorKeyNotFound, Message: "key not found"}
	}

	partyIDs := make([]string, len(key.PartyIDs))
	for i, pid := range key.PartyIDs {
		partyIDs[i] = string(pid)
	}

	info := &KeyInfo{
		KeyID:        key.KeyID,
		Protocol:     key.KeyType,
		PublicKey:    "0x" + hex.EncodeToString(key.PublicKey),
		Threshold:    key.Threshold,
		TotalParties: key.TotalParties,
		Generation:   key.Generation,
		Status:       key.Status,
		SignCount:    key.SignCount,
		CreatedAt:    key.CreatedAt.Unix(),
		PartyIDs:     partyIDs,
	}

	if len(key.Address) > 0 {
		info.Address = "0x" + hex.EncodeToString(key.Address)
	}
	if !key.LastUsedAt.IsZero() {
		info.LastUsedAt = key.LastUsedAt.Unix()
	}

	return info, nil
}

func (vm *VM) rpcGetPublicKey(params json.RawMessage) (map[string]string, error) {
	var p GetKeyParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
		}
	}

	pubKey, err := vm.GetPublicKey(p.KeyID)
	if err != nil {
		return nil, &RPCError{Code: RPCErrorKeyNotFound, Message: err.Error()}
	}

	return map[string]string{
		"publicKey": "0x" + hex.EncodeToString(pubKey),
	}, nil
}

func (vm *VM) rpcGetAddress(params json.RawMessage) (map[string]string, error) {
	var p GetKeyParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
		}
	}

	address, err := vm.GetAddress(p.KeyID)
	if err != nil {
		return nil, &RPCError{Code: RPCErrorKeyNotFound, Message: err.Error()}
	}

	return map[string]string{
		"address": "0x" + hex.EncodeToString(address),
	}, nil
}

// =============================================================================
// Protocol Information RPCs
// =============================================================================

func (vm *VM) rpcGetProtocols() ([]ProtocolInfo, error) {
	return GetProtocolInfo(), nil
}

// GetProtocolInfoParams contains parameters for getting protocol info
type GetProtocolInfoParams struct {
	Protocol string `json:"protocol"`
}

func (vm *VM) rpcGetProtocolInfo(params json.RawMessage) (*ProtocolInfo, error) {
	var p GetProtocolInfoParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	protocols := GetProtocolInfo()
	for _, info := range protocols {
		if string(info.Name) == p.Protocol {
			return &info, nil
		}
	}

	return nil, &RPCError{Code: RPCErrorProtocolNotFound, Message: "protocol not found"}
}

// =============================================================================
// Session Management RPCs
// =============================================================================

// GetSessionsParams contains parameters for listing sessions
type GetSessionsParams struct {
	ChainID string `json:"chainId,omitempty"`
	Status  string `json:"status,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

// SessionInfo contains session information
type SessionInfo struct {
	SessionID       string `json:"sessionId"`
	Type            string `json:"type"` // keygen, sign, reshare
	KeyID           string `json:"keyId"`
	Status          string `json:"status"`
	RequestingChain string `json:"requestingChain,omitempty"`
	CreatedAt       int64  `json:"createdAt"`
	ExpiresAt       int64  `json:"expiresAt,omitempty"`
	CompletedAt     int64  `json:"completedAt,omitempty"`
	Error           string `json:"error,omitempty"`
}

func (vm *VM) rpcGetSessions(params json.RawMessage) ([]SessionInfo, error) {
	var p GetSessionsParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
		}
	}

	if p.Limit == 0 {
		p.Limit = 50
	}

	vm.mu.RLock()
	defer vm.mu.RUnlock()

	sessions := make([]SessionInfo, 0)

	// Add signing sessions
	for _, session := range vm.signingSessions {
		if p.ChainID != "" && session.RequestingChain != p.ChainID {
			continue
		}
		if p.Status != "" && session.Status != p.Status {
			continue
		}

		info := SessionInfo{
			SessionID:       session.SessionID,
			Type:            "sign",
			KeyID:           session.KeyID,
			Status:          session.Status,
			RequestingChain: session.RequestingChain,
			CreatedAt:       session.CreatedAt.Unix(),
			ExpiresAt:       session.ExpiresAt.Unix(),
			Error:           session.Error,
		}
		if !session.CompletedAt.IsZero() {
			info.CompletedAt = session.CompletedAt.Unix()
		}
		sessions = append(sessions, info)

		if len(sessions) >= p.Limit {
			break
		}
	}

	// Add keygen sessions
	for _, session := range vm.keygenSessions {
		if p.Status != "" && session.Status != p.Status {
			continue
		}

		info := SessionInfo{
			SessionID:       session.SessionID,
			Type:            "keygen",
			KeyID:           session.KeyID,
			Status:          session.Status,
			RequestingChain: session.RequestedBy,
			CreatedAt:       session.StartedAt.Unix(),
			Error:           session.Error,
		}
		if !session.CompletedAt.IsZero() {
			info.CompletedAt = session.CompletedAt.Unix()
		}
		sessions = append(sessions, info)

		if len(sessions) >= p.Limit {
			break
		}
	}

	return sessions, nil
}

// CancelSessionParams contains parameters for canceling a session
type CancelSessionParams struct {
	SessionID string `json:"sessionId"`
}

func (vm *VM) rpcCancelSession(params json.RawMessage) (map[string]bool, error) {
	var p CancelSessionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Try signing sessions
	if session, ok := vm.signingSessions[p.SessionID]; ok {
		if session.Status == "signing" || session.Status == "pending" {
			session.Status = "cancelled"
			session.Error = "cancelled by user"
			return map[string]bool{"cancelled": true}, nil
		}
	}

	// Try keygen sessions
	if session, ok := vm.keygenSessions[p.SessionID]; ok {
		if session.Status == "running" || session.Status == "pending" {
			session.Status = "cancelled"
			session.Error = "cancelled by user"
			return map[string]bool{"cancelled": true}, nil
		}
	}

	return nil, &RPCError{Code: RPCErrorSessionNotFound, Message: "session not found or not cancellable"}
}

// =============================================================================
// Network Information RPCs
// =============================================================================

// Note: ThresholdInfo type is defined in client.go

func (vm *VM) rpcGetInfo() (*ThresholdInfo, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	protocols := make([]string, 0)
	for _, p := range vm.protocolRegistry.Available() {
		protocols = append(protocols, string(p))
	}

	chains := make([]string, 0, len(vm.config.AuthorizedChains))
	for chainID := range vm.config.AuthorizedChains {
		chains = append(chains, chainID)
	}

	return &ThresholdInfo{
		Version:            Version.String(),
		NodeID:             vm.rt.NodeID.String(),
		ChainID:            vm.rt.ChainID.String(),
		MPCReady:           vm.mpcReady,
		ActiveKeyID:        vm.activeKeyID,
		Threshold:          vm.config.Threshold,
		TotalParties:       vm.config.TotalParties,
		SupportedProtocols: protocols,
		AuthorizedChains:   chains,
		TotalKeys:          len(vm.keys),
		ActiveSessions:     len(vm.signingSessions),
	}, nil
}

func (vm *VM) rpcGetStats() (*NetworkStats, error) {
	vm.stats.mu.RLock()
	defer vm.stats.mu.RUnlock()

	// Make a copy, converting time.Duration to int64 nanoseconds
	stats := &NetworkStats{
		TotalSignatures:    vm.stats.TotalSignatures,
		TotalKeygens:       vm.stats.TotalKeygens,
		ActiveSessions:     len(vm.signingSessions),
		SignaturesByChain:  make(map[string]uint64),
		AverageSigningTime: int64(vm.stats.AverageSigningTime), // Convert Duration to nanoseconds
		SuccessRate:        vm.stats.SuccessRate,
	}

	for k, v := range vm.stats.SignaturesByChain {
		stats.SignaturesByChain[k] = v
	}

	return stats, nil
}

// PartyInfo contains party information
type PartyInfo struct {
	PartyID string `json:"partyId"`
	NodeID  string `json:"nodeId"`
	IsLocal bool   `json:"isLocal"`
	Active  bool   `json:"active"`
}

func (vm *VM) rpcGetParties() ([]PartyInfo, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	parties := make([]PartyInfo, len(vm.partyIDs))
	for i, pid := range vm.partyIDs {
		parties[i] = PartyInfo{
			PartyID: string(pid),
			IsLocal: pid == vm.partyID,
			Active:  true, // Would need connection tracking
		}
	}

	return parties, nil
}

// GetQuotaParams contains parameters for getting quota
type GetQuotaParams struct {
	ChainID string `json:"chainId"`
}

// Note: QuotaInfo type is defined in client.go

func (vm *VM) rpcGetQuota(params json.RawMessage) (*QuotaInfo, error) {
	var p GetQuotaParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	vm.mu.RLock()
	defer vm.mu.RUnlock()

	perms, ok := vm.config.AuthorizedChains[p.ChainID]
	if !ok {
		return nil, &RPCError{Code: RPCErrorUnauthorized, Message: "chain not authorized"}
	}

	limit := perms.DailySigningLimit
	if vm.config.DailySigningQuota[p.ChainID] > 0 {
		limit = vm.config.DailySigningQuota[p.ChainID]
	}

	used := vm.dailySigningCount[p.ChainID]
	remaining := uint64(0)
	if limit > used {
		remaining = limit - used
	}

	return &QuotaInfo{
		ChainID:    p.ChainID,
		DailyLimit: limit,
		UsedToday:  used,
		Remaining:  remaining,
		ResetTime:  vm.quotaResetTime.Unix(),
	}, nil
}

// =============================================================================
// Authorization RPCs
// =============================================================================

func (vm *VM) rpcGetAuthorizedChains() ([]string, error) {
	chains := make([]string, 0, len(vm.config.AuthorizedChains))
	for chainID := range vm.config.AuthorizedChains {
		chains = append(chains, chainID)
	}
	return chains, nil
}

// GetChainPermissionsParams contains parameters for getting chain permissions
type GetChainPermissionsParams struct {
	ChainID string `json:"chainId"`
}

func (vm *VM) rpcGetChainPermissions(params json.RawMessage) (*ChainPermissions, error) {
	var p GetChainPermissionsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: "invalid parameters"}
	}

	perms, ok := vm.config.AuthorizedChains[p.ChainID]
	if !ok {
		return nil, &RPCError{Code: RPCErrorUnauthorized, Message: "chain not authorized"}
	}

	return perms, nil
}

// =============================================================================
// Health RPCs
// =============================================================================

func (vm *VM) rpcHealthCheck() (map[string]interface{}, error) {
	health, err := vm.HealthCheck(nil)
	if err != nil {
		return nil, &RPCError{Code: RPCErrorInternal, Message: err.Error()}
	}
	// Convert chain.HealthResult to map[string]interface{}
	result := make(map[string]interface{})
	result["healthy"] = health.Healthy
	for k, v := range health.Details {
		result[k] = v
	}
	return result, nil
}

// Helper functions

func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}
