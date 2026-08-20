// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/luxfi/threshold/pkg/quorum"
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

// Error codes. Only codes this server can actually return are declared: a
// published code that nothing emits reads as a contract to callers who then
// write dead branches against it.
const (
	RPCErrorInvalidRequest   = -32600
	RPCErrorMethodNotFound   = -32601
	RPCErrorInvalidParams    = -32602
	RPCErrorInternal         = -32603
	RPCErrorUnauthorized     = -32002
	RPCErrorQuotaExceeded    = -32003
	RPCErrorCeremonyNotFound = -32004
	RPCErrorKeyNotFound      = -32005
	RPCErrorProtocolNotFound = -32006
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

		result, err := vm.handleRPCMethod(r.Context(), req.Method, req.Params)
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

// handleRPCMethod dispatches RPC method calls.
//
// Two families, one per noun: threshold_* runs ceremonies and reports on the
// node, mpc_* reads the replicated custody state (keys, ceremonies, root).
// Nothing is reachable under two names — a capability with two spellings is a
// capability whose two spellings will eventually disagree.
func (vm *VM) handleRPCMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	switch method {
	// Ceremonies. Both run to completion before returning: keygen yields a
	// registered key, sign yields the signature itself.
	case "threshold_keygen", "threshold_sign":
		// Ceremonies are requested BY a chain, and this transport authenticates
		// no chain: an HTTP body can say it is the bridge as easily as it can
		// say anything else. Custody rights are granted over the cross-chain
		// path, where the sender's chain id is authenticated (CrossChainRequest),
		// so there is exactly one way in and it is not this one.
		return nil, &RPCError{
			Code:    RPCErrorUnauthorized,
			Message: fmt.Sprintf("%s is requested by a chain, over the cross-chain transport that authenticates it; this endpoint authenticates no caller", method),
		}

	// Custody registry (replicated state)
	case "mpc_getKey":
		return vm.rpcGetKey(params)
	case "mpc_listKeys":
		return vm.rpcListKeys()
	case "threshold_getPublicKey":
		return vm.rpcGetPublicKey(params)
	case "threshold_getAddress":
		return vm.rpcGetAddress(params)

	// Ceremony log (replicated state) — where a produced signature is read back
	// from durably, and the root that says two validators agree.
	case "mpc_getCeremony":
		return vm.rpcGetCeremony(params)
	case "mpc_listCeremonies":
		return vm.rpcListCeremonies()
	case "mpc_getStateRoot":
		return vm.rpcGetStateRoot()

	// Protocol Information
	case "threshold_getProtocols":
		return vm.rpcGetProtocols()
	case "threshold_getProtocolInfo":
		return vm.rpcGetProtocolInfo(params)

	// Network Information
	case "threshold_getInfo":
		return vm.rpcGetInfo()
	case "threshold_getStats":
		return vm.rpcGetStats()
	case "threshold_getParties":
		return vm.rpcGetParties(ctx)
	case "threshold_getQuota":
		return vm.rpcGetQuota(params)

	// Authorization
	case "threshold_getAuthorizedChains":
		return vm.rpcGetAuthorizedChains()
	case "threshold_getChainPermissions":
		return vm.rpcGetChainPermissions(params)

	// Health
	case "threshold_health":
		return vm.rpcHealthCheck(ctx)

	default:
		return nil, &RPCError{Code: RPCErrorMethodNotFound, Message: fmt.Sprintf("method not found: %s", method)}
	}
}

// asRPCError maps a VM error to its JSON-RPC code. Written once so every method
// classifies the same failure the same way, and matched with errors.Is because
// the VM wraps its errors with context.
func asRPCError(err error) *RPCError {
	switch {
	case errors.Is(err, ErrUnauthorizedChain):
		return &RPCError{Code: RPCErrorUnauthorized, Message: err.Error()}
	case errors.Is(err, ErrQuotaExceeded):
		return &RPCError{Code: RPCErrorQuotaExceeded, Message: err.Error()}
	case errors.Is(err, ErrUnknownKey), errors.Is(err, ErrShareNotHeld):
		return &RPCError{Code: RPCErrorKeyNotFound, Message: err.Error()}
	default:
		return &RPCError{Code: RPCErrorInternal, Message: err.Error()}
	}
}

// =============================================================================
// Ceremony RPCs
// =============================================================================

// KeygenParams contains parameters for key generation.
type KeygenParams struct {
	KeyID       string `json:"keyId"`
	RequestedBy string `json:"requestedBy"` // Chain ID; must be authorised to keygen
	// Policy is the quorum in operator form, "3-of-5". Omit it to use the
	// chain's default. It is deliberately not a pair of numbers: a caller
	// cannot express the quorum ambiguously, and the polynomial degree is
	// derived from it inside the ceremony rather than passed alongside it.
	Policy quorum.Policy `json:"policy,omitempty"`
}

// KeygenResult is a COMPLETED key generation: the ceremony that ran and the
// key it registered. There is no status to poll — a keygen that returns has a
// key, and one that fails returns an error.
type KeygenResult struct {
	Ceremony CeremonyInfo `json:"ceremony"`
	Key      KeyInfo      `json:"key"`
}

// SignParams contains parameters for signing.
type SignParams struct {
	KeyID string `json:"keyId"`
	// MessageHash is the exact 32 bytes to sign, hex encoded. M-Chain does not
	// hash on the caller's behalf: the caller owns its signing domain, and a
	// chain that re-hashed would sign a preimage nobody authorised.
	MessageHash     string `json:"messageHash"`
	RequestingChain string `json:"requestingChain"`
}

// =============================================================================
// Custody registry RPCs (replicated state)
// =============================================================================

// GetKeyParams contains parameters for getting a key.
type GetKeyParams struct {
	KeyID string `json:"keyId"`
}

func (vm *VM) rpcListKeys() ([]KeyInfo, error) {
	recs, err := vm.Keys()
	if err != nil {
		return nil, asRPCError(err)
	}
	keys := make([]KeyInfo, 0, len(recs))
	for _, rec := range recs {
		keys = append(keys, keyInfoOf(rec))
	}
	return keys, nil
}

func (vm *VM) rpcGetKey(params json.RawMessage) (*KeyInfo, error) {
	var p GetKeyParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: err.Error()}
	}
	rec, err := vm.Key(p.KeyID)
	if err != nil {
		return nil, asRPCError(err)
	}
	info := keyInfoOf(rec)
	return &info, nil
}

func (vm *VM) rpcGetPublicKey(params json.RawMessage) (map[string]string, error) {
	var p GetKeyParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: err.Error()}
	}
	pubKey, err := vm.PublicKey(p.KeyID)
	if err != nil {
		return nil, asRPCError(err)
	}
	return map[string]string{"publicKey": "0x" + hex.EncodeToString(pubKey)}, nil
}

func (vm *VM) rpcGetAddress(params json.RawMessage) (map[string]string, error) {
	var p GetKeyParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: err.Error()}
	}
	address, err := vm.Address(p.KeyID)
	if err != nil {
		return nil, asRPCError(err)
	}
	return map[string]string{"address": "0x" + hex.EncodeToString(address)}, nil
}

// =============================================================================
// Ceremony log RPCs (replicated state)
// =============================================================================

// GetCeremonyParams contains parameters for reading one ceremony.
type GetCeremonyParams struct {
	CeremonyID string `json:"ceremonyId"`
}

func (vm *VM) rpcGetCeremony(params json.RawMessage) (*CeremonyInfo, error) {
	var p GetCeremonyParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: err.Error()}
	}
	rec, err := vm.Ceremony(p.CeremonyID)
	if err != nil {
		return nil, &RPCError{Code: RPCErrorCeremonyNotFound, Message: err.Error()}
	}
	info := ceremonyInfoOf(rec)
	return &info, nil
}

func (vm *VM) rpcListCeremonies() ([]CeremonyInfo, error) {
	recs, err := vm.Ceremonies()
	if err != nil {
		return nil, asRPCError(err)
	}
	out := make([]CeremonyInfo, 0, len(recs))
	for _, rec := range recs {
		out = append(out, ceremonyInfoOf(rec))
	}
	return out, nil
}

func (vm *VM) rpcGetStateRoot() (map[string]string, error) {
	root := vm.StateRoot()
	return map[string]string{"stateRoot": "0x" + hex.EncodeToString(root[:])}, nil
}

// keyInfoOf projects a custody key's replicated record onto the wire. One
// conversion in one place: every RPC that returns a key returns the same shape,
// so a field cannot mean one thing under mpc_getKey and another under
// threshold_keygen.
func keyInfoOf(rec *KeyRecord) KeyInfo {
	participants := make([]string, len(rec.Participants))
	for i, p := range rec.Participants {
		participants[i] = string(p)
	}
	return KeyInfo{
		KeyID:          rec.KeyID,
		Kind:           rec.Kind,
		Policy:         rec.Policy.String(),
		Degree:         rec.Degree(),
		GroupPublicKey: "0x" + hex.EncodeToString(rec.GroupPublicKey),
		Address:        "0x" + hex.EncodeToString(rec.Address),
		Participants:   participants,
		Generation:     rec.Generation,
		CreatedHeight:  rec.CreatedHeight,
	}
}

// ceremonyInfoOf projects a ceremony record onto the wire, splitting the
// 65-byte artifact into r‖s‖v for callers whose verifier wants the parts.
func ceremonyInfoOf(c *CeremonyRecord) CeremonyInfo {
	signers := make([]string, len(c.Signers))
	for i, s := range c.Signers {
		signers[i] = string(s)
	}
	info := CeremonyInfo{
		CeremonyID:      c.ID,
		Kind:            c.Kind,
		KeyID:           c.KeyID,
		Digest:          "0x" + hex.EncodeToString(c.Digest),
		Signature:       "0x" + hex.EncodeToString(c.Artifact),
		Signers:         signers,
		RequestingChain: c.RequestingChain,
		Height:          c.Height,
	}
	if len(c.Artifact) == 65 {
		info.R = "0x" + hex.EncodeToString(c.Artifact[0:32])
		info.S = "0x" + hex.EncodeToString(c.Artifact[32:64])
		info.V = int(c.Artifact[64])
	}
	return info
}

// pendingRecord is the ceremony record a completed operation WILL be written
// as, once the block carrying it is accepted. Height is zero until then: the
// ceremony has happened, but the chain has not yet placed it at a height.
func pendingRecord(op *Operation) *CeremonyRecord {
	return &CeremonyRecord{
		ID:              op.CeremonyID,
		Kind:            op.Type,
		KeyID:           op.KeyID,
		Digest:          op.Digest,
		Signers:         op.Signers,
		Artifact:        op.Artifact,
		RequestingChain: op.RequestingChain,
	}
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
// Network Information RPCs
// =============================================================================

// Note: ThresholdInfo type is defined in client.go

func (vm *VM) rpcGetInfo() (*ThresholdInfo, error) {
	keys, err := vm.Keys()
	if err != nil {
		return nil, asRPCError(err)
	}
	root := vm.StateRoot()

	vm.mu.RLock()
	defer vm.mu.RUnlock()
	chains := make([]string, 0, len(vm.config.AuthorizedChains))
	for chainID := range vm.config.AuthorizedChains {
		chains = append(chains, chainID)
	}

	return &ThresholdInfo{
		Version:          Version.String(),
		NodeID:           vm.rt.NodeID.String(),
		ChainID:          vm.rt.ChainID.String(),
		PartyID:          string(vm.partyID),
		Policy:           vm.config.Policy.String(),
		AuthorizedChains: chains,
		TotalKeys:        len(keys),
		SharesHeld:       len(vm.shares),
		StagedCeremonies: len(vm.inflight),
		StateRoot:        "0x" + hex.EncodeToString(root[:]),
	}, nil
}

func (vm *VM) rpcGetStats() (*NetworkStats, error) {
	vm.mu.RLock()
	staged := len(vm.inflight)
	vm.mu.RUnlock()

	vm.stats.mu.RLock()
	defer vm.stats.mu.RUnlock()
	stats := &NetworkStats{
		TotalSignatures:   vm.stats.TotalSignatures,
		TotalKeygens:      vm.stats.TotalKeygens,
		StagedCeremonies:  staged,
		SignaturesByChain: make(map[string]uint64, len(vm.stats.SignaturesByChain)),
	}
	for k, v := range vm.stats.SignaturesByChain {
		stats.SignaturesByChain[k] = v
	}
	return stats, nil
}

// PartyInfo contains party information.
type PartyInfo struct {
	// PartyID and NodeID are the same value in two spellings — party.ID IS the
	// NodeID string — and both are reported so a caller reading either column
	// needs no side table to join them.
	PartyID string `json:"partyId"`
	NodeID  string `json:"nodeId"`
	IsLocal bool   `json:"isLocal"`
}

// rpcGetParties reports the ceremony committee: this chain's validator set.
// There is no separate MPC party roster to drift from it — joining the signing
// ring IS joining the validator set.
func (vm *VM) rpcGetParties(ctx context.Context) ([]PartyInfo, error) {
	vm.mu.RLock()
	height := vm.rt.PChainHeight
	self := vm.partyID
	vm.mu.RUnlock()

	committee, err := vm.Committee(ctx, height)
	if err != nil {
		return nil, asRPCError(err)
	}
	parties := make([]PartyInfo, len(committee))
	for i, pid := range committee {
		parties[i] = PartyInfo{
			PartyID: string(pid),
			NodeID:  string(pid),
			IsLocal: pid == self,
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
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: err.Error()}
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
		return nil, &RPCError{Code: RPCErrorInvalidParams, Message: err.Error()}
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

func (vm *VM) rpcHealthCheck(ctx context.Context) (map[string]interface{}, error) {
	health, err := vm.HealthCheck(ctx)
	if err != nil {
		return nil, asRPCError(err)
	}
	result := make(map[string]interface{}, len(health.Details)+1)
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
