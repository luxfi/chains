// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/rpc/v2"
	"github.com/luxfi/ids"
)

// Service provides JSON-RPC endpoints for BridgeVM LP-333 signer management
type Service struct {
	vm *VM
}

// NewService returns a new Service instance
func NewService(vm *VM) *Service {
	return &Service{vm: vm}
}

// RegisterService registers the BridgeVM RPC handlers
func (vm *VM) RegisterService(server *rpc.Server) error {
	return server.RegisterService(&Service{vm: vm}, "bridge")
}

// =============================================================================
// LP-333 JSON-RPC Endpoints
// =============================================================================

// RegisterValidatorArgs are the arguments for bridge_registerValidator
type RegisterValidatorArgs struct {
	NodeID     string `json:"nodeId"`
	BondAmount string `json:"bondAmount,omitempty"` // 100M LUX bond (slashable)
	MPCPubKey  string `json:"mpcPubKey,omitempty"`
}

// RegisterValidatorReply is the reply for bridge_registerValidator
type RegisterValidatorReply struct {
	Success        bool   `json:"success"`
	NodeID         string `json:"nodeId"`
	Registered     bool   `json:"registered"`
	Waitlisted     bool   `json:"waitlisted"`
	SignerIndex    int    `json:"signerIndex"`
	WaitlistIndex  int    `json:"waitlistIndex,omitempty"`
	TotalSigners   int    `json:"totalSigners"`
	Threshold      int    `json:"threshold"`
	ReshareNeeded  bool   `json:"reshareNeeded"`
	CurrentEpoch   uint64 `json:"currentEpoch"`
	SetFrozen      bool   `json:"setFrozen"`
	RemainingSlots int    `json:"remainingSlots"`
	Message        string `json:"message"`
}

// RegisterValidator registers a validator as a bridge signer (LP-333 opt-in model)
// First 100 validators are accepted directly without reshare.
// After 100 signers, new validators go to waitlist.
func (s *Service) RegisterValidator(_ *http.Request, args *RegisterValidatorArgs, reply *RegisterValidatorReply) error {
	input := &RegisterValidatorInput{
		NodeID:     args.NodeID,
		BondAmount: args.BondAmount,
		MPCPubKey:  args.MPCPubKey,
	}

	result, err := s.vm.RegisterValidator(input)
	if err != nil {
		return err
	}

	reply.Success = result.Success
	reply.NodeID = result.NodeID
	reply.Registered = result.Registered
	reply.Waitlisted = result.Waitlisted
	reply.SignerIndex = result.SignerIndex
	reply.WaitlistIndex = result.WaitlistIndex
	reply.TotalSigners = result.TotalSigners
	reply.Threshold = result.Threshold
	reply.ReshareNeeded = result.ReshareNeeded
	reply.CurrentEpoch = result.CurrentEpoch
	reply.SetFrozen = result.SetFrozen
	reply.RemainingSlots = result.RemainingSlots
	reply.Message = result.Message

	return nil
}

// GetSignerSetInfoArgs are the arguments for bridge_getSignerSetInfo (empty)
type GetSignerSetInfoArgs struct{}

// GetSignerSetInfoReply is the reply for bridge_getSignerSetInfo
type GetSignerSetInfoReply struct {
	TotalSigners   int               `json:"totalSigners"`
	Threshold      int               `json:"threshold"`
	MaxSigners     int               `json:"maxSigners"`
	CurrentEpoch   uint64            `json:"currentEpoch"`
	SetFrozen      bool              `json:"setFrozen"`
	RemainingSlots int               `json:"remainingSlots"`
	WaitlistSize   int               `json:"waitlistSize"`
	Signers        []SignerInfoReply `json:"signers"`
	PublicKey      string            `json:"publicKey,omitempty"`
}

// SignerInfoReply contains signer information for RPC replies
type SignerInfoReply struct {
	NodeID     string `json:"nodeId"`
	PartyID    string `json:"partyId"`
	BondAmount uint64 `json:"bondAmount"` // 100M LUX bond (slashable)
	Active     bool   `json:"active"`
	JoinedAt   string `json:"joinedAt"`
	SlotIndex  int    `json:"slotIndex"`
	Slashed    bool   `json:"slashed"`
	SlashCount int    `json:"slashCount"`
}

// GetSignerSetInfo returns information about the current signer set (LP-333)
func (s *Service) GetSignerSetInfo(_ *http.Request, _ *GetSignerSetInfoArgs, reply *GetSignerSetInfoReply) error {
	info := s.vm.GetSignerSetInfo()

	reply.TotalSigners = info.TotalSigners
	reply.Threshold = info.Threshold
	reply.MaxSigners = info.MaxSigners
	reply.CurrentEpoch = info.CurrentEpoch
	reply.SetFrozen = info.SetFrozen
	reply.RemainingSlots = info.RemainingSlots
	reply.WaitlistSize = info.WaitlistSize
	reply.PublicKey = info.PublicKey

	reply.Signers = make([]SignerInfoReply, len(info.Signers))
	for i, signer := range info.Signers {
		reply.Signers[i] = SignerInfoReply{
			NodeID:     signer.NodeID.String(),
			PartyID:    string(signer.PartyID),
			BondAmount: signer.BondAmount,
			Active:     signer.Active,
			JoinedAt:   signer.JoinedAt.Format("2006-01-02T15:04:05Z"),
			SlotIndex:  signer.SlotIndex,
			Slashed:    signer.Slashed,
			SlashCount: signer.SlashCount,
		}
	}

	return nil
}

// ReplaceSignerArgs are the arguments for bridge_replaceSigner
type ReplaceSignerArgs struct {
	NodeID            string `json:"nodeId"`            // Signer to remove
	ReplacementNodeID string `json:"replacementNodeId"` // Explicit replacement (optional, uses waitlist if empty)
}

// ReplaceSignerReply is the reply for bridge_replaceSigner
type ReplaceSignerReply struct {
	Success           bool   `json:"success"`
	RemovedNodeID     string `json:"removedNodeId,omitempty"`
	ReplacementNodeID string `json:"replacementNodeId,omitempty"`
	ReshareSession    string `json:"reshareSession,omitempty"`
	NewEpoch          uint64 `json:"newEpoch"`
	ActiveSigners     int    `json:"activeSigners"`
	Threshold         int    `json:"threshold"`
	Message           string `json:"message"`
}

// ReplaceSigner removes a failed signer and triggers reshare (LP-333)
// This is the ONLY operation that triggers a reshare.
func (s *Service) ReplaceSigner(_ *http.Request, args *ReplaceSignerArgs, reply *ReplaceSignerReply) error {
	nodeID, err := ids.NodeIDFromString(args.NodeID)
	if err != nil {
		return err
	}

	var replacementNodeID *ids.NodeID
	if args.ReplacementNodeID != "" {
		rid, err := ids.NodeIDFromString(args.ReplacementNodeID)
		if err != nil {
			return err
		}
		replacementNodeID = &rid
	}

	result, err := s.vm.RemoveSigner(nodeID, replacementNodeID)
	if err != nil {
		return err
	}

	reply.Success = result.Success
	reply.RemovedNodeID = result.RemovedNodeID
	reply.ReplacementNodeID = result.ReplacementNodeID
	reply.ReshareSession = result.ReshareSession
	reply.NewEpoch = result.NewEpoch
	reply.ActiveSigners = result.ActiveSigners
	reply.Threshold = result.Threshold
	reply.Message = result.Message

	return nil
}

// HasSignerArgs are the arguments for bridge_hasSigner
type HasSignerArgs struct {
	NodeID string `json:"nodeId"`
}

// HasSignerReply is the reply for bridge_hasSigner
type HasSignerReply struct {
	IsSigner bool `json:"isSigner"`
}

// HasSigner checks if a node is in the active signer set
func (s *Service) HasSigner(_ *http.Request, args *HasSignerArgs, reply *HasSignerReply) error {
	nodeID, err := ids.NodeIDFromString(args.NodeID)
	if err != nil {
		return err
	}

	reply.IsSigner = s.vm.HasSigner(nodeID)
	return nil
}

// GetWaitlistArgs are the arguments for bridge_getWaitlist (empty)
type GetWaitlistArgs struct{}

// GetWaitlistReply is the reply for bridge_getWaitlist
type GetWaitlistReply struct {
	WaitlistSize int      `json:"waitlistSize"`
	NodeIDs      []string `json:"nodeIds"`
}

// GetWaitlist returns the current waitlist of validators waiting for signer slots
func (s *Service) GetWaitlist(_ *http.Request, _ *GetWaitlistArgs, reply *GetWaitlistReply) error {
	s.vm.mu.RLock()
	defer s.vm.mu.RUnlock()

	reply.WaitlistSize = len(s.vm.signerSet.Waitlist)
	reply.NodeIDs = make([]string, len(s.vm.signerSet.Waitlist))
	for i, nodeID := range s.vm.signerSet.Waitlist {
		reply.NodeIDs[i] = nodeID.String()
	}

	return nil
}

// GetCurrentEpochArgs are the arguments for bridge_getCurrentEpoch (empty)
type GetCurrentEpochArgs struct{}

// GetCurrentEpochReply is the reply for bridge_getCurrentEpoch
type GetCurrentEpochReply struct {
	Epoch        uint64 `json:"epoch"`
	TotalSigners int    `json:"totalSigners"`
	Threshold    int    `json:"threshold"`
	SetFrozen    bool   `json:"setFrozen"`
}

// GetCurrentEpoch returns the current epoch (incremented only on reshare)
func (s *Service) GetCurrentEpoch(_ *http.Request, _ *GetCurrentEpochArgs, reply *GetCurrentEpochReply) error {
	s.vm.mu.RLock()
	defer s.vm.mu.RUnlock()

	reply.Epoch = s.vm.signerSet.CurrentEpoch
	reply.TotalSigners = len(s.vm.signerSet.Signers)
	reply.Threshold = s.vm.signerSet.ThresholdT
	reply.SetFrozen = s.vm.signerSet.SetFrozen

	return nil
}

// SlashSignerArgs are the arguments for bridge_slashSigner
type SlashSignerArgs struct {
	NodeID       string `json:"nodeId"`
	Reason       string `json:"reason"`
	SlashPercent int    `json:"slashPercent"` // Percentage of bond to slash (1-100)
	Evidence     string `json:"evidence"`     // Hex-encoded proof of misbehavior
}

// SlashSignerReply is the reply for bridge_slashSigner
type SlashSignerReply struct {
	Success         bool   `json:"success"`
	NodeID          string `json:"nodeId"`
	SlashedAmount   uint64 `json:"slashedAmount"`
	RemainingBond   uint64 `json:"remainingBond"`
	TotalSlashCount int    `json:"totalSlashCount"`
	RemovedFromSet  bool   `json:"removedFromSet"`
	Message         string `json:"message"`
}

// SlashSigner slashes a misbehaving bridge signer's bond
// The bond is NOT stake - it's a slashable deposit that can be partially or fully seized
func (s *Service) SlashSigner(_ *http.Request, args *SlashSignerArgs, reply *SlashSignerReply) error {
	nodeID, err := ids.NodeIDFromString(args.NodeID)
	if err != nil {
		return err
	}

	input := &SlashSignerInput{
		NodeID:       nodeID,
		Reason:       args.Reason,
		SlashPercent: args.SlashPercent,
		Evidence:     []byte(args.Evidence),
	}

	result, err := s.vm.SlashSigner(input)
	if err != nil {
		return err
	}

	reply.Success = result.Success
	reply.NodeID = result.NodeID
	reply.SlashedAmount = result.SlashedAmount
	reply.RemainingBond = result.RemainingBond
	reply.TotalSlashCount = result.TotalSlashCount
	reply.RemovedFromSet = result.RemovedFromSet
	reply.Message = result.Message

	return nil
}

// =============================================================================
// HTTP Handler Integration
// =============================================================================

// CreateRPCHandlers creates HTTP handlers for JSON-RPC endpoints
func (vm *VM) CreateRPCHandlers() (map[string]http.Handler, error) {
	service := NewService(vm)

	// Create a simple HTTP handler that wraps the service methods
	handlers := map[string]http.Handler{
		"/rpc": &jsonRPCHandler{service: service},
	}

	return handlers, nil
}

// jsonRPCHandler handles JSON-RPC requests
type jsonRPCHandler struct {
	service *Service
}

// jsonRPCRequest represents a JSON-RPC request
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

// jsonRPCResponse represents a JSON-RPC response
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id"`
}

// jsonRPCError represents a JSON-RPC error
type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (h *jsonRPCHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, nil, -32700, "parse error", err)
		return
	}

	var result interface{}
	var err error

	switch req.Method {
	case "bridge_registerValidator", "bridge.registerValidator":
		var args RegisterValidatorArgs
		if err := json.Unmarshal(req.Params, &args); err != nil {
			h.writeError(w, req.ID, -32602, "invalid params", err)
			return
		}
		var reply RegisterValidatorReply
		err = h.service.RegisterValidator(r, &args, &reply)
		result = reply

	case "bridge_getSignerSetInfo", "bridge.getSignerSetInfo":
		var reply GetSignerSetInfoReply
		err = h.service.GetSignerSetInfo(r, &GetSignerSetInfoArgs{}, &reply)
		result = reply

	case "bridge_replaceSigner", "bridge.replaceSigner":
		var args ReplaceSignerArgs
		if err := json.Unmarshal(req.Params, &args); err != nil {
			h.writeError(w, req.ID, -32602, "invalid params", err)
			return
		}
		var reply ReplaceSignerReply
		err = h.service.ReplaceSigner(r, &args, &reply)
		result = reply

	case "bridge_hasSigner", "bridge.hasSigner":
		var args HasSignerArgs
		if err := json.Unmarshal(req.Params, &args); err != nil {
			h.writeError(w, req.ID, -32602, "invalid params", err)
			return
		}
		var reply HasSignerReply
		err = h.service.HasSigner(r, &args, &reply)
		result = reply

	case "bridge_getWaitlist", "bridge.getWaitlist":
		var reply GetWaitlistReply
		err = h.service.GetWaitlist(r, &GetWaitlistArgs{}, &reply)
		result = reply

	case "bridge_getCurrentEpoch", "bridge.getCurrentEpoch":
		var reply GetCurrentEpochReply
		err = h.service.GetCurrentEpoch(r, &GetCurrentEpochArgs{}, &reply)
		result = reply

	case "bridge_slashSigner", "bridge.slashSigner":
		var args SlashSignerArgs
		if err := json.Unmarshal(req.Params, &args); err != nil {
			h.writeError(w, req.ID, -32602, "invalid params", err)
			return
		}
		var reply SlashSignerReply
		err = h.service.SlashSigner(r, &args, &reply)
		result = reply

	default:
		h.writeError(w, req.ID, -32601, "method not found", nil)
		return
	}

	if err != nil {
		h.writeError(w, req.ID, -32000, "server error", err)
		return
	}

	h.writeResult(w, req.ID, result)
}

func (h *jsonRPCHandler) writeResult(w http.ResponseWriter, id interface{}, result interface{}) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *jsonRPCHandler) writeError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
