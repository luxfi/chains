// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"encoding/json"
	"net/http"

	"github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/ai/pkg/attestation"
)

// Service provides AIVM RPC service
type Service struct {
	vm *VM
}

// Routes returns one handler per endpoint.
//
// The node mounts each key under /v1/chain/<chainID> and matches that full path
// EXACTLY, then hands the handler the request with the path it arrived on. A
// handler therefore never sees a path it can dispatch on, and no path below a
// mount is routable at all. The key IS the route — the same shape bridgevm and
// zkvm use.
func Routes(vm *VM) map[string]http.Handler {
	s := &Service{vm: vm}
	return map[string]http.Handler{
		"/providers":          http.HandlerFunc(s.handleProviders),
		"/providers/register": http.HandlerFunc(s.handleRegisterProvider),
		"/tasks":              http.HandlerFunc(s.handleTasks),
		"/tasks/submit":       http.HandlerFunc(s.handleSubmitTask),
		"/tasks/result":       http.HandlerFunc(s.handleSubmitResult),
		"/models":             http.HandlerFunc(s.handleModels),
		"/attestation/verify": http.HandlerFunc(s.handleVerifyAttestation),
		"/rewards/claim":      http.HandlerFunc(s.handleClaimRewards),
		"/rewards/stats":      http.HandlerFunc(s.handleRewardStats),
		"/stats":              http.HandlerFunc(s.handleStats),
		"/merkle":             http.HandlerFunc(s.handleMerkleRoot),
		"/health":             http.HandlerFunc(s.handleHealth),
	}
}

// handleProviders returns all registered providers
func (s *Service) handleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providers := s.vm.GetProviders()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": providers,
		"count":     len(providers),
	})
}

// RegisterProviderRequest is the request for registering a provider
type RegisterProviderRequest struct {
	ID             string                      `json:"id"`
	WalletAddress  string                      `json:"wallet_address"`
	Endpoint       string                      `json:"endpoint"`
	GPUs           []aivm.GPUInfo              `json:"gpus"`
	GPUAttestation *attestation.GPUAttestation `json:"gpu_attestation,omitempty"`
}

// handleRegisterProvider registers a new provider
func (s *Service) handleRegisterProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	provider := &aivm.Provider{
		ID:             req.ID,
		WalletAddress:  req.WalletAddress,
		Endpoint:       req.Endpoint,
		GPUs:           req.GPUs,
		GPUAttestation: req.GPUAttestation,
	}

	if err := s.vm.RegisterProvider(provider); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"providerId": req.ID,
	})
}

// handleTasks returns pending tasks
func (s *Service) handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	taskID := r.URL.Query().Get("id")
	if taskID != "" {
		task, err := s.vm.GetTask(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(task)
		return
	}

	// Return stats if no specific task requested
	json.NewEncoder(w).Encode(s.vm.GetStats())
}

// SubmitTaskRequest is the request for submitting a task
type SubmitTaskRequest struct {
	ID    string          `json:"id"`
	Type  string          `json:"type"`
	Model string          `json:"model"`
	Input json.RawMessage `json:"input"`
	Fee   uint64          `json:"fee"`
}

// handleSubmitTask submits a new task
func (s *Service) handleSubmitTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SubmitTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	task := &aivm.Task{
		ID:    req.ID,
		Type:  aivm.TaskType(req.Type),
		Model: req.Model,
		Input: req.Input,
		Fee:   req.Fee,
	}

	if err := s.vm.SubmitTask(task); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"taskId":  req.ID,
	})
}

// SubmitResultRequest is the request for submitting a task result
type SubmitResultRequest struct {
	TaskID      string          `json:"task_id"`
	ProviderID  string          `json:"provider_id"`
	Output      json.RawMessage `json:"output"`
	ComputeTime uint64          `json:"compute_time_ms"`
	Proof       []byte          `json:"proof"`
	Error       string          `json:"error,omitempty"`
}

// handleSubmitResult submits a task result
func (s *Service) handleSubmitResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SubmitResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := &aivm.TaskResult{
		TaskID:      req.TaskID,
		ProviderID:  req.ProviderID,
		Output:      req.Output,
		ComputeTime: req.ComputeTime,
		Proof:       req.Proof,
		Error:       req.Error,
	}

	if err := s.vm.SubmitResult(result); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"taskId":  req.TaskID,
	})
}

// handleModels returns available models
func (s *Service) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	models := s.vm.GetModels()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"models": models,
		"count":  len(models),
	})
}

// VerifyAttestationRequest is the request for verifying attestation
type VerifyAttestationRequest struct {
	GPUAttestation *attestation.GPUAttestation `json:"gpu_attestation"`
}

// handleVerifyAttestation verifies GPU attestation (local nvtrust)
func (s *Service) handleVerifyAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	status, err := s.vm.VerifyGPUAttestation(req.GPUAttestation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"verified":   status.Attested,
		"trustScore": status.TrustScore,
		"mode":       status.Mode,
		"hardwareCC": status.HardwareCC,
	})
}

// handleClaimRewards claims pending rewards
func (s *Service) handleClaimRewards(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ProviderID string `json:"provider_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claimed, err := s.vm.ClaimRewards(req.ProviderID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"claimed": claimed,
	})
}

// handleRewardStats returns reward statistics
func (s *Service) handleRewardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providerID := r.URL.Query().Get("provider_id")
	if providerID == "" {
		http.Error(w, "provider_id required", http.StatusBadRequest)
		return
	}

	stats, err := s.vm.GetRewardStats(providerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(stats)
}

// handleStats returns VM statistics
func (s *Service) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	json.NewEncoder(w).Encode(s.vm.GetStats())
}

// handleMerkleRoot returns merkle root for Q-Chain anchoring
func (s *Service) handleMerkleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	root := s.vm.GetMerkleRoot()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"merkleRoot": root,
	})
}

// handleHealth returns health status
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"healthy": s.vm.live(),
		"version": Version.String(),
	})
}
