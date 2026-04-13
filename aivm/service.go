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

// NewService creates a new AIVM service
func NewService(vm *VM) http.Handler {
	s := &Service{vm: vm}
	mux := http.NewServeMux()

	// Provider endpoints
	mux.HandleFunc("/providers", s.handleProviders)
	mux.HandleFunc("/providers/register", s.handleRegisterProvider)

	// Task endpoints
	mux.HandleFunc("/tasks", s.handleTasks)
	mux.HandleFunc("/tasks/submit", s.handleSubmitTask)
	mux.HandleFunc("/tasks/result", s.handleSubmitResult)

	// Model endpoints
	mux.HandleFunc("/models", s.handleModels)

	// Attestation endpoints
	mux.HandleFunc("/attestation/verify", s.handleVerifyAttestation)

	// Reward endpoints
	mux.HandleFunc("/rewards/claim", s.handleClaimRewards)
	mux.HandleFunc("/rewards/stats", s.handleRewardStats)

	// Stats endpoints
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/merkle", s.handleMerkleRoot)

	// Health endpoint
	mux.HandleFunc("/health", s.handleHealth)

	return mux
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
		"healthy": s.vm.running,
		"version": Version.String(),
	})
}
