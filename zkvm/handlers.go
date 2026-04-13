// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/json"
	"net/http"

	"github.com/luxfi/ids"
)

// NewRPCHandler creates the main RPC handler
func NewRPCHandler(vm *VM) http.Handler {
	mux := http.NewServeMux()

	// Transaction endpoints
	mux.HandleFunc("/sendTransaction", handleSendTransaction(vm))
	mux.HandleFunc("/getTransaction", handleGetTransaction(vm))
	mux.HandleFunc("/createShieldedTransaction", handleCreateShieldedTransaction(vm))

	// Block endpoints
	mux.HandleFunc("/getBlock", handleGetBlock(vm))
	mux.HandleFunc("/getLatestBlock", handleGetLatestBlock(vm))

	// UTXO endpoints
	mux.HandleFunc("/getUTXO", handleGetUTXO(vm))
	mux.HandleFunc("/getUTXOCount", handleGetUTXOCount(vm))

	// Status endpoints
	mux.HandleFunc("/getStatus", handleGetStatus(vm))

	return mux
}

// NewPrivacyHandler creates the privacy-specific handler
func NewPrivacyHandler(vm *VM) http.Handler {
	mux := http.NewServeMux()

	// Address management
	mux.HandleFunc("/generateAddress", handleGenerateAddress(vm))
	mux.HandleFunc("/getAddress", handleGetAddress(vm))

	// Note decryption
	mux.HandleFunc("/decryptNote", handleDecryptNote(vm))

	// Nullifier queries
	mux.HandleFunc("/isNullifierSpent", handleIsNullifierSpent(vm))

	return mux
}

// NewProofHandler creates the proof-specific handler
func NewProofHandler(vm *VM) http.Handler {
	mux := http.NewServeMux()

	// Proof generation
	mux.HandleFunc("/generateTransferProof", handleGenerateTransferProof(vm))
	mux.HandleFunc("/generateShieldProof", handleGenerateShieldProof(vm))

	// Proof verification
	mux.HandleFunc("/verifyProof", handleVerifyProof(vm))

	// Proof statistics
	mux.HandleFunc("/getProofStats", handleGetProofStats(vm))

	return mux
}

// Transaction handlers

func handleSendTransaction(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var tx Transaction
		if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Add to mempool
		if err := vm.mempool.AddTransaction(&tx); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := map[string]interface{}{
			"txID":    tx.ID.String(),
			"success": true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func handleGetTransaction(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txIDStr := r.URL.Query().Get("txID")
		if txIDStr == "" {
			http.Error(w, "txID required", http.StatusBadRequest)
			return
		}

		txID, err := ids.FromString(txIDStr)
		if err != nil {
			http.Error(w, "Invalid txID", http.StatusBadRequest)
			return
		}

		// Check mempool first
		if vm.mempool.HasTransaction(txID) {
			resp := map[string]interface{}{
				"status": "pending",
				"txID":   txID.String(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		http.Error(w, "Transaction not found", http.StatusNotFound)
	}
}

func handleCreateShieldedTransaction(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"error": "Not implemented",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// Block handlers

func handleGetBlock(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		blockIDStr := r.URL.Query().Get("blockID")
		if blockIDStr == "" {
			http.Error(w, "blockID required", http.StatusBadRequest)
			return
		}

		blockID, err := ids.FromString(blockIDStr)
		if err != nil {
			http.Error(w, "Invalid blockID", http.StatusBadRequest)
			return
		}

		block, err := vm.GetBlock(r.Context(), blockID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		zkBlock := block.(*Block)
		resp := zkBlock.ToSummary()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func handleGetLatestBlock(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vm.mu.RLock()
		block := vm.lastAccepted
		vm.mu.RUnlock()

		resp := block.ToSummary()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// UTXO handlers

func handleGetUTXO(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		commitment := r.URL.Query().Get("commitment")
		if commitment == "" {
			http.Error(w, "commitment required", http.StatusBadRequest)
			return
		}

		utxo, err := vm.utxoDB.GetUTXO([]byte(commitment))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(utxo)
	}
}

func handleGetUTXOCount(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		count := vm.utxoDB.GetUTXOCount()

		resp := map[string]interface{}{
			"count": count,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// Status handler

func handleGetStatus(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health, err := vm.HealthCheck(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(health)
	}
}

// Privacy handlers

func handleGenerateAddress(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		addr, err := vm.addressManager.GenerateAddress()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := map[string]interface{}{
			"address":         addr.Address,
			"viewingKey":      addr.ViewingKey,
			"incomingViewKey": addr.IncomingViewKey,
			"diversifier":     addr.Diversifier,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func handleGetAddress(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Would implement address lookup
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	}
}

func handleDecryptNote(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Would implement note decryption
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	}
}

func handleIsNullifierSpent(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nullifier := r.URL.Query().Get("nullifier")
		if nullifier == "" {
			http.Error(w, "nullifier required", http.StatusBadRequest)
			return
		}

		isSpent := vm.nullifierDB.IsNullifierSpent([]byte(nullifier))

		resp := map[string]interface{}{
			"nullifier": nullifier,
			"isSpent":   isSpent,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// Proof handlers

func handleGenerateTransferProof(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Would implement proof generation
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	}
}

func handleGenerateShieldProof(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Would implement shield proof generation
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	}
}

func handleVerifyProof(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Would implement proof verification endpoint
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	}
}

func handleGetProofStats(vm *VM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		verifyCount, cacheHits, cacheMisses := vm.proofVerifier.GetStats()

		resp := map[string]interface{}{
			"verifyCount": verifyCount,
			"cacheHits":   cacheHits,
			"cacheMisses": cacheMisses,
			"cacheSize":   vm.proofVerifier.GetCacheSize(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
