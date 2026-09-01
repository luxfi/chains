// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/luxfi/ids"
)

var (
	errUnknownTransaction = errors.New("transaction not found")
	errNoCommitment       = errors.New("commitment required")
	errNoNullifier        = errors.New("nullifier required")
)

// The node mounts each CreateHandlers key under /v1/chain/<chainID> and matches
// that full path EXACTLY, then hands the handler the request with the path it
// arrived on. A mux behind one key therefore serves nothing: it dispatches on
// r.URL.Path, which is the mounted path and never the route it registered. The
// key IS the route; one handler per key.
func (vm *VM) endpoints() map[string]http.Handler {
	return map[string]http.Handler{
		"/sendTransaction":  post(vm.sendTransaction),
		"/getTransaction":   get(vm.getTransaction),
		"/getBlock":         get(vm.getBlock),
		"/getLatestBlock":   get(vm.getLatestBlock),
		"/getUTXO":          get(vm.getUTXO),
		"/getUTXOCount":     get(vm.getUTXOCount),
		"/isNullifierSpent": get(vm.isNullifierSpent),
		"/getStatus":        get(vm.getStatus),
		"/getProofStats":    get(vm.getProofStats),
	}
}

// handler is what an endpoint answers: a value to encode, or an error and the
// status that names it.
type handler func(*http.Request) (interface{}, int, error)

func get(h handler) http.Handler  { return method(http.MethodGet, h) }
func post(h handler) http.Handler { return method(http.MethodPost, h) }

func method(verb string, h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != verb {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		v, status, err := h(r)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		json.NewEncoder(w).Encode(v)
	})
}

func (vm *VM) sendTransaction(r *http.Request) (interface{}, int, error) {
	var tx Transaction
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, MaxTxSize)).Decode(&tx); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// Fee policy: refuse zero-fee user txs at the public entry before
	// mempool pressure. Internal callers reach Mempool directly.
	if err := vm.gateUserTx(&tx); err != nil {
		return nil, http.StatusPaymentRequired, err
	}

	// Shape too. A transaction that cannot be built into any block must not
	// occupy a slot in a bounded pool; assembly drops what it cannot build,
	// and this stops the obvious garbage arriving in the first place.
	if err := tx.ValidateBasic(); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := vm.mempool.AddTransaction(&tx); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// AddTransaction derives the id from the content, so this reports the
	// transaction the chain will carry rather than the one the caller named.
	return map[string]interface{}{"txID": tx.ID.String(), "success": true}, 0, nil
}

func (vm *VM) getTransaction(r *http.Request) (interface{}, int, error) {
	txID, err := ids.FromString(r.URL.Query().Get("txID"))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if !vm.mempool.HasTransaction(txID) {
		return nil, http.StatusNotFound, errUnknownTransaction
	}
	return map[string]interface{}{"status": "pending", "txID": txID.String()}, 0, nil
}

func (vm *VM) getBlock(r *http.Request) (interface{}, int, error) {
	blockID, err := ids.FromString(r.URL.Query().Get("blockID"))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	block, err := vm.GetBlock(r.Context(), blockID)
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	return block.(*Block).ToSummary(), 0, nil
}

func (vm *VM) getLatestBlock(r *http.Request) (interface{}, int, error) {
	id, _ := vm.chain.Tip()
	block, err := vm.GetBlock(r.Context(), id)
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	return block.(*Block).ToSummary(), 0, nil
}

func (vm *VM) getUTXO(r *http.Request) (interface{}, int, error) {
	commitment := r.URL.Query().Get("commitment")
	if commitment == "" {
		return nil, http.StatusBadRequest, errNoCommitment
	}
	utxo, err := vm.utxoDB.GetUTXO([]byte(commitment))
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	return utxo, 0, nil
}

func (vm *VM) getUTXOCount(*http.Request) (interface{}, int, error) {
	return map[string]interface{}{"count": vm.utxoDB.GetUTXOCount()}, 0, nil
}

// isNullifierSpent reports a READ FAILURE as a failure. Answering "not spent"
// for a set that could not be read is the answer that reopens a double spend.
func (vm *VM) isNullifierSpent(r *http.Request) (interface{}, int, error) {
	nullifier := r.URL.Query().Get("nullifier")
	if nullifier == "" {
		return nil, http.StatusBadRequest, errNoNullifier
	}
	height, spent, err := vm.nullifierDB.Spent([]byte(nullifier))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return map[string]interface{}{"nullifier": nullifier, "isSpent": spent, "height": height}, 0, nil
}

// getStatus answers what HealthCheck answers, which is always an answer.
func (vm *VM) getStatus(r *http.Request) (interface{}, int, error) {
	health, _ := vm.HealthCheck(r.Context())
	return health, 0, nil
}

func (vm *VM) getProofStats(*http.Request) (interface{}, int, error) {
	verifyCount, cacheHits, cacheMisses := vm.proofVerifier.GetStats()
	return map[string]interface{}{
		"verifyCount": verifyCount,
		"cacheHits":   cacheHits,
		"cacheMisses": cacheMisses,
		"cacheSize":   vm.proofVerifier.GetCacheSize(),
	}, 0, nil
}
