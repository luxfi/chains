// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/ids"
)

// Service is the K-Chain JSON-RPC surface. Mutating operations are submitted as
// CLIENT-SIGNED transactions (the client holds its own key; K never does) and
// take effect only through fee-settled consensus blocks. Everything else is a
// read-only query of PUBLIC state. There is no synchronous key creation, no
// encryption endpoint, and no "fee" integer in any request — the prior design's
// secret-bearing, fee-as-JSON-integer surface is gone.
type Service struct {
	vm *VM
}

// ---- Mutating: submit a signed transaction ----

// SubmitTransactionArgs carries a hex-encoded, client-signed transaction
// (Transaction.Bytes()). The client builds and signs it offline with its own
// ML-DSA-65 key; K only verifies the signature and settles the fee.
type SubmitTransactionArgs struct {
	Tx string `json:"tx"`
}

// SubmitTransactionReply returns the accepted transaction's ID. The fee is
// settled when the transaction's block is accepted, not here.
type SubmitTransactionReply struct {
	TxID string `json:"txId"`
}

// SubmitTransaction parses, authenticates, admission-checks, and enqueues a
// signed transaction.
func (s *Service) SubmitTransaction(r *http.Request, args *SubmitTransactionArgs, reply *SubmitTransactionReply) error {
	raw, err := hex.DecodeString(strings.TrimPrefix(args.Tx, "0x"))
	if err != nil {
		return err
	}
	tx, err := ParseTransaction(raw)
	if err != nil {
		return err
	}
	id, err := s.vm.SubmitTx(tx)
	if err != nil {
		return err
	}
	reply.TxID = id.String()
	return nil
}

// ---- Read-only queries (PUBLIC state only) ----

// KeyView is the PUBLIC JSON view of a key record. It exposes the public key and
// commitments; there is no field for a private key or share because none exists.
type KeyView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Algorithm   string   `json:"algorithm"`
	PublicKey   string   `json:"publicKey"` // base64
	Threshold   uint32   `json:"threshold"`
	TotalShares uint32   `json:"totalShares"`
	Commitments []string `json:"commitments"` // base64 public VSS commitments
	Committee   []string `json:"committee"`
	Owner       string   `json:"owner"`
	Status      string   `json:"status"`
	CreatedAt   int64    `json:"createdAt"`
	UpdatedAt   int64    `json:"updatedAt"`
}

func toKeyView(r *KeyRecord) KeyView {
	commits := make([]string, len(r.Commitments))
	for i, c := range r.Commitments {
		commits[i] = base64.StdEncoding.EncodeToString(c)
	}
	committee := make([]string, len(r.Committee))
	for i, n := range r.Committee {
		committee[i] = n.String()
	}
	return KeyView{
		ID:          r.ID.String(),
		Name:        r.Name,
		Algorithm:   r.Algorithm,
		PublicKey:   base64.StdEncoding.EncodeToString(r.PublicKey),
		Threshold:   r.Threshold,
		TotalShares: r.TotalShares,
		Commitments: commits,
		Committee:   committee,
		Owner:       r.Owner.String(),
		Status:      r.Status,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// GetKeyArgs selects a key by ID or Name (ID takes precedence).
type GetKeyArgs struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GetKeyReply returns the public key view.
type GetKeyReply struct {
	Key KeyView `json:"key"`
}

// GetKey returns a key record by ID or name.
func (s *Service) GetKey(r *http.Request, args *GetKeyArgs, reply *GetKeyReply) error {
	var rec *KeyRecord
	var ok bool
	if args.ID != "" {
		id, err := ids.FromString(args.ID)
		if err != nil {
			return err
		}
		rec, ok = s.vm.KeyByID(id)
	} else {
		rec, ok = s.vm.KeyByName(args.Name)
	}
	if !ok {
		return ErrKeyNotFound
	}
	reply.Key = toKeyView(rec)
	return nil
}

// ListKeysArgs filters the key listing.
type ListKeysArgs struct {
	Algorithm string `json:"algorithm"`
	Status    string `json:"status"`
}

// ListKeysReply returns matching key views.
type ListKeysReply struct {
	Keys  []KeyView `json:"keys"`
	Total int       `json:"total"`
}

// ListKeys lists keys, optionally filtered by algorithm and status.
func (s *Service) ListKeys(r *http.Request, args *ListKeysArgs, reply *ListKeysReply) error {
	for _, rec := range s.vm.Keys() {
		if args.Algorithm != "" && rec.Algorithm != args.Algorithm {
			continue
		}
		if args.Status != "" && rec.Status != args.Status {
			continue
		}
		reply.Keys = append(reply.Keys, toKeyView(rec))
	}
	reply.Total = len(reply.Keys)
	return nil
}

// GetCeremonyArgs selects a ceremony by ID.
type GetCeremonyArgs struct {
	ID string `json:"id"`
}

// CeremonyView is the PUBLIC view of a ceremony record.
type CeremonyView struct {
	ID        string `json:"id"`
	KeyID     string `json:"keyId"`
	Type      string `json:"type"`
	Requester string `json:"requester"`
	Message   string `json:"message"` // base64 public digest
	Result    string `json:"result"`  // base64 public result
	Status    string `json:"status"`
	CreatedAt int64  `json:"createdAt"`
}

// GetCeremonyReply returns the ceremony view.
type GetCeremonyReply struct {
	Ceremony CeremonyView `json:"ceremony"`
}

// GetCeremony returns an authorized/fulfilled ceremony record.
func (s *Service) GetCeremony(r *http.Request, args *GetCeremonyArgs, reply *GetCeremonyReply) error {
	id, err := ids.FromString(args.ID)
	if err != nil {
		return err
	}
	c, ok := s.vm.Ceremony(id)
	if !ok {
		return ErrInvalidCeremony
	}
	reply.Ceremony = CeremonyView{
		ID:        c.ID.String(),
		KeyID:     c.KeyID.String(),
		Type:      c.Type,
		Requester: c.Requester.String(),
		Message:   base64.StdEncoding.EncodeToString(c.Message),
		Result:    base64.StdEncoding.EncodeToString(c.Result),
		Status:    c.Status,
		CreatedAt: c.CreatedAt,
	}
	return nil
}

// BalanceArgs selects an account by hex address.
type BalanceArgs struct {
	Address string `json:"address"`
}

// BalanceReply returns the account balance and total burned supply, both nLUX.
type BalanceReply struct {
	BalanceNLUX uint64 `json:"balanceNLux"`
	BurnedNLUX  uint64 `json:"burnedNLux"`
}

// Balance returns an account's spendable balance and the chain's burned supply.
func (s *Service) Balance(r *http.Request, args *BalanceArgs, reply *BalanceReply) error {
	acct, err := accountFromHex(args.Address)
	if err != nil {
		return err
	}
	bal, err := s.vm.Balance(acct)
	if err != nil {
		return err
	}
	burned, err := s.vm.Burned()
	if err != nil {
		return err
	}
	reply.BalanceNLUX = bal
	reply.BurnedNLUX = burned
	return nil
}

// ---- Diagnostics ----

// HealthArgs is empty.
type HealthArgs struct{}

// HealthReply reports VM health.
type HealthReply struct {
	Healthy bool              `json:"healthy"`
	Details map[string]string `json:"details"`
}

// Health reports VM health.
func (s *Service) Health(r *http.Request, args *HealthArgs, reply *HealthReply) error {
	res, err := s.vm.HealthCheck(context.Background())
	if err != nil {
		return err
	}
	reply.Healthy = res.Healthy
	reply.Details = res.Details
	return nil
}

// FeeScheduleArgs is empty.
type FeeScheduleArgs struct{}

// FeeScheduleEntry prices one (operation, algorithm) pair.
type FeeScheduleEntry struct {
	Operation string `json:"operation"`
	Algorithm string `json:"algorithm"`
	Gas       uint64 `json:"gas"`
	FeeNLUX   uint64 `json:"feeNLux"`
}

// FeeScheduleReply returns the per-algorithm gas/fee schedule and the price.
type FeeScheduleReply struct {
	GasPrice uint64             `json:"gasPriceNLuxPerGas"`
	Entries  []FeeScheduleEntry `json:"entries"`
}

// FeeSchedule returns the chain's per-operation, per-algorithm fee schedule so
// clients can compute the exact burn before submitting a transaction.
func (s *Service) FeeSchedule(r *http.Request, args *FeeScheduleArgs, reply *FeeScheduleReply) error {
	reply.GasPrice = uint64(GasPrice)
	opNames := map[uint8]string{
		TxRegisterKey: "registerKey",
		TxSetPolicy:   "setPolicy",
		TxAuthorize:   "authorize",
		TxRevokeKey:   "revokeKey",
	}
	for op, name := range opNames {
		if usesAlgorithm(op) {
			for algo := range algoGas {
				tx := &Transaction{Type: op, Algorithm: algo}
				g, _ := GasFor(tx)
				f, _ := fee.Cost(g, GasPrice)
				reply.Entries = append(reply.Entries, FeeScheduleEntry{
					Operation: name, Algorithm: algo, Gas: uint64(g), FeeNLUX: f,
				})
			}
		} else {
			tx := &Transaction{Type: op}
			g, _ := GasFor(tx)
			f, _ := fee.Cost(g, GasPrice)
			reply.Entries = append(reply.Entries, FeeScheduleEntry{
				Operation: name, Algorithm: "", Gas: uint64(g), FeeNLUX: f,
			})
		}
	}
	return nil
}
