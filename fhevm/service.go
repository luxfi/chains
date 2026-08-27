// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
)

// Service is the F-Chain JSON-RPC surface. Mutating operations are submitted as
// CLIENT-SIGNED transactions and take effect only through fee-settled consensus
// blocks. Everything else is a read-only query of PUBLIC state. There is no
// endpoint that decrypts, none that returns a ciphertext body, and no "fee"
// integer in any request — a fee is never an unbacked number a caller writes
// down, it is gas metered and burned from the payer's on-chain balance inside
// consensus.
//
// Two of the methods report the FHE RUNTIME's configuration rather than F's
// ledger — the public parameters and the seated committee — and those answer in
// the runtime's own reply types (github.com/luxfi/chains/mpcvm/fhe), so a client
// that understands the runtime understands F. The rest describe F's ledger and
// answer in F's own views. That is the whole rule: runtime types for runtime
// facts, F's views for F's records.
type Service struct {
	vm *VM
}

// ---- Mutating: submit a signed transaction ----

// SubmitTransactionArgs carries a hex-encoded, client-signed transaction
// (Transaction.Bytes()). The client builds and signs it offline with its own
// ML-DSA-65 key; F only verifies the signature and settles the fee.
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

// ---- FHE runtime facts ----

// GetPublicParams returns the FHE parameters this network encrypts under,
// together with the seated epoch's threshold and network public key. The
// parameters come from the runtime's own threshold configuration, so a client
// encrypting for F and a node evaluating for F agree by construction.
func (s *Service) GetPublicParams(r *http.Request, args *fhe.GetPublicParamsArgs, reply *fhe.GetPublicParamsReply) error {
	cfg := fhe.DefaultThresholdConfig()
	epoch := s.vm.CurrentEpoch()
	reply.Epoch = epoch
	reply.LogN = cfg.CKKSParams.LogN()
	reply.LogQP = int(cfg.CKKSParams.LogQ() + cfg.CKKSParams.LogP())
	reply.LogScale = cfg.CKKSParams.LogDefaultScale()
	reply.ChainID = s.vm.chainID.String()
	if rec, ok := s.vm.Epoch(epoch); ok {
		reply.Threshold = rec.Threshold
		reply.PublicKey = hex.EncodeToString(rec.PublicKey)
	}
	return nil
}

// GetCommittee returns the threshold committee for an epoch (the seated one by
// default). These are the members whose attestations answer a decryption
// request and install the next epoch.
func (s *Service) GetCommittee(r *http.Request, args *fhe.GetCommitteeArgs, reply *fhe.GetCommitteeReply) error {
	n := s.vm.CurrentEpoch()
	if args.Epoch != nil {
		n = *args.Epoch
	}
	rec, ok := s.vm.Epoch(n)
	if !ok {
		return ErrEpochNotFound
	}
	reply.Epoch = rec.Epoch
	reply.Threshold = rec.Threshold
	reply.Members = make([]fhe.CommitteeMemberInfo, len(rec.Committee))
	for i, m := range rec.Committee {
		reply.Members[i] = fhe.CommitteeMemberInfo{
			NodeID:    m.NodeID.String(),
			PublicKey: hex.EncodeToString(m.PublicKey),
			Weight:    m.Weight,
			Index:     m.Index,
		}
	}
	return nil
}

// ---- F's ledger ----

// CiphertextView is the PUBLIC view of a registered encrypted value. It carries
// the digest of the ciphertext body so a client can check a body it fetched
// from off-chain storage; it does not carry the body, because F never has it.
type CiphertextView struct {
	Handle       string `json:"handle"`
	Owner        string `json:"owner"`
	Scheme       string `json:"scheme"`
	Digest       string `json:"digest"`
	Type         uint8  `json:"type"`
	Level        int    `json:"level"`
	Epoch        uint64 `json:"epoch"`
	Size         uint32 `json:"size"`
	RegisteredAt int64  `json:"registeredAt"`
	ChainID      string `json:"chainId"`
}

func toCiphertextView(r *CiphertextRecord) CiphertextView {
	return CiphertextView{
		Handle:       hex.EncodeToString(r.Handle[:]),
		Owner:        fee.Account(r.Owner).String(),
		Scheme:       r.Scheme,
		Digest:       hex.EncodeToString(r.Digest[:]),
		Type:         r.Type,
		Level:        r.Level,
		Epoch:        r.Epoch,
		Size:         r.Size,
		RegisteredAt: r.RegisteredAt,
		ChainID:      r.ChainID.String(),
	}
}

// GetCiphertextArgs selects a ciphertext by handle.
type GetCiphertextArgs struct {
	Handle string `json:"handle"` // hex-encoded 32 bytes
}

// GetCiphertextReply returns the public ciphertext view.
type GetCiphertextReply struct {
	Ciphertext CiphertextView `json:"ciphertext"`
}

// GetCiphertext returns a ciphertext record by handle.
func (s *Service) GetCiphertext(r *http.Request, args *GetCiphertextArgs, reply *GetCiphertextReply) error {
	h, err := hash32(args.Handle)
	if err != nil {
		return err
	}
	rec, ok := s.vm.Ciphertext(h)
	if !ok {
		return ErrCiphertextNotFound
	}
	reply.Ciphertext = toCiphertextView(rec)
	return nil
}

// ListCiphertextsArgs filters the ciphertext listing.
type ListCiphertextsArgs struct {
	Owner  string `json:"owner"`
	Scheme string `json:"scheme"`
}

// ListCiphertextsReply returns matching ciphertext views.
type ListCiphertextsReply struct {
	Ciphertexts []CiphertextView `json:"ciphertexts"`
	Total       int              `json:"total"`
}

// ListCiphertexts lists registered ciphertexts, optionally filtered.
func (s *Service) ListCiphertexts(r *http.Request, args *ListCiphertextsArgs, reply *ListCiphertextsReply) error {
	var owner fee.Account
	if args.Owner != "" {
		a, err := accountFromHex(args.Owner)
		if err != nil {
			return err
		}
		owner = a
	}
	for _, rec := range s.vm.Ciphertexts() {
		if args.Owner != "" && rec.Owner != owner {
			continue
		}
		if args.Scheme != "" && rec.Scheme != args.Scheme {
			continue
		}
		reply.Ciphertexts = append(reply.Ciphertexts, toCiphertextView(rec))
	}
	reply.Total = len(reply.Ciphertexts)
	return nil
}

// PermitView is the PUBLIC view of a capability grant.
type PermitView struct {
	PermitID   string `json:"permitId"`
	Handle     string `json:"handle"`
	Grantor    string `json:"grantor"`
	Grantee    string `json:"grantee"`
	Operations uint32 `json:"operations"`
	Expiry     int64  `json:"expiry"`
	Status     string `json:"status"`
	CreatedAt  int64  `json:"createdAt"`
	ChainID    string `json:"chainId"`
}

// GetPermitArgs selects a permit by ID.
type GetPermitArgs struct {
	PermitID string `json:"permitId"` // hex-encoded 32 bytes
}

// GetPermitReply returns the public permit view.
type GetPermitReply struct {
	Permit PermitView `json:"permit"`
}

// GetPermit returns a permit record by ID.
func (s *Service) GetPermit(r *http.Request, args *GetPermitArgs, reply *GetPermitReply) error {
	id, err := hash32(args.PermitID)
	if err != nil {
		return err
	}
	rec, ok := s.vm.Permit(id)
	if !ok {
		return ErrPermitNotFound
	}
	reply.Permit = PermitView{
		PermitID:   hex.EncodeToString(rec.PermitID[:]),
		Handle:     hex.EncodeToString(rec.Handle[:]),
		Grantor:    fee.Account(rec.Grantor).String(),
		Grantee:    fee.Account(rec.Grantee).String(),
		Operations: rec.Operations,
		Expiry:     rec.Expiry,
		Status:     rec.Status,
		CreatedAt:  rec.CreatedAt,
		ChainID:    rec.ChainID.String(),
	}
	return nil
}

// AttestationView names one committee member and the value it attested.
type AttestationView struct {
	Member string `json:"member"`
	Value  string `json:"value"`
}

// DecryptView is the PUBLIC view of a threshold-decryption request. It has no
// plaintext field: the plaintext goes to the requester's callback off-chain,
// and F records only the handle the committee agreed the decryption produced.
type DecryptView struct {
	RequestID    string            `json:"requestId"`
	Handle       string            `json:"handle"`
	Requester    string            `json:"requester"`
	PermitID     string            `json:"permitId"`
	Callback     string            `json:"callback"`
	Selector     string            `json:"selector"`
	Epoch        uint64            `json:"epoch"`
	Status       string            `json:"status"`
	ResultHandle string            `json:"resultHandle,omitempty"`
	Attestations []AttestationView `json:"attestations"`
	Threshold    int               `json:"threshold"`
	Expiry       int64             `json:"expiry"`
	CreatedAt    int64             `json:"createdAt"`
	CompletedAt  int64             `json:"completedAt,omitempty"`
	SourceChain  string            `json:"sourceChain"`
}

// GetDecryptArgs selects a decryption request by ID.
type GetDecryptArgs struct {
	RequestID string `json:"requestId"` // hex-encoded 32 bytes
}

// GetDecryptReply returns the public request view.
type GetDecryptReply struct {
	Request DecryptView `json:"request"`
}

// GetDecrypt returns a decryption request and the committee's answer so far.
func (s *Service) GetDecrypt(r *http.Request, args *GetDecryptArgs, reply *GetDecryptReply) error {
	id, err := hash32(args.RequestID)
	if err != nil {
		return err
	}
	rec, ok := s.vm.Decrypt(id)
	if !ok {
		return ErrRequestNotFound
	}
	// A pending request past its expiry can no longer be answered — checkAuth
	// refuses every attestation to it — so it is reported expired. The stored
	// status stays Pending because nothing ever answered it; expiry is a fact
	// about the clock, and this is the one place that reads the clock to say so.
	status := rec.Status
	if status == fhe.RequestPending && rec.Expiry != 0 && s.vm.clock.Time().Unix() > rec.Expiry {
		status = fhe.RequestExpired
	}
	view := DecryptView{
		RequestID:   hex.EncodeToString(rec.RequestID[:]),
		Handle:      hex.EncodeToString(rec.CiphertextHandle[:]),
		Requester:   fee.Account(rec.Requester).String(),
		PermitID:    hex.EncodeToString(rec.PermitID[:]),
		Callback:    hex.EncodeToString(rec.Callback[:]),
		Selector:    hex.EncodeToString(rec.CallbackSelector[:]),
		Epoch:       rec.Epoch,
		Status:      status.String(),
		Expiry:      rec.Expiry,
		CreatedAt:   rec.CreatedAt,
		CompletedAt: rec.CompletedAt,
		SourceChain: rec.SourceChain.String(),
	}
	if rec.Status == fhe.RequestCompleted {
		view.ResultHandle = hex.EncodeToString(rec.ResultHandle[:])
	}
	if ep, ok := s.vm.Epoch(rec.Epoch); ok {
		view.Threshold = ep.Threshold
	}
	view.Attestations = make([]AttestationView, len(rec.Attestations))
	for i, a := range rec.Attestations {
		view.Attestations[i] = AttestationView{
			Member: a.Member.String(),
			Value:  hex.EncodeToString(a.Value[:]),
		}
	}
	reply.Request = view
	return nil
}

// ---- Accounts ----

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

// FeeScheduleEntry prices one (operation, scheme) pair.
type FeeScheduleEntry struct {
	Operation string `json:"operation"`
	Scheme    string `json:"scheme"`
	Gas       uint64 `json:"gas"`
	FeeNLUX   uint64 `json:"feeNLux"`
}

// FeeScheduleReply returns the per-scheme gas/fee schedule and the price.
type FeeScheduleReply struct {
	GasPrice uint64             `json:"gasPriceNLuxPerGas"`
	Entries  []FeeScheduleEntry `json:"entries"`
}

// opNames maps each transaction type to the name clients use for it. It is the
// one place an operation's public name is written down.
var opNames = map[uint8]string{
	TxRegisterCiphertext: "registerCiphertext",
	TxGrantPermit:        "grantPermit",
	TxRevokePermit:       "revokePermit",
	TxRequestDecrypt:     "requestDecrypt",
	TxFulfillDecrypt:     "fulfillDecrypt",
	TxAdvanceEpoch:       "advanceEpoch",
}

// FeeSchedule returns the chain's per-operation, per-scheme fee schedule so
// clients can compute the exact burn before submitting a transaction.
func (s *Service) FeeSchedule(r *http.Request, args *FeeScheduleArgs, reply *FeeScheduleReply) error {
	reply.GasPrice = uint64(GasPrice)
	for op, name := range opNames {
		if usesScheme(op) {
			for scheme := range schemeGas {
				g, _ := GasFor(&Transaction{Type: op, Scheme: scheme})
				f, _ := fee.Cost(g, GasPrice)
				reply.Entries = append(reply.Entries, FeeScheduleEntry{
					Operation: name, Scheme: scheme, Gas: uint64(g), FeeNLUX: f,
				})
			}
			continue
		}
		g, _ := GasFor(&Transaction{Type: op})
		f, _ := fee.Cost(g, GasPrice)
		reply.Entries = append(reply.Entries, FeeScheduleEntry{
			Operation: name, Scheme: "", Gas: uint64(g), FeeNLUX: f,
		})
	}
	return nil
}

// hash32 decodes a hex-encoded 32-byte identifier — a handle, a permit ID, a
// request ID. One decoder for all three, so none of them can drift into
// accepting a length the others reject.
func hash32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, ErrInvalidPayload
	}
	copy(out[:], b)
	return out, nil
}
