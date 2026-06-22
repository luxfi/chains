// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package txs defines transaction types for the DEX VM — a STATELESS ATOMIC
// ZAP PROXY. There is NO local matching, NO AMM, NO embedded order book. The
// transaction surface is exactly the two concerns a proxy owns:
//
//  1. ATOMIC VALUE MOVEMENT (C-Chain <-> proxy), modeled on the platformvm
//     Import/Export txs that move value between primary-network chains in a
//     single atomic shared-memory commit:
//     - TxImport  : claim value exported from C-Chain into the proxy.
//     - TxExport  : settle proceeds (and unfilled IOC remainder) back to
//     C-Chain, derived ONLY from confirmed d-chain fills.
//
//  2. ORDER RELAY (proxy -> d-chain over ZAP), transport only:
//     - TxRelayOrder : an opaque, byte-identical clob_* ZAP payload plus a
//     reference to the collateral already locked by an
//     Import. The matcher is the d-chain; the proxy never
//     matches.
//     - TxPlaceOrder / TxCancelOrder : thin relay envelopes (a CLOB place /
//     cancel forwarded verbatim). They carry NO price/size
//     matching semantics in the proxy — the d-chain is the
//     single source of truth.
package txs

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
)

var (
	// ErrInvalidSignature is returned by RelayOrderTx.Verify when a relay carries a
	// signature that does not recover to its From (a spoofed-From relay). It is the
	// admission-time provenance gate; settle authority itself derives from the
	// consumed C->D object's recorded owner (the escrow owner), not from From.
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidTxType     = errors.New("invalid transaction type")
	ErrInvalidAmount     = errors.New("invalid amount")
	ErrInvalidPrice      = errors.New("invalid price")
	ErrInsufficientFunds = errors.New("insufficient funds")
)

// TxType represents the type of transaction.
type TxType uint8

const (
	// TxImport claims value exported from C-Chain into the proxy (atomic
	// shared-memory import leg). Consumes imported UTXOs, credits local outputs.
	TxImport TxType = iota
	// TxExport settles proceeds back to C-Chain (atomic shared-memory export
	// leg). Produces exported outputs derived ONLY from confirmed d-chain fills.
	TxExport
	// TxRelayOrder forwards an opaque clob_* ZAP payload to the d-chain matcher,
	// bound to a locked-collateral reference. Transport only — no local match.
	TxRelayOrder
	// TxPlaceOrder is a thin relay envelope for a CLOB limit-order placement.
	TxPlaceOrder
	// TxCancelOrder is a thin relay envelope for a CLOB cancel.
	TxCancelOrder
)

func (t TxType) String() string {
	switch t {
	case TxImport:
		return "import"
	case TxExport:
		return "export"
	case TxRelayOrder:
		return "relay_order"
	case TxPlaceOrder:
		return "place_order"
	case TxCancelOrder:
		return "cancel_order"
	default:
		return "unknown"
	}
}

// Tx is the interface for all DEX proxy transactions.
type Tx interface {
	// ID returns the unique identifier for this transaction.
	ID() ids.ID
	// Type returns the transaction type.
	Type() TxType
	// Sender returns the sender's address.
	Sender() ids.ShortID
	// Timestamp returns when the transaction was created.
	Timestamp() int64
	// Bytes returns the serialized transaction.
	Bytes() []byte
	// Verify validates the transaction.
	Verify() error
}

// BaseTx contains common fields for all transactions.
//
// TxID is intentionally NOT serialized (json:"-"): the transaction ID is the
// SHA-256 checksum of the wire bytes, so embedding it in those same bytes would
// be circular and would make the ID depend on whatever value happened to be in
// the field at marshal time. It is always (re)derived from the wire on Parse,
// and stamped by finalize on construction.
type BaseTx struct {
	TxID      ids.ID      `json:"-"`
	TxType    TxType      `json:"type"`
	From      ids.ShortID `json:"from"`
	Nonce     uint64      `json:"nonce"`
	GasPrice  uint64      `json:"gasPrice"`
	GasLimit  uint64      `json:"gasLimit"`
	CreatedAt int64       `json:"createdAt"`
	Signature []byte      `json:"signature"`
	bytes     []byte
}

func (tx *BaseTx) ID() ids.ID          { return tx.TxID }
func (tx *BaseTx) Type() TxType        { return tx.TxType }
func (tx *BaseTx) Sender() ids.ShortID { return tx.From }
func (tx *BaseTx) Timestamp() int64    { return tx.CreatedAt }
func (tx *BaseTx) Bytes() []byte       { return tx.bytes }

// AtomicInput references a UTXO exported from the source chain that an Import
// consumes via shared memory. UTXOID is the source-chain UTXO id (the
// InputID()); Asset and Amount describe the value being claimed.
type AtomicInput struct {
	UTXOID ids.ID `json:"utxoId"`
	Asset  ids.ID `json:"asset"`
	Amount uint64 `json:"amount"`
}

// Rail is the cross-chain object's lane discriminator — the FIRST wire byte of the
// shared-memory object (atomic.go encodeExportedOutput). It is the H1-closing tag the
// precompile (precompile/dex/native_wire.go Rail) binds on the C side: a swap-fill
// object is RailSwap, an LP-collect object is RailLP, and each C-side consume path
// accepts ONLY its own rail (so a cross-rail consume can never reach the wrong pot).
// The proxy stamps it on every exported output and binds it on every import, so the
// rail round-trips through the atomic core unchanged.
type Rail uint8

const (
	// RailSwap is the swap-fill / refund lane — the ZERO value, so an output whose rail
	// is unstated (the proxy's settleFromFills fill/refund exports, every legacy
	// custody/conservation path) defaults to the swap rail. The precompile's
	// ImportSettlement consumes ONLY this rail.
	RailSwap Rail = 0
	// RailLP is the LP position-commit / collect lane — a non-zero tag the proxy's
	// executeWithdraw stamps for an LP collect/withdraw. The precompile's
	// ImportPositionCollect consumes ONLY this rail.
	RailLP Rail = 1
)

// AtomicOutput is a value output: an Import credits these locally; an Export
// puts these into shared memory for the destination chain to claim. Rail is the lane
// the value travels (RailSwap default / RailLP), bound byte-for-byte into the
// shared-memory object so the precompile's matching consume path is the only one that
// can claim it.
type AtomicOutput struct {
	Rail   Rail        `json:"rail,omitempty"`
	Owner  ids.ShortID `json:"owner"`
	Asset  ids.ID      `json:"asset"`
	Amount uint64      `json:"amount"`
}

// ImportTx claims value exported from C-Chain (the SourceChain) into the proxy.
// The atomic shared-memory import leg: the imported UTXOs are removed from
// shared memory and their value credited to local outputs. This is the FIRST
// leg of the conservation ordering (import -> ZAP submit -> export).
type ImportTx struct {
	BaseTx
	SourceChain    ids.ID         `json:"sourceChain"`
	ImportedInputs []AtomicInput  `json:"importedInputs"`
	Outputs        []AtomicOutput `json:"outputs"`
}

// NewImportTx creates a new import transaction.
func NewImportTx(from ids.ShortID, nonce uint64, sourceChain ids.ID, in []AtomicInput, out []AtomicOutput) *ImportTx {
	tx := &ImportTx{
		BaseTx: BaseTx{
			TxType:    TxImport,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  100000,
			CreatedAt: time.Now().UnixNano(),
		},
		SourceChain:    sourceChain,
		ImportedInputs: in,
		Outputs:        out,
	}
	return finalize(tx, &tx.BaseTx)
}

func (tx *ImportTx) Verify() error {
	if tx.SourceChain == ids.Empty {
		return errors.New("import: empty source chain")
	}
	if len(tx.ImportedInputs) == 0 {
		return errors.New("import: no imported inputs")
	}
	// All consumed inputs name ONE asset (a deposit credits one (owner,asset) ledger
	// row). The asset of the first input is the import's asset; every other input
	// and every credited output must match it. This is the STRUCTURAL half of the
	// native-aliasing bind (the AUTHORITATIVE half — input asset == the consumed
	// UTXO's RECORDED asset — is enforced in executeImport against shared memory):
	// together they pin output.Asset == input.Asset == recordedAsset, so an import
	// can never credit an asset it does not actually consume.
	importAsset := tx.ImportedInputs[0].Asset
	var in uint64
	for _, i := range tx.ImportedInputs {
		if i.Amount == 0 {
			return ErrInvalidAmount
		}
		if i.Asset != importAsset {
			return errors.New("import: inputs span multiple assets")
		}
		in += i.Amount
	}
	var outAmt uint64
	// All credited outputs share ONE rail (the lane the funding object travels). This
	// is the STRUCTURAL half of the rail bind; the AUTHORITATIVE half (output rail ==
	// the consumed UTXO's RECORDED rail) is enforced in executeImport against shared
	// memory, exactly as for the asset axis.
	var importRail Rail
	if len(tx.Outputs) > 0 {
		importRail = tx.Outputs[0].Rail
	}
	for _, o := range tx.Outputs {
		if o.Asset != importAsset {
			return errors.New("import: output asset != imported input asset (would re-denominate)")
		}
		if o.Rail != importRail {
			return errors.New("import: outputs span multiple rails")
		}
		outAmt += o.Amount
	}
	// Conservation: credited outputs must not exceed claimed inputs (the proxy
	// never mints). A difference is the burned fee.
	if outAmt > in {
		return errors.New("import: outputs exceed imported value (would mint)")
	}
	return nil
}

// ExportTx settles proceeds back to C-Chain (the DestinationChain). The atomic
// shared-memory export leg: ExportedOutputs are written into shared memory for
// the destination chain to claim. The amounts MUST be derived ONLY from
// confirmed d-chain fills (and any unfilled IOC remainder being refunded) — the
// proxy never mints. This is the FINAL leg of the conservation ordering.
type ExportTx struct {
	BaseTx
	DestinationChain ids.ID         `json:"destinationChain"`
	ExportedOutputs  []AtomicOutput `json:"exportedOutputs"`
	// FillRef binds this settlement to the d-chain relay receipt whose confirmed
	// fills justify the exported amounts (replay-idempotency / audit).
	FillRef ids.ID `json:"fillRef"`
}

// NewExportTx creates a new export transaction.
func NewExportTx(from ids.ShortID, nonce uint64, destChain ids.ID, out []AtomicOutput, fillRef ids.ID) *ExportTx {
	tx := &ExportTx{
		BaseTx: BaseTx{
			TxType:    TxExport,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  100000,
			CreatedAt: time.Now().UnixNano(),
		},
		DestinationChain: destChain,
		ExportedOutputs:  out,
		FillRef:          fillRef,
	}
	return finalize(tx, &tx.BaseTx)
}

// NewSettlementExportTx builds the settlement export the VM constructs INSIDE
// block processing (settleFromFills) — never a client-submitted tx. Because it
// is reconstructed independently on every validator, its identity must be a
// pure function of consensus-agreed inputs only. The wall-clock CreatedAt used
// by the client-facing NewExportTx would make tx.ID() (and therefore any
// shared-memory UTXO key derived from it) diverge per node, splitting the
// atomic commit. Here CreatedAt is pinned to createdAt — the deterministic
// settlement coordinate (the relay's UnixNano block time) supplied by the
// caller — so the wire bytes, the TxID, and every derived export UTXO key are
// byte-identical across validators. Nonce carries the settlement's txIndex so
// two settlements in the same block produce distinct identities.
func NewSettlementExportTx(from ids.ShortID, txIndex uint32, destChain ids.ID, out []AtomicOutput, fillRef ids.ID, createdAt int64) *ExportTx {
	tx := &ExportTx{
		BaseTx: BaseTx{
			TxType:    TxExport,
			From:      from,
			Nonce:     uint64(txIndex),
			GasPrice:  1000,
			GasLimit:  100000,
			CreatedAt: createdAt,
		},
		DestinationChain: destChain,
		ExportedOutputs:  out,
		FillRef:          fillRef,
	}
	return finalize(tx, &tx.BaseTx)
}

func (tx *ExportTx) Verify() error {
	if tx.DestinationChain == ids.Empty {
		return errors.New("export: empty destination chain")
	}
	if len(tx.ExportedOutputs) == 0 {
		return errors.New("export: no exported outputs")
	}
	// All exported outputs share ONE rail — a single export leg settles on one lane
	// (the precompile's matching consume path claims them). The fill/refund legs of a
	// swap settle on RailSwap; an LP withdraw exports on RailLP.
	exportRail := tx.ExportedOutputs[0].Rail
	for _, o := range tx.ExportedOutputs {
		if o.Amount == 0 {
			return ErrInvalidAmount
		}
		if o.Rail != exportRail {
			return errors.New("export: outputs span multiple rails")
		}
	}
	return nil
}

// RelayOrderTx forwards an opaque clob_* ZAP payload to the d-chain matcher,
// bound to a locked-collateral reference. The payload is the byte-identical
// clob_submit/clob_place frame the d-chain's zap_server.go expects; the proxy
// is pure transport and does not interpret it beyond routing.
type RelayOrderTx struct {
	BaseTx
	// Method is the ZAP CLOB method ("clob_submit", "clob_place", "clob_cancel").
	Method string `json:"method"`
	// Payload is the opaque, byte-identical clob_* frame forwarded verbatim.
	Payload []byte `json:"payload"`
	// CollateralRef references the Import whose locked value backs this order.
	CollateralRef ids.ID `json:"collateralRef"`
	// AssetOut is the REAL injective output-asset id the taker receives for a settling
	// clob_submit — the OPPOSITE side of the market this order trades on, the same
	// assetID(currency_out) the C-side ImportSettlement requires (recAsset==claim.Asset,
	// the id that keys seamReserve[assetOut]). The HIGH-1 fix: settleFromFills exports
	// the PROCEEDS leg under THIS id, NOT a SHA256(ref||leg) routing handle (which never
	// matched, so a swap's output was permanently unclaimable). It is keeper-asserted and
	// signature-bound (JSON-covered by SigningBytes); a wrong value can only break the
	// taker's OWN liveness — ImportSettlement equality-rejects a mismatched asset (no
	// theft, no mint), the same bounded surface as the carried-fills proposer-trust model.
	// PriceLimit is the worst-acceptable CLOB price (quote-per-base, float64-bits) for a
	// settling clob_submit, derived from the V4 SqrtPriceLimitX96. settleFromFills refuses
	// any carried fill WORSE than this (BUY: price above the limit; SELL: price below it),
	// enforcing the taker's slippage floor against a sandwich/MEV move. Zero = no limit.
	// LimitIsUpper records the direction the limit bounds (true: reject price ABOVE the
	// limit, the BUY/exact-input ceiling; false: reject price BELOW it, the SELL floor).
	// Empty/zero for place/cancel (non-settling) relays.
	AssetOut    ids.ID  `json:"assetOut,omitempty"`
	PriceLimit  uint64  `json:"priceLimit,omitempty"`
	LimitIsUpper bool   `json:"limitIsUpper,omitempty"`
}

// NewRelayOrderTx creates a new relay-order transaction (UNSIGNED). From carries no
// settle authority (the escrow owner does), so an unsigned relay is admissible; a
// client that wants authenticated From provenance calls Sign afterwards. assetOut is
// the real output-asset id a settling clob_submit credits (the HIGH-1 fix); it is
// ids.Empty for non-settling place/cancel relays. priceLimit/limitIsUpper carry the
// taker's slippage floor (0 = none).
func NewRelayOrderTx(from ids.ShortID, nonce uint64, method string, payload []byte, collateralRef ids.ID) *RelayOrderTx {
	tx := &RelayOrderTx{
		BaseTx: BaseTx{
			TxType:    TxRelayOrder,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  100000,
			CreatedAt: time.Now().UnixNano(),
		},
		Method:        method,
		Payload:       payload,
		CollateralRef: collateralRef,
	}
	return finalize(tx, &tx.BaseTx)
}

// NewSettlingRelayOrderTx builds a settling clob_submit relay carrying the output-asset
// id + slippage limit the proxy settles against. The keeper (which knows the market)
// populates assetOut (the opposite side of the market) and the price limit derived from
// the taker's V4 SqrtPriceLimitX96. This is the canonical constructor for the settling
// rail; non-settling relays use NewRelayOrderTx (assetOut empty).
func NewSettlingRelayOrderTx(from ids.ShortID, nonce uint64, payload []byte, collateralRef, assetOut ids.ID, priceLimit uint64, limitIsUpper bool) *RelayOrderTx {
	tx := NewRelayOrderTx(from, nonce, "clob_submit", payload, collateralRef)
	tx.AssetOut = assetOut
	tx.PriceLimit = priceLimit
	tx.LimitIsUpper = limitIsUpper
	return finalize(tx, &tx.BaseTx)
}

func (tx *RelayOrderTx) Verify() error {
	if tx.Method == "" {
		return errors.New("relay: empty ZAP method")
	}
	if len(tx.Payload) == 0 {
		return errors.New("relay: empty payload")
	}
	// PROVENANCE AUTHENTICATION of the From field. From carries NO settle authority —
	// the settle authority + payout target derive from the consumed C->D object's
	// recorded owner (the escrow owner persisted at import; see chains/dexvm
	// settleFromFills), exactly as platformvm import/export authority comes from the
	// consumed UTXO, not a tx-level identity. So an UNSIGNED relay cannot escalate: it
	// can only settle to whatever escrow its CollateralRef names, and that escrow pays
	// its recorded owner regardless of From. The signature, WHEN PRESENT, cryptographi-
	// cally binds From (a secp256k1/EVM-address recovery over the unsigned wire image),
	// giving the routing/audit layer authenticated provenance and wiring the otherwise-
	// dangling ErrInvalidSignature. A present-but-invalid signature is rejected at
	// admission; an absent one is permitted (authority lives in the escrow bind).
	if len(tx.Signature) > 0 {
		if err := tx.verifyFrom(); err != nil {
			return err
		}
	}
	return nil
}

// SigningBytes is the canonical message a RelayOrderTx signature commits to: the
// wire bytes with the Signature field cleared (so the signature binds From, Method,
// Payload, CollateralRef, Nonce — but never itself). Deterministic (the struct has
// no maps; encoding/json emits fields in declaration order).
func (tx *RelayOrderTx) SigningBytes() ([]byte, error) {
	unsigned := *tx
	unsigned.BaseTx.Signature = nil
	unsigned.BaseTx.bytes = nil
	unsigned.BaseTx.TxID = ids.Empty
	return Marshal(&unsigned, TxRelayOrder)
}

// Sign stamps the relay with a secp256k1 signature over SigningBytes by `key`, and
// sets From to key's EVM address (the owner format the C->D object carries). After
// this, Verify authenticates From cryptographically. Used by clients/keepers that
// build relays; the proxy itself never signs (it derives authority from escrow).
func (tx *RelayOrderTx) Sign(key *secp256k1.PrivateKey) error {
	tx.From = key.EVMAddress()
	msg, err := tx.SigningBytes()
	if err != nil {
		return err
	}
	sig, err := key.SignHash(hashRelaySigningBytes(msg))
	if err != nil {
		return err
	}
	tx.Signature = sig
	// Re-stamp the wire bytes + TxID now that From + Signature are set, so the signed
	// tx is immediately wire-ready and Parse-round-trippable (same as every New*Tx).
	finalize(tx, &tx.BaseTx)
	return nil
}

// verifyFrom recovers the signer of the relay from its signature over the unsigned
// wire image and requires the recovered EVM address to equal tx.From. A mismatch (or
// an unrecoverable signature) is ErrInvalidSignature — a spoofed From is refused at
// admission.
func (tx *RelayOrderTx) verifyFrom() error {
	msg, err := tx.SigningBytes()
	if err != nil {
		return err
	}
	pub, err := secp256k1.RecoverPublicKeyFromHash(hashRelaySigningBytes(msg), tx.Signature)
	if err != nil {
		return ErrInvalidSignature
	}
	if ids.ShortID(pub.EVMAddress()) != tx.From {
		return ErrInvalidSignature
	}
	return nil
}

// hashRelaySigningBytes is the single hash the relay sign+recover paths share, so
// signing and verification commit to the identical digest of the unsigned wire image.
func hashRelaySigningBytes(msg []byte) []byte {
	h := sha256.Sum256(msg)
	return h[:]
}

// PlaceOrderTx is a thin relay envelope for a CLOB limit-order placement. It
// carries the wire fields a clob_place frame needs but NO matching logic — the
// VM forwards it to the d-chain and settles from the returned ack/fills.
type PlaceOrderTx struct {
	BaseTx
	// PoolID is the 32-byte market identity (V4 poolId) the d-chain keys by.
	PoolID [32]byte `json:"poolId"`
	Side   uint8    `json:"side"` // 0 = Buy/bid, 1 = Sell/ask
	Price  uint64   `json:"price"`
	Size   uint64   `json:"size"`
	// CollateralRef references the Import whose locked value backs this order.
	CollateralRef ids.ID `json:"collateralRef"`
}

// NewPlaceOrderTx creates a new place-order relay envelope.
func NewPlaceOrderTx(from ids.ShortID, nonce uint64, poolID [32]byte, side uint8, price, size uint64) *PlaceOrderTx {
	tx := &PlaceOrderTx{
		BaseTx: BaseTx{
			TxType:    TxPlaceOrder,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  100000,
			CreatedAt: time.Now().UnixNano(),
		},
		PoolID: poolID,
		Side:   side,
		Price:  price,
		Size:   size,
	}
	return finalize(tx, &tx.BaseTx)
}

func (tx *PlaceOrderTx) Verify() error {
	if tx.Size == 0 {
		return ErrInvalidAmount
	}
	if tx.Price == 0 {
		return ErrInvalidPrice
	}
	return nil
}

// CancelOrderTx is a thin relay envelope for a CLOB cancel. The d-chain
// authenticates the cancel against the resting order's maker — the proxy only
// forwards the (market, orderID) reference.
type CancelOrderTx struct {
	BaseTx
	PoolID  [32]byte `json:"poolId"`
	OrderID uint64   `json:"orderId"`
}

// NewCancelOrderTx creates a new cancel-order relay envelope.
func NewCancelOrderTx(from ids.ShortID, nonce uint64, poolID [32]byte, orderID uint64) *CancelOrderTx {
	tx := &CancelOrderTx{
		BaseTx: BaseTx{
			TxType:    TxCancelOrder,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  50000,
			CreatedAt: time.Now().UnixNano(),
		},
		PoolID:  poolID,
		OrderID: orderID,
	}
	return finalize(tx, &tx.BaseTx)
}

func (tx *CancelOrderTx) Verify() error {
	if tx.OrderID == 0 {
		return errors.New("cancel: order id cannot be zero")
	}
	return nil
}

// TxParser parses raw transaction bytes.
type TxParser struct{}

// Parse parses a transaction from bytes.
func (p *TxParser) Parse(data []byte) (Tx, error) {
	if len(data) < 1 {
		return nil, ErrInvalidTxType
	}

	txType := TxType(data[0])
	switch txType {
	case TxImport:
		return parse[ImportTx](data, TxImport)
	case TxExport:
		return parse[ExportTx](data, TxExport)
	case TxRelayOrder:
		return parse[RelayOrderTx](data, TxRelayOrder)
	case TxPlaceOrder:
		return parse[PlaceOrderTx](data, TxPlaceOrder)
	case TxCancelOrder:
		return parse[CancelOrderTx](data, TxCancelOrder)
	default:
		return nil, ErrInvalidTxType
	}
}

// parse decodes the JSON body into a concrete tx, stamps its type, wire bytes,
// and the deterministic TxID. One codec for every type — there is exactly one
// way to read a transaction off the wire.
func parse[T any](data []byte, txType TxType) (*T, error) {
	tx := new(T)
	if err := unmarshalBody(data, tx); err != nil {
		return nil, err
	}
	stampBase(tx, txType, data)
	return tx, nil
}

// stampBase sets the embedded BaseTx's type, wire bytes, and checksum TxID via
// the Tx interface methods exposed on *BaseTx. It relies on every concrete tx
// embedding BaseTx.
func stampBase(tx any, txType TxType, data []byte) {
	type baseHolder interface{ base() *BaseTx }
	if h, ok := tx.(baseHolder); ok {
		b := h.base()
		b.TxType = txType
		b.TxID = ids.Checksum256(data)
		b.bytes = data
	}
}

func (tx *BaseTx) base() *BaseTx { return tx }

// Wire format for every transaction is a single type byte followed by the JSON
// encoding of the concrete transaction struct:
//
//	[0]      = TxType
//	[1:]     = json.Marshal(tx)
//
// The encoding is deterministic (Go's encoding/json emits struct fields in
// declaration order and these types contain no maps), so the same logical
// transaction always serializes to identical bytes and therefore the same
// TxID. This is the single codec used by both the constructors and the parser.

// Marshal serializes a concrete transaction struct into wire bytes:
// type byte + JSON body.
func Marshal[T any](tx *T, txType TxType) ([]byte, error) {
	body, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(body))
	out[0] = byte(txType)
	copy(out[1:], body)
	return out, nil
}

// unmarshalBody decodes the JSON body (everything after the type byte) into the
// supplied transaction struct. The type byte itself is validated by the caller
// (TxParser.Parse) before dispatch.
func unmarshalBody(data []byte, v any) error {
	if len(data) < 1 {
		return ErrInvalidTxType
	}
	return json.Unmarshal(data[1:], v)
}

// finalize serializes the constructed transaction and stamps its wire bytes and
// deterministic TxID. Every New*Tx constructor calls this so a freshly built
// transaction is immediately wire-ready and Parse-round-trippable.
func finalize[T any](tx *T, base *BaseTx) *T {
	wire, err := Marshal(tx, base.TxType)
	if err != nil {
		// JSON encoding of these plain structs cannot fail; treat as a
		// programmer error rather than silently returning a half-built tx.
		panic("txs: failed to marshal transaction: " + err.Error())
	}
	base.TxID = ids.Checksum256(wire)
	base.bytes = wire
	return tx
}
