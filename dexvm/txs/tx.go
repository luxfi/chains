// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package txs defines transaction types for the DEX VM.
package txs

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/luxfi/ids"
)

var (
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidTxType     = errors.New("invalid transaction type")
	ErrInvalidAmount     = errors.New("invalid amount")
	ErrInvalidPrice      = errors.New("invalid price")
	ErrInsufficientFunds = errors.New("insufficient funds")
)

// TxType represents the type of transaction.
type TxType uint8

const (
	TxPlaceOrder TxType = iota
	TxCancelOrder
	TxSwap
	TxAddLiquidity
	TxRemoveLiquidity
	TxCreatePool
	TxCrossChainSwap
	TxCrossChainTransfer
	TxCommitOrder // MEV protection: commit order hash
	TxRevealOrder // MEV protection: reveal order details
)

func (t TxType) String() string {
	switch t {
	case TxPlaceOrder:
		return "place_order"
	case TxCancelOrder:
		return "cancel_order"
	case TxSwap:
		return "swap"
	case TxAddLiquidity:
		return "add_liquidity"
	case TxRemoveLiquidity:
		return "remove_liquidity"
	case TxCreatePool:
		return "create_pool"
	case TxCrossChainSwap:
		return "cross_chain_swap"
	case TxCrossChainTransfer:
		return "cross_chain_transfer"
	case TxCommitOrder:
		return "commit_order"
	case TxRevealOrder:
		return "reveal_order"
	default:
		return "unknown"
	}
}

// Tx is the interface for all DEX transactions.
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
type BaseTx struct {
	TxID      ids.ID      `json:"id"`
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

// PlaceOrderTx represents a place order transaction.
type PlaceOrderTx struct {
	BaseTx
	Symbol      string `json:"symbol"`
	Side        uint8  `json:"side"`      // 0 = Buy, 1 = Sell
	OrderType   uint8  `json:"orderType"` // 0 = Limit, 1 = Market, etc.
	Price       uint64 `json:"price"`
	Quantity    uint64 `json:"quantity"`
	StopPrice   uint64 `json:"stopPrice"`
	PostOnly    bool   `json:"postOnly"`
	ReduceOnly  bool   `json:"reduceOnly"`
	TimeInForce string `json:"timeInForce"` // GTC, IOC, FOK
	ExpiresAt   int64  `json:"expiresAt"`
}

// NewPlaceOrderTx creates a new place order transaction.
func NewPlaceOrderTx(
	from ids.ShortID,
	nonce uint64,
	symbol string,
	side uint8,
	orderType uint8,
	price, quantity uint64,
	timeInForce string,
) *PlaceOrderTx {
	return &PlaceOrderTx{
		BaseTx: BaseTx{
			TxType:    TxPlaceOrder,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  100000,
			CreatedAt: time.Now().UnixNano(),
		},
		Symbol:      symbol,
		Side:        side,
		OrderType:   orderType,
		Price:       price,
		Quantity:    quantity,
		TimeInForce: timeInForce,
	}
}

func (tx *PlaceOrderTx) Verify() error {
	if tx.Quantity == 0 {
		return ErrInvalidAmount
	}
	if tx.OrderType == 0 && tx.Price == 0 { // Limit order needs price
		return ErrInvalidPrice
	}
	return nil
}

// CancelOrderTx represents a cancel order transaction.
type CancelOrderTx struct {
	BaseTx
	OrderID ids.ID `json:"orderId"`
	Symbol  string `json:"symbol"`
}

// NewCancelOrderTx creates a new cancel order transaction.
func NewCancelOrderTx(from ids.ShortID, nonce uint64, orderID ids.ID, symbol string) *CancelOrderTx {
	return &CancelOrderTx{
		BaseTx: BaseTx{
			TxType:    TxCancelOrder,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  50000,
			CreatedAt: time.Now().UnixNano(),
		},
		OrderID: orderID,
		Symbol:  symbol,
	}
}

func (tx *CancelOrderTx) Verify() error {
	if tx.OrderID == ids.Empty {
		return errors.New("order ID cannot be empty")
	}
	return nil
}

// SwapTx represents an AMM swap transaction.
type SwapTx struct {
	BaseTx
	PoolID       ids.ID `json:"poolId"`
	TokenIn      ids.ID `json:"tokenIn"`
	TokenOut     ids.ID `json:"tokenOut"`
	AmountIn     uint64 `json:"amountIn"`
	MinAmountOut uint64 `json:"minAmountOut"`
	MaxSlippage  uint16 `json:"maxSlippage"` // In basis points
	Deadline     int64  `json:"deadline"`
}

// NewSwapTx creates a new swap transaction.
func NewSwapTx(
	from ids.ShortID,
	nonce uint64,
	poolID ids.ID,
	tokenIn, tokenOut ids.ID,
	amountIn, minAmountOut uint64,
	maxSlippage uint16,
) *SwapTx {
	return &SwapTx{
		BaseTx: BaseTx{
			TxType:    TxSwap,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  200000,
			CreatedAt: time.Now().UnixNano(),
		},
		PoolID:       poolID,
		TokenIn:      tokenIn,
		TokenOut:     tokenOut,
		AmountIn:     amountIn,
		MinAmountOut: minAmountOut,
		MaxSlippage:  maxSlippage,
		Deadline:     time.Now().Add(5 * time.Minute).UnixNano(),
	}
}

func (tx *SwapTx) Verify() error {
	if tx.AmountIn == 0 {
		return ErrInvalidAmount
	}
	if tx.TokenIn == tx.TokenOut {
		return errors.New("cannot swap same token")
	}
	return nil
}

// AddLiquidityTx represents adding liquidity to a pool.
type AddLiquidityTx struct {
	BaseTx
	PoolID       ids.ID `json:"poolId"`
	Token0Amount uint64 `json:"token0Amount"`
	Token1Amount uint64 `json:"token1Amount"`
	MinLPTokens  uint64 `json:"minLPTokens"`
	Deadline     int64  `json:"deadline"`
}

// NewAddLiquidityTx creates a new add liquidity transaction.
func NewAddLiquidityTx(
	from ids.ShortID,
	nonce uint64,
	poolID ids.ID,
	token0Amount, token1Amount, minLPTokens uint64,
) *AddLiquidityTx {
	return &AddLiquidityTx{
		BaseTx: BaseTx{
			TxType:    TxAddLiquidity,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  250000,
			CreatedAt: time.Now().UnixNano(),
		},
		PoolID:       poolID,
		Token0Amount: token0Amount,
		Token1Amount: token1Amount,
		MinLPTokens:  minLPTokens,
		Deadline:     time.Now().Add(5 * time.Minute).UnixNano(),
	}
}

func (tx *AddLiquidityTx) Verify() error {
	if tx.Token0Amount == 0 || tx.Token1Amount == 0 {
		return ErrInvalidAmount
	}
	return nil
}

// RemoveLiquidityTx represents removing liquidity from a pool.
type RemoveLiquidityTx struct {
	BaseTx
	PoolID        ids.ID `json:"poolId"`
	LPTokenAmount uint64 `json:"lpTokenAmount"`
	MinToken0     uint64 `json:"minToken0"`
	MinToken1     uint64 `json:"minToken1"`
	Deadline      int64  `json:"deadline"`
}

// NewRemoveLiquidityTx creates a new remove liquidity transaction.
func NewRemoveLiquidityTx(
	from ids.ShortID,
	nonce uint64,
	poolID ids.ID,
	lpTokenAmount, minToken0, minToken1 uint64,
) *RemoveLiquidityTx {
	return &RemoveLiquidityTx{
		BaseTx: BaseTx{
			TxType:    TxRemoveLiquidity,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  250000,
			CreatedAt: time.Now().UnixNano(),
		},
		PoolID:        poolID,
		LPTokenAmount: lpTokenAmount,
		MinToken0:     minToken0,
		MinToken1:     minToken1,
		Deadline:      time.Now().Add(5 * time.Minute).UnixNano(),
	}
}

func (tx *RemoveLiquidityTx) Verify() error {
	if tx.LPTokenAmount == 0 {
		return ErrInvalidAmount
	}
	return nil
}

// CreatePoolTx represents creating a new liquidity pool.
type CreatePoolTx struct {
	BaseTx
	Token0        ids.ID `json:"token0"`
	Token1        ids.ID `json:"token1"`
	PoolType      uint8  `json:"poolType"` // 0 = ConstantProduct, 1 = StableSwap, 2 = Concentrated
	SwapFeeBps    uint16 `json:"swapFeeBps"`
	InitialToken0 uint64 `json:"initialToken0"`
	InitialToken1 uint64 `json:"initialToken1"`
	// For concentrated liquidity
	TickLower int32 `json:"tickLower"`
	TickUpper int32 `json:"tickUpper"`
}

// NewCreatePoolTx creates a new create pool transaction.
func NewCreatePoolTx(
	from ids.ShortID,
	nonce uint64,
	token0, token1 ids.ID,
	poolType uint8,
	swapFeeBps uint16,
	initialToken0, initialToken1 uint64,
) *CreatePoolTx {
	return &CreatePoolTx{
		BaseTx: BaseTx{
			TxType:    TxCreatePool,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  500000,
			CreatedAt: time.Now().UnixNano(),
		},
		Token0:        token0,
		Token1:        token1,
		PoolType:      poolType,
		SwapFeeBps:    swapFeeBps,
		InitialToken0: initialToken0,
		InitialToken1: initialToken1,
	}
}

func (tx *CreatePoolTx) Verify() error {
	if tx.Token0 == tx.Token1 {
		return errors.New("cannot create pool with same token")
	}
	if tx.InitialToken0 == 0 || tx.InitialToken1 == 0 {
		return ErrInvalidAmount
	}
	if tx.SwapFeeBps > 10000 { // Max 100%
		return errors.New("swap fee too high")
	}
	return nil
}

// CrossChainSwapTx represents a cross-chain atomic swap via Warp.
type CrossChainSwapTx struct {
	BaseTx
	SourceChain   ids.ID      `json:"sourceChain"`
	DestChain     ids.ID      `json:"destChain"`
	TokenIn       ids.ID      `json:"tokenIn"`
	TokenOut      ids.ID      `json:"tokenOut"`
	AmountIn      uint64      `json:"amountIn"`
	MinAmountOut  uint64      `json:"minAmountOut"`
	Recipient     ids.ShortID `json:"recipient"`
	WarpMessageID ids.ID      `json:"warpMessageId"`
	Deadline      int64       `json:"deadline"`
}

func (tx *CrossChainSwapTx) Verify() error {
	if tx.AmountIn == 0 {
		return ErrInvalidAmount
	}
	if tx.SourceChain == tx.DestChain {
		return errors.New("source and destination chain must be different")
	}
	return nil
}

// CrossChainTransferTx represents a cross-chain token transfer via Warp.
type CrossChainTransferTx struct {
	BaseTx
	SourceChain   ids.ID      `json:"sourceChain"`
	DestChain     ids.ID      `json:"destChain"`
	Token         ids.ID      `json:"token"`
	Amount        uint64      `json:"amount"`
	Recipient     ids.ShortID `json:"recipient"`
	WarpMessageID ids.ID      `json:"warpMessageId"`
}

func (tx *CrossChainTransferTx) Verify() error {
	if tx.Amount == 0 {
		return ErrInvalidAmount
	}
	if tx.SourceChain == tx.DestChain {
		return errors.New("source and destination chain must be different")
	}
	return nil
}

// CommitOrderTx represents a commit phase for MEV-protected order placement.
// Users submit hash(order || salt) without revealing order details.
type CommitOrderTx struct {
	BaseTx
	// CommitmentHash is SHA256(order_bytes || salt)
	CommitmentHash ids.ID `json:"commitmentHash"`
}

// NewCommitOrderTx creates a new commit order transaction.
func NewCommitOrderTx(from ids.ShortID, nonce uint64, commitmentHash ids.ID) *CommitOrderTx {
	return &CommitOrderTx{
		BaseTx: BaseTx{
			TxType:    TxCommitOrder,
			From:      from,
			Nonce:     nonce,
			GasPrice:  500, // Lower gas for commit
			GasLimit:  30000,
			CreatedAt: time.Now().UnixNano(),
		},
		CommitmentHash: commitmentHash,
	}
}

func (tx *CommitOrderTx) Verify() error {
	if tx.CommitmentHash == ids.Empty {
		return errors.New("commitment hash cannot be empty")
	}
	return nil
}

// RevealOrderTx represents a reveal phase for MEV-protected order placement.
// Users reveal the actual order and salt to match their commitment.
type RevealOrderTx struct {
	BaseTx
	// CommitmentHash links to the original commitment
	CommitmentHash ids.ID `json:"commitmentHash"`

	// Salt is the 32-byte random salt used in commitment
	Salt [32]byte `json:"salt"`

	// Order details being revealed
	Symbol      string `json:"symbol"`
	Side        uint8  `json:"side"`      // 0 = Buy, 1 = Sell
	OrderType   uint8  `json:"orderType"` // 0 = Limit, 1 = Market, etc.
	Price       uint64 `json:"price"`
	Quantity    uint64 `json:"quantity"`
	StopPrice   uint64 `json:"stopPrice"`
	PostOnly    bool   `json:"postOnly"`
	ReduceOnly  bool   `json:"reduceOnly"`
	TimeInForce string `json:"timeInForce"` // GTC, IOC, FOK
	ExpiresAt   int64  `json:"expiresAt"`
}

// NewRevealOrderTx creates a new reveal order transaction.
func NewRevealOrderTx(
	from ids.ShortID,
	nonce uint64,
	commitmentHash ids.ID,
	salt [32]byte,
	symbol string,
	side uint8,
	orderType uint8,
	price, quantity uint64,
	timeInForce string,
) *RevealOrderTx {
	return &RevealOrderTx{
		BaseTx: BaseTx{
			TxType:    TxRevealOrder,
			From:      from,
			Nonce:     nonce,
			GasPrice:  1000,
			GasLimit:  100000,
			CreatedAt: time.Now().UnixNano(),
		},
		CommitmentHash: commitmentHash,
		Salt:           salt,
		Symbol:         symbol,
		Side:           side,
		OrderType:      orderType,
		Price:          price,
		Quantity:       quantity,
		TimeInForce:    timeInForce,
	}
}

func (tx *RevealOrderTx) Verify() error {
	if tx.CommitmentHash == ids.Empty {
		return errors.New("commitment hash cannot be empty")
	}
	if tx.Quantity == 0 {
		return ErrInvalidAmount
	}
	if tx.OrderType == 0 && tx.Price == 0 { // Limit order needs price
		return ErrInvalidPrice
	}
	// Salt verification is done in commit-reveal matching, not here
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
	case TxPlaceOrder:
		return p.parsePlaceOrder(data)
	case TxCancelOrder:
		return p.parseCancelOrder(data)
	case TxSwap:
		return p.parseSwap(data)
	case TxAddLiquidity:
		return p.parseAddLiquidity(data)
	case TxRemoveLiquidity:
		return p.parseRemoveLiquidity(data)
	case TxCreatePool:
		return p.parseCreatePool(data)
	case TxCrossChainSwap:
		return p.parseCrossChainSwap(data)
	case TxCrossChainTransfer:
		return p.parseCrossChainTransfer(data)
	case TxCommitOrder:
		return p.parseCommitOrder(data)
	case TxRevealOrder:
		return p.parseRevealOrder(data)
	default:
		return nil, ErrInvalidTxType
	}
}

func (p *TxParser) parsePlaceOrder(data []byte) (*PlaceOrderTx, error) {
	// Simplified parsing - in production use proper codec
	tx := &PlaceOrderTx{}
	tx.TxType = TxPlaceOrder
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseCancelOrder(data []byte) (*CancelOrderTx, error) {
	tx := &CancelOrderTx{}
	tx.TxType = TxCancelOrder
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseSwap(data []byte) (*SwapTx, error) {
	tx := &SwapTx{}
	tx.TxType = TxSwap
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseAddLiquidity(data []byte) (*AddLiquidityTx, error) {
	tx := &AddLiquidityTx{}
	tx.TxType = TxAddLiquidity
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseRemoveLiquidity(data []byte) (*RemoveLiquidityTx, error) {
	tx := &RemoveLiquidityTx{}
	tx.TxType = TxRemoveLiquidity
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseCreatePool(data []byte) (*CreatePoolTx, error) {
	tx := &CreatePoolTx{}
	tx.TxType = TxCreatePool
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseCrossChainSwap(data []byte) (*CrossChainSwapTx, error) {
	tx := &CrossChainSwapTx{}
	tx.TxType = TxCrossChainSwap
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseCrossChainTransfer(data []byte) (*CrossChainTransferTx, error) {
	tx := &CrossChainTransferTx{}
	tx.TxType = TxCrossChainTransfer
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseCommitOrder(data []byte) (*CommitOrderTx, error) {
	tx := &CommitOrderTx{}
	tx.TxType = TxCommitOrder
	tx.bytes = data
	return tx, nil
}

func (p *TxParser) parseRevealOrder(data []byte) (*RevealOrderTx, error) {
	tx := &RevealOrderTx{}
	tx.TxType = TxRevealOrder
	tx.bytes = data
	return tx, nil
}

// Helper functions for encoding
func encodeUint64(buf []byte, v uint64) {
	binary.BigEndian.PutUint64(buf, v)
}

func decodeUint64(buf []byte) uint64 {
	return binary.BigEndian.Uint64(buf)
}
