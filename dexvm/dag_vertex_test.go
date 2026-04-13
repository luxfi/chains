// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"testing"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/chains/dexvm/orderbook"
)

func TestDexVertexConflicts_OverlappingKeys(t *testing.T) {
	orderID := ids.GenerateTestID()
	shared := OrderKey{Symbol: "LUX/USDC", Side: orderbook.Buy, OrderID: orderID}

	v1 := &DexVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []OrderKey{shared, {Symbol: "BTC/USDC", Side: orderbook.Sell, OrderID: ids.GenerateTestID()}},
	}
	v2 := &DexVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []OrderKey{shared, {Symbol: "ETH/USDC", Side: orderbook.Buy, OrderID: ids.GenerateTestID()}},
	}

	if !v1.Conflicts(v2) {
		t.Fatal("expected conflict: vertices share (LUX/USDC, Buy, same orderID)")
	}
	if !v2.Conflicts(v1) {
		t.Fatal("expected conflict: symmetric check failed")
	}
}

func TestDexVertexConflicts_DisjointKeys(t *testing.T) {
	v1 := &DexVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []OrderKey{{Symbol: "LUX/USDC", Side: orderbook.Buy, OrderID: ids.GenerateTestID()}},
	}
	v2 := &DexVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []OrderKey{{Symbol: "BTC/USDC", Side: orderbook.Sell, OrderID: ids.GenerateTestID()}},
	}

	if v1.Conflicts(v2) {
		t.Fatal("expected no conflict: different symbols and order IDs")
	}
}

func TestDexVertexConflicts_SameSymbolDifferentOrderID(t *testing.T) {
	v1 := &DexVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []OrderKey{{Symbol: "LUX/USDC", Side: orderbook.Buy, OrderID: ids.GenerateTestID()}},
	}
	v2 := &DexVertex{
		id:     ids.GenerateTestID(),
		status: choices.Processing,
		keys:   []OrderKey{{Symbol: "LUX/USDC", Side: orderbook.Buy, OrderID: ids.GenerateTestID()}},
	}

	if v1.Conflicts(v2) {
		t.Fatal("expected no conflict: same symbol+side but different orderIDs")
	}
}
