// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"errors"
	"strings"
	"testing"
)

func TestInMemorySwapStore_PutGet(t *testing.T) {
	s := newInMemorySwapStore()
	rec := &BridgeRequestRecord{
		SourceChain: "ETHEREUM_SEPOLIA",
		DestChain:   "LUX_TESTNET",
		SourceAsset: "ETH",
		DestAsset:   "LUX",
		Amount:      "1",
		Recipient:   "0xa28fAE14eB42e7A5C36Ad2D774a2b7Eb293c4473",
	}
	if err := s.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.HasPrefix(rec.RequestID, "req_") {
		t.Errorf("RequestID = %q, want req_ prefix", rec.RequestID)
	}
	if rec.Status != StatusPending {
		t.Errorf("default Status = %q, want pending", rec.Status)
	}

	got, err := s.Get(rec.RequestID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Recipient != rec.Recipient {
		t.Errorf("Recipient = %q, want %q", got.Recipient, rec.Recipient)
	}
}

func TestInMemorySwapStore_GetMissing(t *testing.T) {
	s := newInMemorySwapStore()
	if _, err := s.Get("req_nope"); !errors.Is(err, ErrSwapNotFound) {
		t.Fatalf("missing id: want ErrSwapNotFound, got %v", err)
	}
}

func TestInMemorySwapStore_Patch(t *testing.T) {
	s := newInMemorySwapStore()
	rec := &BridgeRequestRecord{SourceChain: "A", DestChain: "B", Amount: "1", Recipient: "x"}
	_ = s.Put(rec)

	out, err := s.Patch(rec.RequestID, func(r *BridgeRequestRecord) {
		r.Status = StatusSigning
		r.SourceTxHash = "0xsrctx"
	})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if out.Status != StatusSigning || out.SourceTxHash != "0xsrctx" {
		t.Errorf("Patch leftovers: %+v", out)
	}
	// Refetch to confirm persistence.
	got, _ := s.Get(rec.RequestID)
	if got.Status != StatusSigning {
		t.Errorf("Status not persisted: %q", got.Status)
	}
}

func TestInMemorySwapStore_ListFilter(t *testing.T) {
	s := newInMemorySwapStore()
	_ = s.Put(&BridgeRequestRecord{SourceChain: "A", Status: StatusPending})
	_ = s.Put(&BridgeRequestRecord{SourceChain: "A", Status: StatusCompleted})
	_ = s.Put(&BridgeRequestRecord{SourceChain: "B", Status: StatusCompleted})

	all, _ := s.List(SwapListFilter{})
	if len(all) != 3 {
		t.Errorf("unfiltered: got %d, want 3", len(all))
	}

	done, _ := s.List(SwapListFilter{Status: StatusCompleted})
	if len(done) != 2 {
		t.Errorf("status=completed: got %d, want 2", len(done))
	}

	aChain, _ := s.List(SwapListFilter{SourceChain: "A"})
	if len(aChain) != 2 {
		t.Errorf("source=A: got %d, want 2", len(aChain))
	}

	limited, _ := s.List(SwapListFilter{Limit: 1})
	if len(limited) != 1 {
		t.Errorf("limit=1: got %d, want 1", len(limited))
	}
}
