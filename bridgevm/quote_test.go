// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"errors"
	"testing"
)

func TestStaticPriceFeed_GetSet(t *testing.T) {
	f := NewStaticPriceFeed(map[string]float64{"ETH": 3500})
	v, err := f.Price("eth")
	if err != nil {
		t.Fatalf("price: %v", err)
	}
	if v != 3500 {
		t.Fatalf("eth = %v, want 3500", v)
	}

	if _, err := f.Price("UNOBTAINIUM"); !errors.Is(err, ErrPriceUnknown) {
		t.Fatalf("missing asset: want ErrPriceUnknown, got %v", err)
	}

	f.Set("BTC", 65000)
	v, err = f.Price("BTC")
	if err != nil || v != 65000 {
		t.Fatalf("Set then Price: v=%v err=%v", v, err)
	}
}

func TestQuoteEngine_NoLuxExitFee(t *testing.T) {
	eng := &QuoteEngine{Feed: NewStaticPriceFeed(map[string]float64{
		"ETH": 3500,
		"LUX": 2.5,
	})}
	res, err := eng.Quote(QuoteInput{
		Amount:             1,
		SourceNetwork:      "ETHEREUM_SEPOLIA",
		SourceAsset:        "ETH",
		DestinationNetwork: "LUX_TESTNET",
		DestinationAsset:   "LUX",
	})
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	// 1 ETH @ $3500 → LUX @ $2.50 → 1400 LUX gross; no Lux-exit fee.
	if res.ReceiveAmount != 1400 {
		t.Errorf("ReceiveAmount = %v, want 1400", res.ReceiveAmount)
	}
	if res.ServiceFee != 0 {
		t.Errorf("ServiceFee = %v, want 0 for non-Lux exit", res.ServiceFee)
	}
	if want := 1400 * (1 - DefaultSlippage); approxEq(res.MinReceiveAmount, want) == false {
		t.Errorf("MinReceiveAmount = %v, want ~%v", res.MinReceiveAmount, want)
	}
}

func TestQuoteEngine_LuxExitAppliesFee(t *testing.T) {
	eng := &QuoteEngine{Feed: NewStaticPriceFeed(map[string]float64{
		"ETH": 3500,
		"LUX": 2.5,
	})}
	res, err := eng.Quote(QuoteInput{
		Amount:             1000,
		SourceNetwork:      "LUX_TESTNET",
		SourceAsset:        "LUX",
		DestinationNetwork: "ETHEREUM_SEPOLIA",
		DestinationAsset:   "ETH",
	})
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if res.ServiceFee <= 0 {
		t.Errorf("Lux-exit ServiceFee = %v, want > 0", res.ServiceFee)
	}
	// 1000 LUX @ $2.50 = $2500 / $3500 = 0.71428... ETH gross.
	// 1% fee → ~0.00714... ETH fee.
	if res.ReceiveAmount >= 0.7142858 {
		t.Errorf("ReceiveAmount = %v, want < gross (0.71428...) due to fee", res.ReceiveAmount)
	}
}

func TestQuoteEngine_UnknownAssetSurfacesErr(t *testing.T) {
	eng := &QuoteEngine{Feed: NewStaticPriceFeed(map[string]float64{"LUX": 2.5})}
	_, err := eng.Quote(QuoteInput{
		Amount:             1,
		SourceNetwork:      "ETHEREUM_SEPOLIA",
		SourceAsset:        "ETH",
		DestinationNetwork: "LUX_TESTNET",
		DestinationAsset:   "LUX",
	})
	if !errors.Is(err, ErrPriceUnknown) {
		t.Fatalf("unknown asset: want ErrPriceUnknown, got %v", err)
	}
}

func TestQuoteEngine_NegativeAmountRefused(t *testing.T) {
	eng := &QuoteEngine{Feed: NewStaticPriceFeed(map[string]float64{"LUX": 2.5, "ETH": 3500})}
	_, err := eng.Quote(QuoteInput{
		Amount:             -1,
		SourceNetwork:      "ETHEREUM_SEPOLIA",
		SourceAsset:        "ETH",
		DestinationNetwork: "LUX_TESTNET",
		DestinationAsset:   "LUX",
	})
	if err == nil {
		t.Fatalf("negative amount should error")
	}
}

func approxEq(a, b float64) bool {
	if a == b {
		return true
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-6
}
