// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package rpcverify is the REAL, network-backed ChainVerifier used by CI (and any
// out-of-process validator) to prove a manifest's assets exist on the TARGET net
// before a deploy. It is kept out of the registry package proper so the
// consensus-path registry carries no JSON-RPC / EVM-client dependency; only the
// offline validator links it.
//
// For an ERC-20 it confirms: the C-Chain's eth_chainId matches the manifest's
// declared EVMChainID, the contract has code (eth_getCode length > 0), and a static
// decimals() call returns a value (which the registry then cross-checks against the
// manifest's declared decimals). For EVM_NATIVE it confirms the chainID. UTXO
// verification is delegated to the X-Chain avm.getAssetDescription endpoint.
package rpcverify

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/ethclient"
	"github.com/luxfi/ids"

	gethereum "github.com/luxfi/geth"
)

// Verifier proves assets real against a live network: a C-Chain EVM RPC (for
// EVM_NATIVE/ERC20) and a P-Chain + X-Chain API base (for the C-Chain consensus-id
// confirm and UTXO asset descriptions).
type Verifier struct {
	eth        *ethclient.Client
	apiBase    string // e.g. https://api.lux.network — used for platform/avm JSON-RPC
	httpc      *http.Client
	nativeDec  uint8
	timeout    time.Duration
}

// New dials the C-Chain EVM RPC and records the node API base for P/X queries.
// evmRPC is the full C-Chain RPC URL (…/ext/bc/C/rpc); apiBase is the node root
// (…) used to reach /ext/P and /ext/bc/X. nativeDecimals is the C-Chain native
// coin's decimals (18 for LUX).
func New(ctx context.Context, evmRPC, apiBase string, nativeDecimals uint8) (*Verifier, error) {
	ec, err := ethclient.DialContext(ctx, evmRPC)
	if err != nil {
		return nil, fmt.Errorf("rpcverify: dial C-Chain RPC %s: %w", evmRPC, err)
	}
	return &Verifier{
		eth:       ec,
		apiBase:   strings.TrimRight(apiBase, "/"),
		httpc:     &http.Client{Timeout: 20 * time.Second},
		nativeDec: nativeDecimals,
		timeout:   20 * time.Second,
	}, nil
}

// ConfirmCChain implements registry.CChainConfirmer: it confirms the live C-Chain's
// eth_chainId equals the manifest's EVMChainID and the live C-Chain consensus id
// equals the manifest's CChainID (queried from the P-Chain). A mismatch on either
// means the validator is pointed at the wrong network — the manifest must NOT be
// admitted.
func (v *Verifier) ConfirmCChain(networkID uint32, evmChainID uint64, cChainID ids.ID) error {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	got, err := v.eth.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("eth_chainId: %w", err)
	}
	if want := new(big.Int).SetUint64(evmChainID); got.Cmp(want) != 0 {
		return fmt.Errorf("eth_chainId mismatch: RPC=%s manifest=%s (wrong network)", got, want)
	}

	liveC, err := v.resolveCChainID(ctx, networkID)
	if err != nil {
		return fmt.Errorf("resolve live C-Chain id: %w", err)
	}
	if liveC != cChainID {
		return fmt.Errorf("C-Chain consensus id mismatch: live=%s manifest=%s", liveC, cChainID)
	}
	return nil
}

// VerifyERC20 confirms a contract has code at addr and returns its decimals().
func (v *Verifier) VerifyERC20(_ uint32, _ ids.ID, addr []byte) (uint8, error) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	a := common.BytesToAddress(addr)
	code, err := v.eth.CodeAt(ctx, a, nil)
	if err != nil {
		return 0, fmt.Errorf("eth_getCode(%s): %w", a.Hex(), err)
	}
	if len(code) == 0 {
		return 0, fmt.Errorf("no contract code at %s (not a real ERC-20 on this net)", a.Hex())
	}
	dec, err := v.callDecimals(ctx, a)
	if err != nil {
		return 0, fmt.Errorf("decimals() at %s: %w", a.Hex(), err)
	}
	return dec, nil
}

// VerifyEVMNative confirms the C-Chain is reachable (chainID readable) and returns
// the native decimals. (The chainID equality is enforced once in ConfirmCChain.)
func (v *Verifier) VerifyEVMNative(_ uint32, _ ids.ID) (uint8, error) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()
	if _, err := v.eth.ChainID(ctx); err != nil {
		return 0, fmt.Errorf("native chainID: %w", err)
	}
	return v.nativeDec, nil
}

// VerifyUTXOAsset confirms a UTXO assetID exists via the X-Chain
// avm.getAssetDescription endpoint and returns its denomination.
func (v *Verifier) VerifyUTXOAsset(_ uint32, _ ids.ID, assetID ids.ID) (uint8, error) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()
	var out struct {
		Result struct {
			Denomination jsonUint8 `json:"denomination"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := v.jsonRPC(ctx, "/ext/bc/X", "avm.getAssetDescription",
		map[string]any{"assetID": assetID.String()}, &out); err != nil {
		return 0, err
	}
	if out.Error != nil {
		return 0, fmt.Errorf("avm.getAssetDescription: %s (asset not on this net)", out.Error.Message)
	}
	return uint8(out.Result.Denomination), nil
}

// resolveCChainID asks the P-Chain for the blockchain whose name is "C" and returns
// its id — the live, authoritative C-Chain consensus id for this net.
func (v *Verifier) resolveCChainID(ctx context.Context, _ uint32) (ids.ID, error) {
	var out struct {
		Result struct {
			Blockchains []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"blockchains"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := v.jsonRPC(ctx, "/ext/P", "platform.getBlockchains", map[string]any{}, &out); err != nil {
		return ids.Empty, err
	}
	if out.Error != nil {
		return ids.Empty, fmt.Errorf("platform.getBlockchains: %s", out.Error.Message)
	}
	for _, b := range out.Result.Blockchains {
		// The Lux P-Chain names the EVM chain "C-Chain" (older nets used "C").
		if b.Name == "C-Chain" || b.Name == "C" {
			return ids.FromString(b.ID)
		}
	}
	return ids.Empty, fmt.Errorf("no C-Chain in platform.getBlockchains")
}

// decimalsSelector is the 4-byte selector of ERC-20 decimals() — keccak256("decimals()")[:4].
var decimalsSelector = []byte{0x31, 0x3c, 0xe5, 0x67}

// callDecimals performs a static eth_call to decimals() and decodes the uint8.
func (v *Verifier) callDecimals(ctx context.Context, addr common.Address) (uint8, error) {
	out, err := v.eth.CallContract(ctx, gethereum.CallMsg{To: &addr, Data: decimalsSelector}, nil)
	if err != nil {
		return 0, err
	}
	if len(out) == 0 {
		return 0, fmt.Errorf("decimals() returned empty (not ERC-20 compliant)")
	}
	// decimals() returns a uint8 right-aligned in a 32-byte word.
	return out[len(out)-1], nil
}

// jsonRPC posts a single JSON-RPC 2.0 call to apiBase+path and decodes into out.
func (v *Verifier) jsonRPC(ctx context.Context, path, method string, params any, out any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.apiBase+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, v.apiBase+path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// jsonUint8 accepts either a JSON number or a numeric string for a uint8 field
// (some avm responses stringify the denomination).
type jsonUint8 uint8

func (j *jsonUint8) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	var n uint64
	if _, err := fmt.Sscan(s, &n); err != nil {
		return fmt.Errorf("rpcverify: bad uint8 %q: %w", s, err)
	}
	if n > 255 {
		return fmt.Errorf("rpcverify: denomination %d out of uint8 range", n)
	}
	*j = jsonUint8(n)
	return nil
}
