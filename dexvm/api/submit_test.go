// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package api

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/luxfi/ids"
)

// stubVM implements api.VM for the SubmitTx tests. bootstrapped toggles the
// IsBootstrapped gate; the relay is never exercised by SubmitTx.
type stubVM struct {
	bootstrapped bool
}

func (s *stubVM) IsBootstrapped() bool { return s.bootstrapped }
func (s *stubVM) Relay() Relayer       { return stubRelayer{} }

type stubRelayer struct{}

func (stubRelayer) Configured() bool { return false }
func (stubRelayer) Relay(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("unused")
}

// stubSubmitter records the last tx handed to SubmitTx and can be told to fail,
// so the test can assert the service forwards bytes verbatim and propagates errors.
type stubSubmitter struct {
	last []byte
	err  error
}

func (s *stubSubmitter) SubmitTx(tx []byte) error {
	s.last = append([]byte(nil), tx...)
	return s.err
}

// TestSubmitTx_NoSubmitter proves the read-only surface (NewService, no submitter)
// reports ErrSubmitUnavailable — the standalone/test path keeps Ping/Status/Relay
// but cannot inject txs.
func TestSubmitTx_NoSubmitter(t *testing.T) {
	svc := NewService(&stubVM{bootstrapped: true})
	err := svc.SubmitTx(nil, &SubmitTxArgs{Tx: "00"}, &SubmitTxReply{})
	if !errors.Is(err, ErrSubmitUnavailable) {
		t.Fatalf("want ErrSubmitUnavailable, got %v", err)
	}
}

// TestSubmitTx_NotBootstrapped proves a submit mid-bootstrap is refused before it
// can race the state machine.
func TestSubmitTx_NotBootstrapped(t *testing.T) {
	svc := NewServiceWithSubmitter(&stubVM{bootstrapped: false}, &stubSubmitter{})
	err := svc.SubmitTx(nil, &SubmitTxArgs{Tx: "00"}, &SubmitTxReply{})
	if !errors.Is(err, ErrNotBootstrapped) {
		t.Fatalf("want ErrNotBootstrapped, got %v", err)
	}
}

// TestSubmitTx_BadHex proves a non-hex tx is a clean ErrInvalidRequest, never a
// panic or a partial submit.
func TestSubmitTx_BadHex(t *testing.T) {
	sub := &stubSubmitter{}
	svc := NewServiceWithSubmitter(&stubVM{bootstrapped: true}, sub)
	if err := svc.SubmitTx(nil, &SubmitTxArgs{Tx: "zz"}, &SubmitTxReply{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest, got %v", err)
	}
	if sub.last != nil {
		t.Fatalf("bad-hex tx must not reach the submitter, got %x", sub.last)
	}
}

// TestSubmitTx_EmptyTx proves an empty tx is rejected before the submitter.
func TestSubmitTx_EmptyTx(t *testing.T) {
	sub := &stubSubmitter{}
	svc := NewServiceWithSubmitter(&stubVM{bootstrapped: true}, sub)
	if err := svc.SubmitTx(nil, &SubmitTxArgs{Tx: ""}, &SubmitTxReply{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest, got %v", err)
	}
}

// TestSubmitTx_Success proves the happy path: the wire bytes reach the submitter
// VERBATIM and the returned TxID is the canonical ids.Checksum256 of those bytes
// (byte-identical to what the VM stamps as txs.BaseTx.TxID — the keeper's
// correlation handle).
func TestSubmitTx_Success(t *testing.T) {
	sub := &stubSubmitter{}
	svc := NewServiceWithSubmitter(&stubVM{bootstrapped: true}, sub)

	// A representative dexvm wire: type byte (TxRelayOrder=2) + a JSON body. The
	// service does not parse it; it only forwards + hashes.
	wire := append([]byte{2}, []byte(`{"type":2,"method":"clob_submit"}`)...)
	args := &SubmitTxArgs{Tx: hex.EncodeToString(wire)}
	reply := &SubmitTxReply{}

	if err := svc.SubmitTx(nil, args, reply); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	if string(sub.last) != string(wire) {
		t.Fatalf("submitter got %x, want verbatim %x", sub.last, wire)
	}
	want := ids.Checksum256(wire).String()
	if reply.TxID != want {
		t.Fatalf("TxID = %s, want %s (ids.Checksum256 of the wire)", reply.TxID, want)
	}
}

// TestSubmitTx_SubmitterError proves a submitter rejection (e.g. the fee gate)
// propagates to the caller and is not swallowed into a fake success.
func TestSubmitTx_SubmitterError(t *testing.T) {
	sentinel := errors.New("fee gate: zero-fee tx refused")
	sub := &stubSubmitter{err: sentinel}
	svc := NewServiceWithSubmitter(&stubVM{bootstrapped: true}, sub)
	err := svc.SubmitTx(nil, &SubmitTxArgs{Tx: "02"}, &SubmitTxReply{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want submitter error propagated, got %v", err)
	}
}
