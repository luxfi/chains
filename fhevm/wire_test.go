// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/zap"
)

// sampleTx is a fully-populated transaction whose every field is non-empty, so
// the canonical round-trip exercises every offset.
func sampleTx() *Transaction {
	tx := &Transaction{
		Type:     TxRegisterCiphertext,
		Scheme:   "ckks-n14",
		Subject:  [32]byte{9, 8, 7, 6, 5, 4, 3, 2, 1},
		GasLimit: 81000,
		Nonce:    42,
		Payload:  []byte("register-ciphertext-payload"),
		Auth:     []byte("payer-public-key-bytes"),
		Sig:      []byte("payer-signature-bytes"),
	}
	copy(tx.Payer[:], []byte("payer-address-20byte"))
	return tx
}

// TestWireCanonicalRoundTrip proves Bytes()→ParseTransaction is a faithful,
// idempotent round-trip and that the id is the content hash of the canonical
// wire (id == sha256(Bytes())).
func TestWireCanonicalRoundTrip(t *testing.T) {
	tx := sampleTx()
	data := tx.Bytes()

	parsed, err := ParseTransaction(data)
	if err != nil {
		t.Fatalf("ParseTransaction(canonical) failed: %v", err)
	}

	if got := parsed.Bytes(); string(got) != string(data) {
		t.Fatalf("re-serialization not canonical: parsed.Bytes() != input\n in =%x\n out=%x", data, got)
	}
	if want := ids.ID(sha256.Sum256(data)); parsed.ID() != want {
		t.Fatalf("id != sha256(Bytes()): got %s want %s", parsed.ID(), want)
	}

	// Field fidelity across the seam.
	if parsed.Type != tx.Type || parsed.Scheme != tx.Scheme ||
		parsed.GasLimit != tx.GasLimit || parsed.Nonce != tx.Nonce ||
		parsed.Payer != tx.Payer || parsed.Subject != tx.Subject ||
		string(parsed.Payload) != string(tx.Payload) ||
		string(parsed.Auth) != string(tx.Auth) || string(parsed.Sig) != string(tx.Sig) {
		t.Fatalf("field mismatch after round-trip:\n in =%+v\n out=%+v", tx, parsed)
	}
}

// TestWireContentIsThePrefixTheSignatureCovers proves what is authenticated and
// what is transmitted cannot come apart: the content object is a genuine
// byte-prefix of the wire, zapLen names exactly its length, and the signed
// preimage ENDS with that same prefix. So the only thing the signature covers
// that the wire does not carry is the chain id, which the verifier supplies.
func TestWireContentIsThePrefixTheSignatureCovers(t *testing.T) {
	tx := sampleTx()
	content := tx.content()
	full := tx.Bytes()
	if len(content) > len(full) || !bytes.Equal(full[:len(content)], content) {
		t.Fatal("content() is not a prefix of Bytes()")
	}
	n, err := zapLen(full)
	if err != nil {
		t.Fatalf("zapLen: %v", err)
	}
	if n != len(content) {
		t.Fatalf("zapLen = %d, want the content length %d", n, len(content))
	}

	pre := tx.SigningBytes(testChainID)
	if !bytes.HasSuffix(pre, content) {
		t.Fatal("the signed preimage does not end with the transmitted content")
	}
	if want := len(txDomain) + 32 + len(content); len(pre) != want {
		t.Fatalf("preimage is %d bytes, want domain+chain+content = %d", len(pre), want)
	}
}

// TestWireSigningBytesBindTheChain proves a preimage names ONE chain. Without
// it, a transaction signed on one F-Chain authenticates on every other — the
// payer's address is the hash of its public key, so the same account exists on
// all of them, and the replay burns a balance there for an operation nobody
// asked for.
func TestWireSigningBytesBindTheChain(t *testing.T) {
	tx := sampleTx()
	other := ids.ID{'o', 't', 'h', 'e', 'r'}
	if bytes.Equal(tx.SigningBytes(testChainID), tx.SigningBytes(other)) {
		t.Fatal("two chains produced one preimage: a signature would replay across them")
	}
	// And the domain separates a transaction preimage from a bare content
	// encoding, so no other digest this chain computes can stand in for one.
	if !bytes.HasPrefix(tx.SigningBytes(testChainID), []byte(txDomain)) {
		t.Fatal("the preimage is not domain-separated")
	}
}

// TestWireSigningBytesBindEveryField proves the signed preimage changes when
// ANY semantically-meaningful field changes — including Subject, which names
// the object the operation acts on. A field the signature did not cover could
// be swapped in flight.
func TestWireSigningBytesBindEveryField(t *testing.T) {
	base := string(sampleTx().SigningBytes(testChainID))
	for name, mutate := range map[string]func(*Transaction){
		"Type":     func(tx *Transaction) { tx.Type = TxGrantPermit },
		"Scheme":   func(tx *Transaction) { tx.Scheme = "bfv-n13" },
		"Payer":    func(tx *Transaction) { tx.Payer[0] ^= 0xff },
		"Subject":  func(tx *Transaction) { tx.Subject[0] ^= 0xff },
		"GasLimit": func(tx *Transaction) { tx.GasLimit++ },
		"Nonce":    func(tx *Transaction) { tx.Nonce++ },
		"Payload":  func(tx *Transaction) { tx.Payload = append(tx.Payload, 'x') },
	} {
		tx := sampleTx()
		mutate(tx)
		if string(tx.SigningBytes(testChainID)) == base {
			t.Fatalf("changing %s left the signed preimage unchanged", name)
		}
	}
	// Auth and Sig are deliberately EXCLUDED from the preimage: the signature
	// cannot cover itself.
	tx := sampleTx()
	tx.Auth = []byte("a-different-public-key")
	tx.Sig = []byte("a-different-signature")
	if string(tx.SigningBytes(testChainID)) != base {
		t.Fatal("Auth/Sig must not appear in the signed preimage")
	}
}

// TestWireRejectsNonCanonical proves the canonical gate: zap follows the root
// offset and ignores unreferenced padding inside a message's declared size, so
// a twin buffer can decode to identical fields yet hash differently. Parse must
// reject any input that is not already byte-equal to its re-serialized form —
// exactly one byte-string authenticates per logical tx (no id-malleability).
func TestWireRejectsNonCanonical(t *testing.T) {
	tx := sampleTx()
	data := tx.Bytes()

	// Split the two concatenated zap messages (signing ‖ sig).
	n, err := zapLen(data)
	if err != nil {
		t.Fatalf("zapLen: %v", err)
	}

	// Craft a non-canonical twin: append 8 unreferenced bytes to the trailing
	// (sig) message and bump its declared size field so a naive
	// n+gm.Size()==len(data) trailing-bytes check still passes. The root offset
	// does not reference the padding, so the fields decode identically.
	sig := append([]byte(nil), data[n:]...)
	sig = append(sig, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(sig[12:16], uint32(len(sig)))
	twin := append(append([]byte(nil), data[:n]...), sig...)

	if string(twin) == string(data) {
		t.Fatal("twin construction failed to differ from canonical")
	}
	if got := int(binary.LittleEndian.Uint32(twin[n+12 : n+16])); got != len(sig) {
		t.Fatalf("twin size field not bumped: got %d want %d", got, len(sig))
	}
	if _, err := ParseTransaction(twin); err == nil {
		t.Fatal("ParseTransaction accepted a non-canonical (padded) twin — id-malleability not closed")
	}
}

// TestWireParseRejectsTruncated confirms the parser fails closed on a short
// buffer rather than reading past the end.
func TestWireParseRejectsTruncated(t *testing.T) {
	data := sampleTx().Bytes()
	for _, cut := range []int{0, 4, zap.HeaderSize, len(data) - 1} {
		if _, err := ParseTransaction(data[:cut]); err == nil {
			t.Fatalf("ParseTransaction accepted truncated buffer of len %d", cut)
		}
	}
}

// TestWireParseRejectsTrailing confirms bytes appended after a complete
// transaction are refused rather than ignored.
func TestWireParseRejectsTrailing(t *testing.T) {
	data := append(sampleTx().Bytes(), 0xde, 0xad)
	if _, err := ParseTransaction(data); err == nil {
		t.Fatal("ParseTransaction accepted trailing bytes")
	}
}

// wireVM is the least VM a block needs to name itself: a chain id. A block id
// commits to the chain it belongs to, so there is no such thing as a block
// without one.
func wireVM() *VM { return &VM{chainID: testChainID} }

// TestBlockWireRoundTrip proves a block serializes and re-parses with its
// transactions intact and its id unchanged.
func TestBlockWireRoundTrip(t *testing.T) {
	a := sampleTx()
	b := sampleTx()
	b.Nonce = 43
	b.Payload = []byte("second")
	vm := wireVM()
	blk := &Block{
		parentID:     ids.ID{1, 2, 3},
		height:       7,
		timestamp:    timeAt(1_700_000_000),
		transactions: []*Transaction{a, b},
		vm:           vm,
	}
	blk.id = blk.computeID()

	parsed, err := parseBlock(vm, blk.Bytes())
	if err != nil {
		t.Fatalf("parseBlock: %v", err)
	}
	if parsed.id != blk.id {
		t.Fatalf("block id changed across the wire: %s != %s", parsed.id, blk.id)
	}
	if parsed.height != blk.height || parsed.parentID != blk.parentID ||
		!parsed.timestamp.Equal(blk.timestamp) {
		t.Fatalf("header mismatch:\n in =%+v\n out=%+v", blk, parsed)
	}
	if len(parsed.transactions) != 2 {
		t.Fatalf("got %d transactions, want 2", len(parsed.transactions))
	}
	for i, tx := range parsed.transactions {
		if tx.ID() != blk.transactions[i].ID() {
			t.Fatalf("transaction %d id changed across the wire", i)
		}
	}
}

// TestBlockWireRejectsTrailing confirms a block with appended bytes is refused.
func TestBlockWireRejectsTrailing(t *testing.T) {
	vm := wireVM()
	blk := &Block{parentID: ids.ID{1}, height: 1, timestamp: timeAt(1), vm: vm}
	if _, err := parseBlock(vm, append(blk.Bytes(), 0xff)); err == nil {
		t.Fatal("parseBlock accepted trailing bytes")
	}
}

// TestBlockIDBindsTheChain proves the same block bytes name DIFFERENT blocks on
// different chains, and — the case that matters most — that two chains sharing
// a genesis timestamp do not share a genesis id. They did: the id hashed parent,
// height, time and transactions, none of which distinguishes one F-Chain from
// another, so every chain's height-0 block had the same name and a block built
// on one resolved its parent on all of them.
func TestBlockIDBindsTheChain(t *testing.T) {
	mk := func(chain ids.ID) ids.ID {
		vm := &VM{chainID: chain}
		blk := &Block{parentID: ids.Empty, height: 0, timestamp: timeAt(testGenesisTime), vm: vm}
		return blk.computeID()
	}
	if mk(testChainID) == mk(ids.ID{'o', 't', 'h', 'e', 'r'}) {
		t.Fatal("two chains share a genesis id")
	}
	if mk(testChainID) != mk(testChainID) {
		t.Fatal("a block id must be a function of its content, not of the call")
	}
}

// TestBuildBudgetNeverUnderstatesTheBlock pins the relation BuildBlock's
// selection loop depends on: its running total — emptyBlockSize plus each
// transaction's wire length plus txEntry — is never LESS than what Bytes()
// actually produces. If it could understate, a proposer would select its way
// past MaxBlockSize and build a block its own Verify refuses, which is the
// halt-shaped bug of a builder and a checker that disagree.
//
// Payload lengths vary per step so the eight-byte alignment txEntry covers is
// exercised at every offset, not only where the numbers happen to divide.
func TestBuildBudgetNeverUnderstatesTheBlock(t *testing.T) {
	vm := wireVM()
	var txs []*Transaction
	budget := emptyBlockSize
	for n := 0; n <= 24; n++ {
		blk := &Block{parentID: ids.ID{7}, height: uint64(n), timestamp: timeAt(1), transactions: txs, vm: vm}
		if actual := len(blk.Bytes()); budget < actual {
			t.Fatalf("%d txs: budget %d understates the block's %d bytes", n, budget, actual)
		}
		tx := sampleTx()
		tx.Nonce = uint64(n)
		tx.Payload = bytes.Repeat([]byte{byte(n)}, n)
		txs = append(txs, tx)
		budget += len(tx.Bytes()) + txEntry
	}
}

// TestParseRefusesEveryMalformedBlock walks what a peer can send that is not a
// block. Each is refused with an error rather than a partial decode, and none
// of them costs a signature check.
func TestParseRefusesEveryMalformedBlock(t *testing.T) {
	vm := wireVM()
	tx := sampleTx()
	blk := &Block{parentID: ids.ID{3}, height: 4, timestamp: timeAt(1_700_000_000),
		transactions: []*Transaction{tx}, vm: vm}
	sound := blk.Bytes()

	// A header that is not a zap message at all.
	garbage := make([]byte, zap.HeaderSize+16)
	binary.LittleEndian.PutUint32(garbage[12:16], uint32(len(garbage)))
	if _, err := parseBlock(vm, garbage); err == nil {
		t.Fatal("parseBlock accepted a message that decodes to nothing")
	}

	// A length entry that runs past the blob it indexes.
	over := blockBytesWithTxLens(blk, []uint32{uint32(len(tx.Bytes()) + 64)})
	if _, err := parseBlock(vm, over); err == nil {
		t.Fatal("parseBlock accepted a length running past the blob")
	}

	// A length entry that stops short, so the transaction under it does not
	// decode.
	short := blockBytesWithTxLens(blk, []uint32{uint32(len(tx.Bytes()) - 8)})
	if _, err := parseBlock(vm, short); err == nil {
		t.Fatal("parseBlock accepted a truncated transaction")
	}

	// A block over the size bound is refused before it is decoded at all.
	if _, err := parseBlock(vm, make([]byte, MaxBlockSize+1)); err == nil {
		t.Fatal("parseBlock accepted a message over the size bound")
	}

	// The control: the sound encoding parses and names the same block.
	got, err := parseBlock(vm, sound)
	if err != nil {
		t.Fatalf("parseBlock(sound): %v", err)
	}
	if got.id != blk.computeID() {
		t.Fatal("a sound block did not name itself")
	}
}

// TestParseRefusesANonCanonicalBlock proves a block has exactly one encoding.
// zap ignores padding the root does not reference, so without this a block has
// as many byte-strings as an attacker cares to make and one id.
func TestParseRefusesANonCanonicalBlock(t *testing.T) {
	vm := wireVM()
	blk := &Block{parentID: ids.ID{5}, height: 2, timestamp: timeAt(1_700_000_000),
		transactions: []*Transaction{sampleTx()}, vm: vm}
	data := blk.Bytes()

	// Grow the message's declared size and pad it. The root offset does not
	// reference the padding, so every field still decodes identically.
	padded := append(append([]byte(nil), data...), make([]byte, 16)...)
	binary.LittleEndian.PutUint32(padded[12:16], uint32(len(padded)))
	if bytes.Equal(padded, data) {
		t.Fatal("the twin is not a twin")
	}
	if _, err := parseBlock(vm, padded); err == nil {
		t.Fatal("parseBlock accepted a padded twin — a block with two encodings")
	}
}

// TestParseRefusesAMalformedTransaction covers the seam between a
// transaction's two concatenated messages: the trailing Auth/Sig object must
// itself be a message.
func TestParseRefusesAMalformedTransaction(t *testing.T) {
	data := sampleTx().Bytes()
	n, err := zapLen(data)
	if err != nil {
		t.Fatalf("zapLen: %v", err)
	}
	broken := append(append([]byte(nil), data[:n]...), make([]byte, zap.HeaderSize)...)
	binary.LittleEndian.PutUint32(broken[n+12:n+16], uint32(zap.HeaderSize))
	if _, err := ParseTransaction(broken); err == nil {
		t.Fatal("ParseTransaction accepted a trailing object that decodes to nothing")
	}
}

// TestAppendBytesDistinguishesEmptyFromNil proves an absent field comes back
// nil rather than an empty non-nil slice, so a re-serialization of what was
// parsed is byte-identical to what arrived — which is the whole canonical rule.
func TestAppendBytesDistinguishesEmptyFromNil(t *testing.T) {
	if got := appendBytes(nil); got != nil {
		t.Fatalf("appendBytes(nil) = %v, want nil", got)
	}
	if got := appendBytes([]byte{}); got != nil {
		t.Fatalf("appendBytes(empty) = %v, want nil", got)
	}
	if got := appendBytes([]byte{1, 2}); !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("appendBytes copied wrong: %v", got)
	}

	// A transaction with no scheme and no payload round-trips, which is what
	// that distinction buys.
	bare := &Transaction{Type: TxRevokePermit, Nonce: 1}
	again, err := ParseTransaction(bare.Bytes())
	if err != nil {
		t.Fatalf("a bare transaction did not round-trip: %v", err)
	}
	if again.Scheme != "" || again.Payload != nil || again.Auth != nil || again.Sig != nil {
		t.Fatalf("absent fields came back present: %+v", again)
	}
}

// blockBytesWithTxLens rebuilds a block's wire form with a length list the
// caller chooses, so the parser can be tested against lengths a builder would
// never produce.
func blockBytesWithTxLens(b *Block, txLens []uint32) []byte {
	var txBlob []byte
	for _, tx := range b.transactions {
		txBlob = append(txBlob, tx.Bytes()...)
	}
	bld := zap.NewBuilder(zap.HeaderSize + blkSize + len(txBlob) + 4*len(txLens) + 128)
	off := writeU32List(bld, txLens)
	ob := bld.StartObject(blkSize)
	ob.SetBytesFixed(blkParent, b.parentID[:])
	ob.SetUint64(blkHeight, b.height)
	ob.SetInt64(blkTime, b.timestamp.Unix())
	ob.SetList(blkTxLens, off, len(txLens))
	ob.SetBytes(blkTxBlob, txBlob)
	ob.FinishAsRoot()
	return bld.Finish()
}

// TestParseRefusesATransactionWithNoAuthObject proves the second of a
// transaction's two concatenated messages must actually be there. A declared
// length covering the whole buffer leaves nothing for the Auth/Sig object, and
// an empty remainder is not a message.
func TestParseRefusesATransactionWithNoAuthObject(t *testing.T) {
	data := append([]byte(nil), sampleTx().Bytes()...)
	binary.LittleEndian.PutUint32(data[12:16], uint32(len(data)))
	if _, err := ParseTransaction(data); err == nil {
		t.Fatal("ParseTransaction accepted a transaction with no Auth/Sig object")
	}
}

// TestParseRefusesAContentObjectThatIsNotOne proves the leading message is held
// to more than its declared length. zapLen reads only the size field, so a
// buffer can name a plausible length and still not be a message at all — a
// wrong magic, or a wire version this build does not speak.
func TestParseRefusesAContentObjectThatIsNotOne(t *testing.T) {
	sound := sampleTx().Bytes()
	for name, corrupt := range map[string]func([]byte){
		"a magic this is not":       func(b []byte) { b[0] ^= 0xff },
		"a version we do not speak": func(b []byte) { binary.LittleEndian.PutUint16(b[4:6], 0xbeef) },
	} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), sound...)
			corrupt(data)
			if _, err := zapLen(data); err != nil {
				t.Fatalf("the length field is still sound; zapLen must pass: %v", err)
			}
			if _, err := ParseTransaction(data); err == nil {
				t.Fatal("ParseTransaction accepted a buffer that is not a message")
			}
		})
	}
	if _, err := ParseTransaction(sound); err != nil {
		t.Fatalf("the control failed: %v", err)
	}
}
