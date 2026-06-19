// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompiles

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/starkfri"
)

func TestGroth16VerifierGas(t *testing.T) {
	v := &Groth16Verifier{}
	if g := v.RequiredGas(nil); g != groth16Gas {
		t.Fatalf("expected %d gas, got %d", groth16Gas, g)
	}
}

func TestGroth16VerifierRejectsTooShort(t *testing.T) {
	v := &Groth16Verifier{}
	result, err := v.Run([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for short input")
	}
	if len(result) != 1 || result[0] != 0x00 {
		t.Fatal("expected 0x00 result for invalid input")
	}
}

// TestGroth16VerifierValidProof constructs a trivial Groth16 proof
// and verifying key using known discrete log relations, then verifies it.
func TestGroth16VerifierValidProof(t *testing.T) {
	// Generate a valid Groth16 proof/VK pair with known trapdoor.
	// Trapdoor: alpha, beta, gamma, delta, tau are random field elements.
	var alpha, beta, gamma, delta fr.Element
	alpha.SetRandom()
	beta.SetRandom()
	gamma.SetRandom()
	delta.SetRandom()

	_, _, g1, g2 := bn254.Generators()

	var alphaBI, betaBI, gammaBI, deltaBI big.Int

	// VK components
	var vkAlpha bn254.G1Affine
	vkAlpha.ScalarMultiplication(&g1, alpha.BigInt(&alphaBI))

	var vkBeta bn254.G2Affine
	vkBeta.ScalarMultiplication(&g2, beta.BigInt(&betaBI))

	var vkGamma bn254.G2Affine
	vkGamma.ScalarMultiplication(&g2, gamma.BigInt(&gammaBI))

	var vkDelta bn254.G2Affine
	vkDelta.ScalarMultiplication(&g2, delta.BigInt(&deltaBI))

	// Single public input: witness w. K[0] = g1, K[1] = g1 (simple circuit).
	vkK := []bn254.G1Affine{g1, g1}

	// Witness
	var w fr.Element
	w.SetRandom()

	// pubLC = K[0] + w * K[1] = g1 + w*g1 = (1+w)*g1
	var onePlusW fr.Element
	onePlusW.SetOne()
	onePlusW.Add(&onePlusW, &w)

	var pubLC bn254.G1Affine
	var onePlusWBI big.Int
	pubLC.ScalarMultiplication(&g1, onePlusW.BigInt(&onePlusWBI))

	// For a valid Groth16 proof, we need:
	// e(A, B) = e(alpha, beta) * e(pubLC, gamma) * e(C, delta)
	//
	// Pick random r, s. Set:
	//   A = alpha + r*delta (in G1)
	//   B = beta + s*delta (in G2)
	//   C = (alpha*beta + r*s*delta^2 + pubLC*gamma_inv*delta - alpha*beta) / delta
	//     = (r*beta + s*alpha + r*s*delta) + pubLC * gamma_inv  ... simplified
	//
	// Simplest valid proof: use the identity that e(A,B) can be decomposed.
	// For testing, we use the multi-pairing check directly.
	//
	// We construct A, B, C such that the pairing equation holds.
	// Let A = alpha*g1, B = beta*g2. Then e(A,B) = e(alpha*g1, beta*g2).
	// We need e(alpha*g1, beta*g2) = e(vkAlpha, vkBeta) * e(pubLC, vkGamma) * e(C, vkDelta)
	// = e(alpha*g1, beta*g2) * e(pubLC, gamma*g2) * e(C, delta*g2)
	//
	// So we need e(pubLC, gamma*g2) * e(C, delta*g2) = 1
	// i.e., e(pubLC, gamma*g2) = e(-C, delta*g2)
	// i.e., C = pubLC * gamma / delta (scalar division in the exponent)
	var gammaInvDelta fr.Element
	gammaInvDelta.Div(&gamma, &delta)

	var gammaInvDeltaBI big.Int
	gammaInvDelta.BigInt(&gammaInvDeltaBI)

	var proofC bn254.G1Affine
	proofC.ScalarMultiplication(&pubLC, &gammaInvDeltaBI)
	proofC.Neg(&proofC)

	proofA := vkAlpha // alpha * g1
	proofB := vkBeta  // beta * g2

	// Verify the pairing equation holds (sanity check before serializing)
	{
		var negA, negPubLC, negC bn254.G1Affine
		negA.Neg(&vkAlpha)
		negPubLC.Neg(&pubLC)
		negC.Neg(&proofC)
		ok, err := bn254.PairingCheck(
			[]bn254.G1Affine{proofA, negA, negPubLC, negC},
			[]bn254.G2Affine{proofB, vkBeta, vkGamma, vkDelta},
		)
		if err != nil {
			t.Fatalf("sanity pairing error: %v", err)
		}
		if !ok {
			t.Fatal("sanity pairing check failed — test setup is wrong")
		}
	}

	// Serialize
	input := serializeGroth16Input(
		&groth16VK{Alpha: vkAlpha, Beta: vkBeta, Gamma: vkGamma, Delta: vkDelta, K: vkK},
		&groth16Proof{Ar: proofA, Bs: proofB, Krs: proofC},
		[]fr.Element{w},
	)

	v := &Groth16Verifier{}
	result, err := v.Run(input)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(result) != 1 || result[0] != 0x01 {
		t.Fatalf("expected valid proof (0x01), got %x", result)
	}
}

func TestGroth16VerifierRejectsInvalidProof(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()

	// Construct a VK with generators
	vk := &groth16VK{
		Alpha: g1,
		Beta:  g2,
		Gamma: g2,
		Delta: g2,
		K:     []bn254.G1Affine{g1, g1},
	}

	// Random (invalid) proof — points are on curve but pairing won't check out
	var r fr.Element
	r.SetRandom()
	var randG1 bn254.G1Affine
	var rBI big.Int
	randG1.ScalarMultiplication(&g1, r.BigInt(&rBI))

	proof := &groth16Proof{Ar: randG1, Bs: g2, Krs: g1}

	var w fr.Element
	w.SetRandom()

	input := serializeGroth16Input(vk, proof, []fr.Element{w})

	v := &Groth16Verifier{}
	result, err := v.Run(input)
	if err != nil {
		t.Fatalf("Run should not return error for invalid proof, got: %v", err)
	}
	if len(result) != 1 || result[0] != 0x00 {
		t.Fatalf("expected invalid proof (0x00), got %x", result)
	}
}

func TestPLONKVerifierGas(t *testing.T) {
	v := &PLONKVerifier{}
	if g := v.RequiredGas(nil); g != plonkGas {
		t.Fatalf("expected %d gas, got %d", plonkGas, g)
	}
}

// buildPLONKInput serialises [vk_len(4)][vk][proof_len(4)][proof][num_inputs(4)][inputs]
// in the wire format the PLONKVerifier precompile expects.
func buildPLONKInput(vk, proof []byte, numInputs uint32, inputs []byte) []byte {
	out := make([]byte, 0, 4+len(vk)+4+len(proof)+4+len(inputs))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(vk)))
	out = append(out, l[:]...)
	out = append(out, vk...)
	binary.BigEndian.PutUint32(l[:], uint32(len(proof)))
	out = append(out, l[:]...)
	out = append(out, proof...)
	binary.BigEndian.PutUint32(l[:], numInputs)
	out = append(out, l[:]...)
	out = append(out, inputs...)
	return out
}

// TestPLONKVerifierNeverUniversalAccepts is the H4 regression test. The
// previous verifyPLONK computed a self-cancelling pairing, discarded the
// result, ignored the public inputs, and returned VALID (0x01) for ANY
// >=544-byte blob. We construct a well-formed-but-arbitrary proof+VK
// (7 valid G1 commitments + 3 scalars + a valid SRS G2) — exactly the
// shape the old bypass rubber-stamped — and assert the precompile does
// NOT return 0x01. It must fail closed (0x00).
func TestPLONKVerifierNeverUniversalAccepts(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()

	// Proof: 7 G1 commitments (use the generator — a valid prime-order
	// point) + 3 scalar evals (32 bytes each) = 448 + 96 = 544 bytes.
	g1m := g1.Marshal() // 64 bytes uncompressed
	proof := make([]byte, 0, 544)
	for i := 0; i < 7; i++ {
		proof = append(proof, g1m...)
	}
	proof = append(proof, make([]byte, 96)...) // 3 zero scalars

	// VK: SRS G2 = generator (valid prime-order G2 point), 128 bytes.
	vk := g2.Marshal()

	input := buildPLONKInput(vk, proof, 1, make([]byte, 32))

	v := &PLONKVerifier{}
	res, err := v.Run(input)
	// The precompile treats an invalid proof as 0x00 with nil error
	// (invalid proof is not an execution error). The load-bearing
	// assertion: it must NOT be 0x01 (valid).
	if err == nil && len(res) == 1 && res[0] == 0x01 {
		t.Fatal("PLONKVerifier UNIVERSAL-ACCEPTED an arbitrary well-formed proof (H4 bypass)")
	}
	if len(res) != 1 || res[0] != 0x00 {
		t.Fatalf("PLONKVerifier must fail closed (0x00) for an unverified proof, got res=%x err=%v", res, err)
	}
}

// TestVerifyPLONKFailsClosed asserts the internal verifyPLONK never
// returns nil (valid) — it either reports a structural error or
// errPLONKVerifierIncomplete, but NEVER accepts.
func TestVerifyPLONKFailsClosed(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	g1m := g1.Marshal()
	proof := make([]byte, 0, 544)
	for i := 0; i < 7; i++ {
		proof = append(proof, g1m...)
	}
	proof = append(proof, make([]byte, 96)...)
	vk := g2.Marshal()

	if err := verifyPLONK(vk, proof, make([]byte, 32)); err == nil {
		t.Fatal("verifyPLONK returned nil (valid) — must fail closed, never universal-accept")
	} else if !errors.Is(err, errPLONKVerifierIncomplete) {
		// A well-formed proof should reach the incomplete-verifier guard,
		// not bail early on a structural error.
		t.Fatalf("verifyPLONK: expected errPLONKVerifierIncomplete for a well-formed blob, got %v", err)
	}
}

// buildSTARKInput serialises [proof_len(4)][proof][pub_len(4)][pub] in
// the wire format the STARKVerifier precompile expects.
func buildSTARKInput(proof, pub []byte) []byte {
	out := make([]byte, 0, 4+len(proof)+4+len(pub))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(proof)))
	out = append(out, l[:]...)
	out = append(out, proof...)
	binary.BigEndian.PutUint32(l[:], uint32(len(pub)))
	out = append(out, l[:]...)
	out = append(out, pub...)
	return out
}

// TestSTARKVerifierFailsClosedWhenUnbound proves the Z-Chain STARK
// rollup verifier delegates to precompile/starkfri and FAILS CLOSED
// when no verifier binding is registered (the CGO_ENABLED=0 / no
// starkfri_p3q build). A structurally well-formed P3Q1 proof must NOT
// be accepted in the unbound configuration — there is no forgery
// oracle. This is the post-quantum-safe posture: absent the FRI
// verifier, the precompile refuses rather than rubber-stamps.
func TestSTARKVerifierFailsClosedWhenUnbound(t *testing.T) {
	starkfri.RegisterVerifier(nil) // ensure no binding
	v := &STARKVerifier{}

	proof := append([]byte(starkfri.MagicHeader), []byte("strict-PQ-FRI-Goldilocks-payload")...)
	pub := []byte{0x01, 0x02, 0x03, 0x04}
	res, err := v.Run(buildSTARKInput(proof, pub))

	if !errors.Is(err, errVerifierUnavailable) {
		t.Fatalf("expected errVerifierUnavailable (fail-closed), got: %v", err)
	}
	if len(res) != 1 || res[0] != 0x00 {
		t.Fatalf("unbound STARK verifier must return 0x00 (invalid), got: %x", res)
	}
}

// TestSTARKVerifierDelegatesToStarkFRI proves the verifier-side switch:
// the Z-Chain rollup STARK path routes through starkfri.Verify (NOT the
// pairing-based Groth16 path). We register a fake FRI verifier and
// assert (a) it is invoked with the proof/pub bytes the precompile
// parsed, (b) an accept yields 0x01, (c) a reject yields 0x00, and
// (d) a proof without the "P3Q1" magic is rejected by starkfri's
// structural pre-filter BEFORE the verifier callback runs.
func TestSTARKVerifierDelegatesToStarkFRI(t *testing.T) {
	defer starkfri.RegisterVerifier(nil)
	v := &STARKVerifier{}

	proof := append([]byte(starkfri.MagicHeader), []byte("trace-root|fri-root|queries")...)
	pub := []byte{0xaa, 0xbb, 0xcc}

	// (a)+(b): accept path, capture what starkfri.Verify received.
	var sawProof, sawPub []byte
	starkfri.RegisterVerifier(func(_ byte, p, pi []byte) (bool, error) {
		sawProof = append([]byte(nil), p...)
		sawPub = append([]byte(nil), pi...)
		return true, nil
	})
	res, err := v.Run(buildSTARKInput(proof, pub))
	if err != nil {
		t.Fatalf("accept path returned error: %v", err)
	}
	if len(res) != 1 || res[0] != 0x01 {
		t.Fatalf("accept path must return 0x01 (valid), got: %x", res)
	}
	if string(sawProof) != string(proof) {
		t.Fatalf("starkfri verifier saw wrong proof bytes: %x != %x", sawProof, proof)
	}
	if string(sawPub) != string(pub) {
		t.Fatalf("starkfri verifier saw wrong public-input bytes: %x != %x", sawPub, pub)
	}

	// (c): reject path.
	starkfri.RegisterVerifier(func(byte, []byte, []byte) (bool, error) { return false, nil })
	res, err = v.Run(buildSTARKInput(proof, pub))
	if err != nil {
		t.Fatalf("reject path must not surface an execution error, got: %v", err)
	}
	if len(res) != 1 || res[0] != 0x00 {
		t.Fatalf("reject path must return 0x00 (invalid), got: %x", res)
	}

	// (d): bad-magic proof is rejected by starkfri's structural filter
	// before the callback runs (the callback would say true otherwise).
	called := false
	starkfri.RegisterVerifier(func(byte, []byte, []byte) (bool, error) { called = true; return true, nil })
	badProof := append([]byte("BAD!"), []byte("not-a-p3q1-proof")...)
	res, _ = v.Run(buildSTARKInput(badProof, pub))
	if len(res) != 1 || res[0] != 0x00 {
		t.Fatalf("bad-magic proof must return 0x00 (invalid), got: %x", res)
	}
	if called {
		t.Fatal("starkfri callback must not run on a proof missing the P3Q1 magic header")
	}
}

func TestHalo2VerifierNotImplemented(t *testing.T) {
	v := &Halo2Verifier{}
	_, err := v.Run([]byte{0x00})
	if err != errNotImplemented {
		t.Fatalf("expected errNotImplemented, got: %v", err)
	}
}

func TestNovaVerifierNotImplemented(t *testing.T) {
	v := &NovaVerifier{}
	_, err := v.Run([]byte{0x00})
	if err != errNotImplemented {
		t.Fatalf("expected errNotImplemented, got: %v", err)
	}
}

// TestRegistryRegistersAll confirms a NON-strict chain registers every
// verifier, including the classical Groth16/PLONK kept as an optional
// building block.
func TestRegistryRegistersAll(t *testing.T) {
	reg := NewMapRegistry()
	RegisterZKPrecompiles(reg, false /* strictPQ */)

	addrs := []byte{
		Groth16VerifierAddr,
		PLONKVerifierAddr,
		STARKVerifierAddr,
		Halo2VerifierAddr,
		NovaVerifierAddr,
	}
	for _, addr := range addrs {
		if _, err := reg.Get(addr); err != nil {
			t.Fatalf("precompile 0x%02x not registered: %v", addr, err)
		}
	}

	// Non-existent address
	if _, err := reg.Get(0xFF); err == nil {
		t.Fatal("expected error for unregistered address")
	}
}

// TestRegistryStrictPQOmitsClassical is the H2 gating test: on a strict-PQ
// chain the classical Groth16 (0x80) and PLONK (0x81) verifiers are NOT
// registered (calls fail closed by absence), while the post-quantum STARK
// (0x82) verifier and the always-fail-closed Halo2/Nova stubs ARE.
func TestRegistryStrictPQOmitsClassical(t *testing.T) {
	reg := NewMapRegistry()
	RegisterZKPrecompiles(reg, true /* strictPQ */)

	// Classical verifiers MUST be absent on a strict-PQ chain.
	for _, addr := range []byte{Groth16VerifierAddr, PLONKVerifierAddr} {
		if _, err := reg.Get(addr); err == nil {
			t.Fatalf("classical precompile 0x%02x MUST NOT be registered on a strict-PQ chain", addr)
		}
	}

	// Post-quantum STARK and the fail-closed stubs MUST be present.
	for _, addr := range []byte{STARKVerifierAddr, Halo2VerifierAddr, NovaVerifierAddr} {
		if _, err := reg.Get(addr); err != nil {
			t.Fatalf("precompile 0x%02x must be registered on a strict-PQ chain: %v", addr, err)
		}
	}
}

// TestCrossChainVerifierStrictPQRefusesClassical is the H2 cross-chain
// gating test: a strict-PQ router refuses to route Groth16/PLONK proofs
// to Z-Chain, but still routes the quantum-safe STARK path.
func TestCrossChainVerifierStrictPQRefusesClassical(t *testing.T) {
	v := &CrossChainZKVerifier{ZChainID: ids.ID{}, StrictPQ: true}

	for _, vtype := range []byte{VerifierTypeGroth16, VerifierTypePLONK} {
		res, err := v.Run([]byte{vtype, 0x00, 0x01, 0x02})
		if !errors.Is(err, errClassicalForbiddenStrictPQ) {
			t.Fatalf("type 0x%02x: expected errClassicalForbiddenStrictPQ, got %v", vtype, err)
		}
		if len(res) != 1 || res[0] != 0x00 {
			t.Fatalf("type 0x%02x: expected 0x00 result, got %x", vtype, res)
		}
	}

	// STARK still routes under strict-PQ.
	msg, err := v.Run(append([]byte{VerifierTypeSTARK}, []byte("p3q-proof")...))
	if err != nil {
		t.Fatalf("strict-PQ router must still route STARK, got: %v", err)
	}
	if _, gotAddr, _, derr := DecodeWarpPayload(msg); derr != nil || gotAddr != STARKVerifierAddr {
		t.Fatalf("strict-PQ STARK route: addr=0x%02x err=%v", gotAddr, derr)
	}
}

func TestCrossChainVerifierGas(t *testing.T) {
	v := &CrossChainZKVerifier{ZChainID: ids.ID{}}

	tests := []struct {
		input    []byte
		expected uint64
	}{
		{nil, 100_000},
		{[]byte{VerifierTypeGroth16}, 100_000 + groth16Gas},
		{[]byte{VerifierTypePLONK}, 100_000 + plonkGas},
		{[]byte{VerifierTypeSTARK}, 100_000 + starkGas},
		{[]byte{VerifierTypeHalo2}, 100_000 + halo2Gas},
		{[]byte{VerifierTypeNova}, 100_000 + novaGas},
		{[]byte{0xFF}, 100_000}, // unknown type
	}
	for _, tt := range tests {
		if g := v.RequiredGas(tt.input); g != tt.expected {
			t.Errorf("input=%x: expected %d gas, got %d", tt.input, tt.expected, g)
		}
	}
}

func TestCrossChainWarpPayloadRoundtrip(t *testing.T) {
	var zID ids.ID
	rand.Read(zID[:])

	payload := []byte("test proof data")
	encoded := encodeWarpPayload(zID, Groth16VerifierAddr, payload)

	gotID, gotAddr, gotPayload, err := DecodeWarpPayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != zID {
		t.Fatal("chain ID mismatch")
	}
	if gotAddr != Groth16VerifierAddr {
		t.Fatalf("addr mismatch: got 0x%02x", gotAddr)
	}
	if string(gotPayload) != string(payload) {
		t.Fatal("payload mismatch")
	}
}

func TestCrossChainVerifierRejectsTooShort(t *testing.T) {
	v := &CrossChainZKVerifier{ZChainID: ids.ID{}}
	result, err := v.Run([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if result[0] != 0x00 {
		t.Fatal("expected 0x00 result")
	}
}

func TestCrossChainVerifierRejectsStubs(t *testing.T) {
	v := &CrossChainZKVerifier{ZChainID: ids.ID{}}
	// STARK is no longer a stub — it routes to the strict-PQ STARK
	// verifier on Z-Chain. Only Halo2/Nova remain unimplemented.
	for _, vtype := range []byte{VerifierTypeHalo2, VerifierTypeNova} {
		result, err := v.Run([]byte{vtype, 0x00})
		if err != errNotImplemented {
			t.Fatalf("type 0x%02x: expected errNotImplemented, got %v", vtype, err)
		}
		if result[0] != 0x00 {
			t.Fatalf("type 0x%02x: expected 0x00 result", vtype)
		}
	}
}

// TestCrossChainVerifierRoutesSTARK proves the cross-chain router now
// forwards strict-PQ STARK rollup proofs to the Z-Chain STARKVerifier
// (target address STARKVerifierAddr), instead of rejecting them as
// not-implemented. The quantum-safe rollup path is reachable from any
// EVM chain via Warp.
func TestCrossChainVerifierRoutesSTARK(t *testing.T) {
	var zID ids.ID
	rand.Read(zID[:])
	v := &CrossChainZKVerifier{ZChainID: zID}

	proofData := []byte("p3q-stark-proof-bytes")
	msg, err := v.Run(append([]byte{VerifierTypeSTARK}, proofData...))
	if err != nil {
		t.Fatalf("STARK routing returned error: %v", err)
	}
	_, gotAddr, gotPayload, err := DecodeWarpPayload(msg)
	if err != nil {
		t.Fatalf("decode warp payload: %v", err)
	}
	if gotAddr != STARKVerifierAddr {
		t.Fatalf("STARK must route to STARKVerifierAddr 0x%02x, got 0x%02x", STARKVerifierAddr, gotAddr)
	}
	if string(gotPayload) != string(proofData) {
		t.Fatalf("STARK routed payload mismatch: %x != %x", gotPayload, proofData)
	}
}

// --- helpers ---

func serializeGroth16Input(vk *groth16VK, proof *groth16Proof, witness []fr.Element) []byte {
	// Serialize VK
	vkBuf := make([]byte, 0, 64+128+128+128+4+len(vk.K)*64)
	vkBuf = append(vkBuf, vk.Alpha.Marshal()...)
	vkBuf = append(vkBuf, vk.Beta.Marshal()...)
	vkBuf = append(vkBuf, vk.Gamma.Marshal()...)
	vkBuf = append(vkBuf, vk.Delta.Marshal()...)
	numK := make([]byte, 4)
	binary.BigEndian.PutUint32(numK, uint32(len(vk.K)))
	vkBuf = append(vkBuf, numK...)
	for i := range vk.K {
		vkBuf = append(vkBuf, vk.K[i].Marshal()...)
	}

	// Build input
	buf := make([]byte, 0, 4+len(vkBuf)+256+4+len(witness)*32)
	vkLen := make([]byte, 4)
	binary.BigEndian.PutUint32(vkLen, uint32(len(vkBuf)))
	buf = append(buf, vkLen...)
	buf = append(buf, vkBuf...)
	buf = append(buf, proof.Ar.Marshal()...)
	buf = append(buf, proof.Bs.Marshal()...)
	buf = append(buf, proof.Krs.Marshal()...)
	numInputs := make([]byte, 4)
	binary.BigEndian.PutUint32(numInputs, uint32(len(witness)))
	buf = append(buf, numInputs...)
	for _, w := range witness {
		b := w.Bytes()
		buf = append(buf, b[:]...)
	}
	return buf
}
