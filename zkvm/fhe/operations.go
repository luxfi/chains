// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"errors"
	"fmt"

	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/schemes/ckks"
)

// neg negates a ciphertext by negating its polynomial coefficients
func (p *Processor) neg(in, out *rlwe.Ciphertext) error {
	if in == nil || out == nil {
		return errors.New("nil ciphertext")
	}
	ringQ := p.params.RingQ()
	for i := range in.Value {
		if i < len(out.Value) {
			ringQ.Neg(in.Value[i], out.Value[i])
		}
	}
	out.MetaData = in.MetaData.CopyNew()
	return nil
}

// negRLWE negates an rlwe.Ciphertext directly
func (p *Processor) negRLWE(in, out *rlwe.Ciphertext) error {
	return p.neg(in, out)
}

// FHE Operations - Lux fhEVM interface

// Add performs homomorphic addition: result = a + b
func (p *Processor) Add(a, b *Ciphertext) (*Ciphertext, error) {
	if err := p.checkOperands(a, b); err != nil {
		return nil, err
	}

	result := p.allocateResult(a, b)

	if err := p.evaluator.Add(a.Ct, b.Ct, result.Ct); err != nil {
		return nil, fmt.Errorf("add failed: %w", err)
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// AddPlain performs homomorphic addition with plaintext: result = a + scalar
func (p *Processor) AddPlain(a *Ciphertext, scalar uint64) (*Ciphertext, error) {
	if a == nil || a.Ct == nil {
		return nil, errors.New("nil ciphertext")
	}

	result := p.allocateSingleResult(a)

	if err := p.evaluator.Add(a.Ct, float64(scalar), result.Ct); err != nil {
		return nil, fmt.Errorf("add plain failed: %w", err)
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// Sub performs homomorphic subtraction: result = a - b
func (p *Processor) Sub(a, b *Ciphertext) (*Ciphertext, error) {
	if err := p.checkOperands(a, b); err != nil {
		return nil, err
	}

	result := p.allocateResult(a, b)

	if err := p.evaluator.Sub(a.Ct, b.Ct, result.Ct); err != nil {
		return nil, fmt.Errorf("sub failed: %w", err)
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// Mul performs homomorphic multiplication: result = a * b
// Note: Consumes one multiplicative level
func (p *Processor) Mul(a, b *Ciphertext) (*Ciphertext, error) {
	if err := p.checkOperands(a, b); err != nil {
		return nil, err
	}

	// Check if we have enough levels for multiplication
	minLevel := min(a.Ct.Level(), b.Ct.Level())
	if minLevel < 1 {
		return nil, errors.New("insufficient levels for multiplication - refresh needed")
	}

	result := p.allocateResult(a, b)

	// Multiply
	if err := p.evaluator.MulRelin(a.Ct, b.Ct, result.Ct); err != nil {
		return nil, fmt.Errorf("mul failed: %w", err)
	}

	// Rescale to manage noise
	if err := p.evaluator.Rescale(result.Ct, result.Ct); err != nil {
		return nil, fmt.Errorf("rescale failed: %w", err)
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// MulPlain performs homomorphic multiplication with plaintext: result = a * scalar
func (p *Processor) MulPlain(a *Ciphertext, scalar uint64) (*Ciphertext, error) {
	if a == nil || a.Ct == nil {
		return nil, errors.New("nil ciphertext")
	}

	result := p.allocateSingleResult(a)

	if err := p.evaluator.Mul(a.Ct, float64(scalar), result.Ct); err != nil {
		return nil, fmt.Errorf("mul plain failed: %w", err)
	}

	if err := p.evaluator.Rescale(result.Ct, result.Ct); err != nil {
		return nil, fmt.Errorf("rescale failed: %w", err)
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// Neg performs homomorphic negation: result = -a
func (p *Processor) Neg(a *Ciphertext) (*Ciphertext, error) {
	if a == nil || a.Ct == nil {
		return nil, errors.New("nil ciphertext")
	}

	result := p.allocateSingleResult(a)

	if err := p.neg(a.Ct, result.Ct); err != nil {
		return nil, fmt.Errorf("neg failed: %w", err)
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// Comparison Operations

// Lt performs homomorphic less-than: result = (a < b) ? 1 : 0
func (p *Processor) Lt(a, b *Ciphertext) (*Ciphertext, error) {
	if err := p.checkOperands(a, b); err != nil {
		return nil, err
	}

	if p.comparator == nil {
		return nil, errors.New("comparison evaluator not initialized")
	}

	// Compute a - b
	diff := ckks.NewCiphertext(p.params, 1, min(a.Ct.Level(), b.Ct.Level()))
	if err := p.evaluator.Sub(a.Ct, b.Ct, diff); err != nil {
		return nil, fmt.Errorf("sub for lt failed: %w", err)
	}

	// Apply sign function: sign(a-b) gives -1 if a<b, 0 if a=b, 1 if a>b
	signResult, err := p.comparator.Sign(diff)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}

	// Convert sign to lt: lt = (1 - sign) / 2
	// If sign = -1 (a < b): lt = (1 - (-1)) / 2 = 1
	// If sign = 0 (a = b): lt = (1 - 0) / 2 = 0.5 -> rounds to 0
	// If sign = 1 (a > b): lt = (1 - 1) / 2 = 0
	result := ckks.NewCiphertext(p.params, 1, signResult.Level())

	// 1 - sign
	if err := p.negRLWE(signResult, result); err != nil {
		return nil, err
	}
	if err := p.evaluator.Add(result, 1.0, result); err != nil {
		return nil, err
	}
	// / 2
	if err := p.evaluator.Mul(result, 0.5, result); err != nil {
		return nil, err
	}

	handle := p.generateHandle(result)
	ct := NewCiphertext(EBool, result, handle)
	p.StoreCiphertext(ct)
	p.incrementOpCount()

	return ct, nil
}

// Gt performs homomorphic greater-than: result = (a > b) ? 1 : 0
func (p *Processor) Gt(a, b *Ciphertext) (*Ciphertext, error) {
	// a > b is equivalent to b < a
	return p.Lt(b, a)
}

// Lte performs homomorphic less-than-or-equal: result = (a <= b) ? 1 : 0
func (p *Processor) Lte(a, b *Ciphertext) (*Ciphertext, error) {
	// a <= b is equivalent to NOT(a > b)
	gt, err := p.Gt(a, b)
	if err != nil {
		return nil, err
	}
	return p.Not(gt)
}

// Gte performs homomorphic greater-than-or-equal: result = (a >= b) ? 1 : 0
func (p *Processor) Gte(a, b *Ciphertext) (*Ciphertext, error) {
	// a >= b is equivalent to NOT(a < b)
	lt, err := p.Lt(a, b)
	if err != nil {
		return nil, err
	}
	return p.Not(lt)
}

// Eq performs homomorphic equality: result = (a == b) ? 1 : 0
func (p *Processor) Eq(a, b *Ciphertext) (*Ciphertext, error) {
	if err := p.checkOperands(a, b); err != nil {
		return nil, err
	}

	// For equality, we need |a - b| < epsilon
	// This is more complex with CKKS due to approximate arithmetic
	// We use: eq = 1 - sign(|a-b| - epsilon) where epsilon is small

	diff := ckks.NewCiphertext(p.params, 1, min(a.Ct.Level(), b.Ct.Level()))
	if err := p.evaluator.Sub(a.Ct, b.Ct, diff); err != nil {
		return nil, err
	}

	// Square to get |diff|^2 (approximate absolute value)
	if err := p.evaluator.MulRelin(diff, diff, diff); err != nil {
		return nil, err
	}
	if err := p.evaluator.Rescale(diff, diff); err != nil {
		return nil, err
	}

	// Apply sign function with offset
	// If diff^2 is very small (values equal), sign gives ~0
	// Otherwise sign gives 1
	signResult, err := p.comparator.Sign(diff)
	if err != nil {
		return nil, fmt.Errorf("sign for eq failed: %w", err)
	}

	// eq = 1 - |sign|
	result := ckks.NewCiphertext(p.params, 1, signResult.Level())
	if err := p.negRLWE(signResult, result); err != nil {
		return nil, err
	}
	if err := p.evaluator.Add(result, 1.0, result); err != nil {
		return nil, err
	}

	handle := p.generateHandle(result)
	ct := NewCiphertext(EBool, result, handle)
	p.StoreCiphertext(ct)
	p.incrementOpCount()

	return ct, nil
}

// Ne performs homomorphic not-equal: result = (a != b) ? 1 : 0
func (p *Processor) Ne(a, b *Ciphertext) (*Ciphertext, error) {
	eq, err := p.Eq(a, b)
	if err != nil {
		return nil, err
	}
	return p.Not(eq)
}

// Boolean Operations

// Not performs homomorphic NOT: result = 1 - a (for boolean)
func (p *Processor) Not(a *Ciphertext) (*Ciphertext, error) {
	if a == nil || a.Ct == nil {
		return nil, errors.New("nil ciphertext")
	}

	result := p.allocateSingleResult(a)
	result.Type = EBool

	// NOT = 1 - a
	if err := p.negRLWE(a.Ct, result.Ct); err != nil {
		return nil, err
	}
	if err := p.evaluator.Add(result.Ct, 1.0, result.Ct); err != nil {
		return nil, err
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// And performs homomorphic AND: result = a * b (for boolean)
func (p *Processor) And(a, b *Ciphertext) (*Ciphertext, error) {
	return p.Mul(a, b)
}

// Or performs homomorphic OR: result = a + b - a*b (for boolean)
func (p *Processor) Or(a, b *Ciphertext) (*Ciphertext, error) {
	if err := p.checkOperands(a, b); err != nil {
		return nil, err
	}

	// OR = a + b - a*b
	sum, err := p.Add(a, b)
	if err != nil {
		return nil, err
	}

	prod, err := p.Mul(a, b)
	if err != nil {
		return nil, err
	}

	result, err := p.Sub(sum, prod)
	if err != nil {
		return nil, err
	}

	result.Type = EBool
	return result, nil
}

// Xor performs homomorphic XOR: result = a + b - 2*a*b (for boolean)
func (p *Processor) Xor(a, b *Ciphertext) (*Ciphertext, error) {
	if err := p.checkOperands(a, b); err != nil {
		return nil, err
	}

	// XOR = a + b - 2*a*b
	sum, err := p.Add(a, b)
	if err != nil {
		return nil, err
	}

	prod, err := p.Mul(a, b)
	if err != nil {
		return nil, err
	}

	twoProd, err := p.MulPlain(prod, 2)
	if err != nil {
		return nil, err
	}

	result, err := p.Sub(sum, twoProd)
	if err != nil {
		return nil, err
	}

	result.Type = EBool
	return result, nil
}

// Conditional Operations

// Select performs conditional selection: result = condition ? ifTrue : ifFalse
// This is the key operation for private DeFi (e.g., "if balance >= amount then transfer")
func (p *Processor) Select(condition, ifTrue, ifFalse *Ciphertext) (*Ciphertext, error) {
	if condition == nil || ifTrue == nil || ifFalse == nil {
		return nil, errors.New("nil operand")
	}

	// SELECT = condition * ifTrue + (1 - condition) * ifFalse
	// This reveals nothing about which branch was taken

	// condition * ifTrue
	branch1, err := p.Mul(condition, ifTrue)
	if err != nil {
		return nil, fmt.Errorf("select branch1 failed: %w", err)
	}

	// (1 - condition)
	notCond, err := p.Not(condition)
	if err != nil {
		return nil, fmt.Errorf("select not failed: %w", err)
	}

	// (1 - condition) * ifFalse
	branch2, err := p.Mul(notCond, ifFalse)
	if err != nil {
		return nil, fmt.Errorf("select branch2 failed: %w", err)
	}

	// condition * ifTrue + (1 - condition) * ifFalse
	result, err := p.Add(branch1, branch2)
	if err != nil {
		return nil, fmt.Errorf("select add failed: %w", err)
	}

	result.Type = ifTrue.Type
	return result, nil
}

// Min returns the minimum of two encrypted values
func (p *Processor) Min(a, b *Ciphertext) (*Ciphertext, error) {
	// min(a, b) = select(a < b, a, b)
	lt, err := p.Lt(a, b)
	if err != nil {
		return nil, err
	}
	return p.Select(lt, a, b)
}

// Max returns the maximum of two encrypted values
func (p *Processor) Max(a, b *Ciphertext) (*Ciphertext, error) {
	// max(a, b) = select(a > b, a, b)
	gt, err := p.Gt(a, b)
	if err != nil {
		return nil, err
	}
	return p.Select(gt, a, b)
}

// Bitwise Operations (for integer types)

// Shl performs left shift by a constant: result = a << bits
func (p *Processor) Shl(a *Ciphertext, bits uint) (*Ciphertext, error) {
	// Left shift by n is multiplication by 2^n
	return p.MulPlain(a, 1<<bits)
}

// Shr performs right shift by a constant: result = a >> bits
// Note: This is approximate due to CKKS arithmetic
func (p *Processor) Shr(a *Ciphertext, bits uint) (*Ciphertext, error) {
	if a == nil || a.Ct == nil {
		return nil, errors.New("nil ciphertext")
	}

	result := p.allocateSingleResult(a)

	// Right shift by n is division by 2^n (multiplication by 2^-n)
	scalar := 1.0 / float64(uint64(1)<<bits)
	if err := p.evaluator.Mul(a.Ct, scalar, result.Ct); err != nil {
		return nil, fmt.Errorf("shr failed: %w", err)
	}

	p.StoreCiphertext(result)
	p.incrementOpCount()
	return result, nil
}

// Helper functions

func (p *Processor) checkOperands(a, b *Ciphertext) error {
	if a == nil || a.Ct == nil {
		return errors.New("first operand is nil")
	}
	if b == nil || b.Ct == nil {
		return errors.New("second operand is nil")
	}
	return nil
}

func (p *Processor) allocateResult(a, b *Ciphertext) *Ciphertext {
	level := min(a.Ct.Level(), b.Ct.Level())
	ct := rlwe.NewCiphertext(p.params.Parameters, 1, level)
	handle := p.generateHandle(ct)

	// Result type is the larger of the two input types
	resultType := a.Type
	if b.Type > a.Type {
		resultType = b.Type
	}

	return NewCiphertext(resultType, ct, handle)
}

func (p *Processor) allocateSingleResult(a *Ciphertext) *Ciphertext {
	ct := rlwe.NewCiphertext(p.params.Parameters, 1, a.Ct.Level())
	handle := p.generateHandle(ct)
	return NewCiphertext(a.Type, ct, handle)
}
