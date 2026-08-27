// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// run.go is what an operator produces by running a workload: what came out, what
// it cost, and the evidence for how it ran.
//
// The claim and the evidence are kept apart on purpose. A claim is a statement
// about the run — this workload, this operator, this output, this consumption —
// and it exists before any evidence does, which is what lets a hardware quote be
// requested for it: the quote's report-data field carries the claim, so the
// hardware attests a specific run rather than a general willingness to attest.
// The evidence is then bound to the claim by the operator's signature over both.
// Neither can be moved onto the other's counterpart afterwards.
//
// A Receipt is checked, never trusted: Check refuses a run that produced nothing,
// a run that consumed more than it was allowed, and a run whose evidence does not
// establish every property its workload demanded.

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Receipt is one operator's run of one workload.
type Receipt struct {
	Workload common.Hash    `json:"workload"`
	Operator common.Address `json:"operator"`
	Output   Handle         `json:"output"`
	Exit     uint32         `json:"exit"`
	Consumed Resource       `json:"consumed"`
	Evidence Evidence       `json:"evidence"`
}

// Claim is the statement the run makes about itself, independent of how it is
// evidenced. It is what a hardware quote is bound to and what the operator's
// signature covers, so it is fixed before either exists.
func (r Receipt) Claim() common.Hash {
	buf := make([]byte, 0, len(DomainRun)+32+20+32+4+resourceLen)
	buf = append(buf, []byte(DomainRun)...)
	buf = append(buf, r.Workload.Bytes()...)
	buf = append(buf, r.Operator.Bytes()...)
	buf = append(buf, r.Output.ID().Bytes()...)
	buf = append(buf, u32be(r.Exit)...)
	buf = append(buf, r.Consumed.encode()...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

// Hash identifies the attested artifact: the claim, every evidence fact, and the
// signature over them. Two receipts differing in any of those are different
// receipts.
func (r Receipt) Hash() common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		[]byte(DomainRun), r.Claim().Bytes(), r.Evidence.facts(r.Output), r.Evidence.Signature,
	))
}

// Check refuses the receipt unless it is a complete account of a run that stayed
// within its ask and proved everything the demand required. It is the whole gate:
// a receipt that does not pass here never becomes a reveal, so it never reaches
// the tally and can never settle.
func (r Receipt) Check(w Workload, demand Properties, trust Trust) error {
	if r.Workload != w.ID() {
		return ErrReceiptWorkload
	}
	if err := r.Output.Validate(); err != nil {
		return ErrReceiptOutput
	}
	if !r.Consumed.Within(w.Resource) {
		return ErrReceiptResource
	}
	return r.Evidence.Proves(demand, r.Claim(), r.Output, r.Operator, trust)
}
