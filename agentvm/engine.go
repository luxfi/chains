// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package agentvm is hanzo.network's VM for attested agentic compute. It is built
// ON A-Chain rather than out of it: A-Chain (luxfi/chains/aivm) is the general
// attested-compute base — bonded providers, reproducible selection, commit and
// reveal, quorum, slashing, settlement, receipts — and AgentVM adds the layer that
// says what was run, how it was isolated, where its bytes went, and which
// capability it served.
//
// Nothing about the economic loop is rebuilt here. A workload names how many
// operators must run it; A-Chain draws them, compares what they reveal, pays the
// ones that agreed and slashes the ones that withheld. There is exactly one
// payout path in this system and it is aivm.Settle. This package expresses the
// demand and hands it over.
//
// Three things AgentVM adds and A-Chain does not have:
//
//	the demand      what isolation and durability the work requires, as a set of
//	                atomic properties rather than a level
//	the evidence    what a run must show to have met each one, checked before its
//	                answer is allowed to count
//	the capability  which slice of an API surface the work needs, and which
//	                operators serve it
//
// The evidence check happens at reveal, not at settlement, and it is
// unconditional: no operator answers a task without first attesting the answer,
// whatever the workload asked for. So a receipt failing its evidence never
// becomes a reveal, never reaches the tally, and can never settle. That is why
// "settlement refuses weak evidence" is structural here rather than a check
// somebody has to remember to run.
//
// AgentVM drives A-Chain's engine over AgentVM's OWN state and ledger. No A-Chain
// node serves those slots, so the two chains share code and share no state, and
// an operator cannot reach A-Chain's reveal path to get around this one.
package agentvm

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/aivm"
)

// Engine is AgentVM's handle. It holds A-Chain's engine privately rather than
// embedding it: embedding would promote RevealResponse onto this type and give an
// operator a way to answer a task without showing evidence. Everything A-Chain
// does is reached through a method here that knows what AgentVM requires first.
type Engine struct {
	core *aivm.Engine
}

// New builds an AgentVM engine over A-Chain's, bound to the same chain ids the
// underlying engine carries.
func New(core *aivm.Engine) *Engine { return &Engine{core: core} }

// Core exposes the underlying A-Chain engine for the reads that belong to it —
// operator registry, credit, canonical results, receipts. It deliberately does
// not hide them: they are A-Chain's answers about A-Chain's state, and
// duplicating them here would create a second version of the truth.
func (e *Engine) Core() *aivm.Engine { return e.core }

// trust reads what this chain has admitted: hardware whose quotes are believed,
// and S-Chain roots that pins may name.
type trust struct{ st State }

func (t trust) Attests(keyDigest common.Hash) bool {
	return isSet(t.st.GetState(slotHash(nsAttestKey, keyDigest)))
}

func (t trust) Pins(root common.Hash) bool {
	return isSet(t.st.GetState(slotHash(nsStateRoot, root)))
}

// Trust returns what this chain believes as of this state. On a fresh chain it
// believes nothing, so hardware attestation and pinned durability are both
// refused until something is admitted. That is the intended starting position.
func (e *Engine) Trust(st State) Trust { return trust{st: st} }

// Open creates a task from an authorised workload and returns its id. Called
// UNDER CONSENSUS (from the block build and verify paths), it validates the
// workload, checks the capability against a registered catalog, guards against
// replay, prices the run, builds the one-per-domain pool, and hands the whole
// thing to A-Chain's task-opening path.
//
// Order is fail-closed: every check that can refuse runs before any state or
// money is touched, so a rejected workload leaves the chain untouched.
//
// The pool handed over has one operator per declared failure domain, so A-Chain's
// eligible-set margin — the check that the pool must exceed the draw by
// requiredMargin(N), enforced before any money moves — applies to DOMAINS here.
// That is stricter than the guard it rides on. Nothing weakens it: there is no
// bootstrap path, no development mode and no configurable floor, so a network
// that cannot field enough independent domains does not open the task.
func (e *Engine) Open(st State, lg Ledger, w Workload, height uint64) (common.Hash, error) {
	// (1) The workload must be well formed and signed by the payer whose balance
	// it will spend. Validate ends in that signature check.
	if err := w.Validate(); err != nil {
		return common.Hash{}, err
	}

	// (2) The capability must exist: a registered catalog version that holds the
	// group. A workload naming a surface the chain has never seen has no meaning
	// to agree on.
	if !e.CatalogKnown(st, w.Capability.Catalog) {
		return common.Hash{}, ErrCatalogUnknown
	}
	if !e.CatalogHolds(st, w.Capability.Catalog, w.Capability.Group) {
		return common.Hash{}, ErrCapabilityUnknown
	}

	// (anti-replay) one workload opens one task. The id is over the content, so
	// asking for the same work again needs a different nonce and is a different
	// workload.
	seen := slotHash(nsWorkloadSeen, w.ID())
	if isSet(st.GetState(seen)) {
		return common.Hash{}, ErrWorkloadAlreadyUsed
	}

	// (3) Price is a pure function of the workload, so nobody names a number and
	// every validator computes the same reward.
	reward, err := Price(w)
	if err != nil {
		return common.Hash{}, err
	}
	fee := new(uint256.Int)
	if _, over := fee.MulOverflow(aivm.RequestFeePerOperator, uint256.NewInt(uint64(w.Duplication))); over {
		return common.Hash{}, ErrPriceOverflow
	}

	// (4) The pool is one operator per domain, drawn from the operators that can
	// actually serve this demand at this capability with a slot free. There is no
	// relaxed second pass: an operator that cannot meet the demand is not in the
	// pool, and if that leaves too few domains the task does not open.
	pool := e.Pool(st, w)

	taskID, err := e.core.OpenTask(st, lg, aivm.TaskSpec{
		Requester: w.Payer,
		Code:      w.Code.Digest,
		// The workload id is what the operators are asked to answer about: a
		// digest over the input handle, the environment, the arguments and
		// everything else that changes what running this means, so the commit
		// preimage binds all of it.
		Input:      w.ID(),
		Candidates: pool,
		N:          w.Duplication,
		Threshold:  w.Threshold(),
		Fee:        fee,
		Reward:     reward,
	}, height)
	if err != nil {
		return common.Hash{}, err
	}

	st.SetState(seen, oneHash())
	st.SetState(slotHash(nsTaskWorkload, taskID), w.ID())
	st.SetState(slotHash(nsWorkloadTask, w.ID()), taskID)
	st.SetState(slotHash(nsTaskDemand, taskID), packDemand(w))

	// Take a slot from each selected operator and record that this task holds
	// them, so settlement gives back exactly what was taken.
	trackOpen(st, taskID)
	for i := uint32(0); i < w.Duplication; i++ {
		hold(st, e.core.SelectedAt(st, taskID, i))
	}
	return taskID, nil
}

// packDemand stores a task's demanded properties and placement in one word:
// demand in the low two bytes, placement in the next. A task opened here always
// records this, so the reveal path can ask what the task required without
// consulting anything outside its own state.
func packDemand(w Workload) common.Hash {
	var word [32]byte
	copy(word[30:32], u16be(uint16(w.Demand)))
	word[29] = byte(w.Placement)
	word[28] = 1 // present: a task with a zero demand is still an AgentVM task
	return common.BytesToHash(word[:])
}

// Demanded returns what a task required and whether it is an AgentVM task at all.
func (e *Engine) Demanded(st State, taskID common.Hash) (d Properties, p Placement, ok bool) {
	word := st.GetState(slotHash(nsTaskDemand, taskID)).Bytes()
	if word[28] == 0 {
		return 0, PlacementAny, false
	}
	return Properties(uint16(word[30])<<8 | uint16(word[31])), Placement(word[29]), true
}

// TaskFor returns the task a workload opened, or zero if it opened none.
func (e *Engine) TaskFor(st State, workloadID common.Hash) common.Hash {
	return st.GetState(slotHash(nsWorkloadTask, workloadID))
}

// WorkloadFor returns the workload a task was opened from, or zero for a task
// that did not come from one.
func (e *Engine) WorkloadFor(st State, taskID common.Hash) common.Hash {
	return st.GetState(slotHash(nsTaskWorkload, taskID))
}

// Commit records a selected operator's sealed answer within the commit window. It
// is A-Chain's commit unchanged; it lives here so an operator has one vocabulary
// to work in.
func (e *Engine) Commit(st State, taskID common.Hash, op common.Address, commit common.Hash, height uint64) error {
	return e.core.CommitResponse(st, taskID, op, commit, height)
}

// Attest records a selected operator's run of a task's workload. The receipt must
// be for this task's workload, must be the operator's own, and its evidence must
// establish every property the task demanded. Anything less is refused, and a
// refusal writes nothing.
//
// Attestation happens inside the reveal window. It has to: an attestation names
// the output, and naming it during the commit window would hand every peer the
// answer before their own commit was sealed.
//
// The evidence signature is required here whatever the demand says, because the
// chain is recording a statement and a statement needs an author. Without it an
// operator could present a peer's evidence as its own. A demand naming
// attest.software asks for the same fact from the requester's side.
func (e *Engine) Attest(st State, taskID common.Hash, op common.Address, w Workload, r Receipt, height uint64) error {
	demand, placement, ok := e.Demanded(st, taskID)
	if !ok {
		return ErrTaskNotAgentic
	}
	info := e.core.GetTask(st, taskID)
	if info.Status == aivm.TaskNone {
		return ErrTaskUnknown
	}
	if info.Status != aivm.TaskCommitting {
		return ErrTaskSettled
	}
	if height <= info.CommitDeadline {
		return ErrAttestNotOpen
	}
	if height > info.RevealDeadline {
		return ErrAttestClosed
	}
	if !e.core.IsSelected(st, taskID, op) {
		return ErrNotSelected
	}
	if e.WorkloadFor(st, taskID) != w.ID() {
		return ErrReceiptWorkload
	}
	if r.Operator != op {
		return ErrReceiptOperator
	}
	if isSet(st.GetState(slotHashAddr(nsAttestRcpt, taskID, op))) {
		return ErrAlreadyAttested
	}
	signer, err := r.Evidence.signer(r.Claim(), r.Output)
	if err != nil {
		return err
	}
	if signer != op {
		return ErrEvidenceSignature
	}
	// A workload that named a place is answered from that place. The evidence
	// declares where the run happened and the task recorded where it was asked
	// to happen, so comparing them costs nothing; discarding the value meant a
	// workload demanding a local run accepted evidence saying it ran remotely.
	if !placement.Admits(r.Evidence.Placement) {
		return ErrEvidencePlacement
	}
	if err := r.Check(w, demand, e.Trust(st)); err != nil {
		return err
	}

	st.SetState(slotHashAddr(nsAttestOut, taskID, op), r.Output.ID())
	st.SetState(slotHashAddr(nsAttestRcpt, taskID, op), r.Hash())
	return nil
}

// Attested returns the output handle id and receipt an operator attested for a
// task, or zeroes if it attested nothing.
func (e *Engine) Attested(st State, taskID common.Hash, op common.Address) (output, receipt common.Hash) {
	return st.GetState(slotHashAddr(nsAttestOut, taskID, op)),
		st.GetState(slotHashAddr(nsAttestRcpt, taskID, op))
}

// Reveal opens an operator's answer. The answer an AgentVM task agrees on is the
// output handle's id, and an operator may only reveal one it has attested: this
// is where evidence stops weak work, before it can become a reveal, reach the
// tally, or settle.
//
// aux is the second value the operator sealed into its commit alongside the
// answer. An operator running an agentic workload puts its receipt hash there, so
// the commit binds which run produced the answer as well as what the answer was.
func (e *Engine) Reveal(st State, taskID common.Hash, op common.Address, output Handle, aux, nonce common.Hash, height uint64) error {
	if _, _, ok := e.Demanded(st, taskID); !ok {
		return ErrTaskNotAgentic
	}
	answer := output.ID()
	// Unconditional. Guarding this on a non-empty demand made the safe path the
	// one a workload had to opt into: Properties is a bitset and Demand is a
	// struct field, so a workload that never mentions it holds the empty set,
	// and the empty set would have waived the check entirely. A workload that
	// genuinely requires nothing of a run says so with AttestNone, which is a
	// property and passes; it does not say so by omission.
	//
	// Attest requires a signature whatever the demand says, so requiring an
	// attestation here means every answer is attributable to the operator that
	// gave it, on every task, however little the workload asked for.
	if st.GetState(slotHashAddr(nsAttestOut, taskID, op)) != answer {
		return ErrEvidenceMissing
	}
	return e.core.RevealResponse(st, taskID, op, answer, aux, nonce, height)
}

// Commitment is the value an operator seals during the commit window: A-Chain's
// operator-bound commit over the answer this task agrees on. The operator address
// is inside it, so a commit observed on the wire cannot be replayed as somebody
// else's.
func (e *Engine) Commitment(st State, taskID common.Hash, op common.Address, output Handle, aux, nonce common.Hash) common.Hash {
	info := e.core.GetTask(st, taskID)
	return aivm.ComputeCommit(taskID, info.ModelSpecHash, info.PromptHash, output.ID(), aux, op, nonce)
}

// Settle gives verdicts to every task whose reveal window has closed, and gives
// back the slots those tasks held. The verdict itself is A-Chain's: it compares
// what the operators revealed, pays the ones that agreed, slashes the ones that
// committed and then withheld, and emits the receipt. There is no second payout
// path here and no second slashing rule.
//
// Slot release is AgentVM's own concern, so it is done here rather than inside
// A-Chain's settlement: A-Chain has no idea an operator advertised slots.
func (e *Engine) Settle(st State, lg Ledger, height uint64) uint32 {
	settled := e.core.SettleDue(st, lg, height)
	e.releaseSettled(st)
	return settled
}

// releaseSettled walks the tasks AgentVM opened and still holds slots for, and
// gives the slots back for any that has reached a verdict.
func (e *Engine) releaseSettled(st State) {
	for i := uint32(0); i < openCount(st); {
		taskID := openAt(st, i)
		info := e.core.GetTask(st, taskID)
		if info.Status == aivm.TaskCommitting {
			i++
			continue
		}
		for k := uint32(0); k < info.N; k++ {
			if op := e.core.SelectedAt(st, taskID, k); op != (common.Address{}) {
				release(st, op)
			}
		}
		dropOpen(st, i)
	}
}

// ---------------------------------------------------------------------------
// The open-task array: which tasks AgentVM opened and still holds slots for.
// ---------------------------------------------------------------------------

func openCount(st State) uint32 {
	return uint32(readUint(st, slotNS(nsTaskOpenLen)).Uint64())
}

func openAt(st State, i uint32) common.Hash {
	return st.GetState(slotNSIdx(nsTaskOpen, i))
}

func trackOpen(st State, taskID common.Hash) {
	n := openCount(st)
	st.SetState(slotNSIdx(nsTaskOpen, n), taskID)
	st.SetState(slotNS(nsTaskOpenLen), h32(uint256.NewInt(uint64(n)+1)))
}

// dropOpen removes the entry at i by moving the last entry into its place. The
// array's order is therefore not the order tasks arrived in, which costs nothing:
// every node performs the identical swap against identical state.
func dropOpen(st State, i uint32) {
	n := openCount(st)
	if n == 0 || i >= n {
		return
	}
	last := n - 1
	if i != last {
		st.SetState(slotNSIdx(nsTaskOpen, i), openAt(st, last))
	}
	st.SetState(slotNSIdx(nsTaskOpen, last), common.Hash{})
	st.SetState(slotNS(nsTaskOpenLen), h32(uint256.NewInt(uint64(last))))
}

// Pending reports how many tasks AgentVM has opened that still hold slots.
func (e *Engine) Pending(st State) uint32 { return openCount(st) }

// AdmitAttestingKey records that quotes signed by this key may be believed. The
// certificate chain proving the key belongs to genuine hardware is validated
// before admission; what the chain keeps is the resulting digest.
//
// CALLER CONTRACT. This is a governance operation and it carries no
// authorization of its own. Admitting one key is enough to satisfy every
// hardware-attestation demand on the chain, which is the only guarantee here
// that does not rest on an operator's bond, so a VM binding MUST reach it only
// from the consensus-gated block path and MUST NOT route any request surface to
// it. The same holds for AdmitStateRoot and for the revocations. This is the
// convention A-Chain already uses for SetCommitVerifier, and like that one it is
// a contract rather than a check: nothing in this package can tell an authorised
// caller from an unauthorised one, because the authority is the chain's own
// consensus and this type does not see it.
func (e *Engine) AdmitAttestingKey(st State, keyDigest common.Hash) error {
	if keyDigest == (common.Hash{}) {
		return ErrEmptyAttestingKey
	}
	st.SetState(slotHash(nsAttestKey, keyDigest), oneHash())
	return nil
}

// RevokeAttestingKey withdraws belief in a key. Quotes it signed stop verifying
// from the next block; receipts already settled under it keep the finality every
// other settled receipt has.
func (e *Engine) RevokeAttestingKey(st State, keyDigest common.Hash) {
	st.SetState(slotHash(nsAttestKey, keyDigest), common.Hash{})
}

// AdmitStateRoot records an S-Chain state root this chain will believe pins
// against. Admitting one is the act of saying "this root is S-Chain's". It has
// the same shape as admitting an attesting key, and for the same reason: the
// chain cannot verify the claim itself, so it names who it trusts to have.
//
// The caller contract on AdmitAttestingKey applies here unchanged.
func (e *Engine) AdmitStateRoot(st State, root common.Hash) error {
	if root == (common.Hash{}) {
		return ErrRootEmpty
	}
	st.SetState(slotHash(nsStateRoot, root), oneHash())
	return nil
}

// RevokeStateRoot withdraws belief in a state root.
func (e *Engine) RevokeStateRoot(st State, root common.Hash) {
	st.SetState(slotHash(nsStateRoot, root), common.Hash{})
}
