// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// provider.go is the A-Chain provider/operator registry with REAL stake/slash
// economics — the prior aivm RegisterProvider had no bond enforcement and the
// rewards SlashProvider never fired. Here:
//
//   - RegisterOperator bonds >= MinProviderBond at register time (pulled into
//     EscrowAccount, fail-closed) and advertises exactly one ModelSpec.
//   - Eligibility = exists AND not unbonding AND bonded stake >= MinProviderBond
//     AND advertises the required ModelSpec. Recomputed from live state, so a
//     slashed-below-bond or unbonding operator is excluded automatically.
//   - Unstake is deregister -> cooldown -> withdraw: the bond is returned only
//     after UnbondCooldownBlocks, and the operator is ineligible for NEW tasks
//     the moment it deregisters.
//   - Stake is SLASHABLE: settlement reduces a withholder's bonded stake (see
//     settlement.go), and once it drops below MinProviderBond the operator stops
//     being selected.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Operator registry flags.
const (
	opExistsFlag    uint8 = 0x01
	opUnbondingFlag uint8 = 0x02
)

type operatorRecord struct {
	Exists        bool
	Unbonding     bool
	ModelSpecHash common.Hash
	EndpointHash  common.Hash
	UnbondBlock   uint64
}

// Per-operator slots. Each scalar gets a clean 32-byte word via a discriminator
// hash so stake math is never packed alongside flags.
func opMetaSlot(op common.Address) common.Hash { return slotAddr(nsOperator, op) }
func opSpecSlot(op common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsOperator, op.Bytes(), []byte("spec")))
}
func opEndpSlot(op common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsOperator, op.Bytes(), []byte("endp")))
}
func opStakeSlot(op common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsOperator, op.Bytes(), []byte("stake")))
}

func packOpMeta(r operatorRecord) common.Hash {
	var w [32]byte
	if r.Exists {
		w[0] |= opExistsFlag
	}
	if r.Unbonding {
		w[0] |= opUnbondingFlag
	}
	copy(w[24:32], u64be(r.UnbondBlock))
	return common.BytesToHash(w[:])
}

func unpackOpMeta(h common.Hash) operatorRecord {
	b := h.Bytes()
	return operatorRecord{
		Exists:      b[0]&opExistsFlag != 0,
		Unbonding:   b[0]&opUnbondingFlag != 0,
		UnbondBlock: be64(b[24:32]),
	}
}

func be64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func readOperator(st QuorumState, op common.Address) operatorRecord {
	r := unpackOpMeta(st.GetState(opMetaSlot(op)))
	if !r.Exists {
		return r
	}
	r.ModelSpecHash = st.GetState(opSpecSlot(op))
	r.EndpointHash = st.GetState(opEndpSlot(op))
	return r
}

func writeOperatorMeta(st QuorumState, op common.Address, r operatorRecord) {
	st.SetState(opMetaSlot(op), packOpMeta(r))
}

func readStake(st QuorumState, op common.Address) *uint256.Int {
	return new(uint256.Int).SetBytes(st.GetState(opStakeSlot(op)).Bytes())
}

func writeStake(st QuorumState, op common.Address, v *uint256.Int) {
	st.SetState(opStakeSlot(op), h32(v))
}

// ---------------------------------------------------------------------------
// Per-ModelSpec eligible-operator array (append-only, enumerable so selection is
// reproducible by anyone who rebuilds the array in insertion order).
// ---------------------------------------------------------------------------

func modelCount(st QuorumState, spec common.Hash) uint32 {
	return uint32(new(uint256.Int).SetBytes(st.GetState(slotHash(nsModelIndex, spec)).Bytes()).Uint64())
}

func modelMember(st QuorumState, spec common.Hash, idx uint32) common.Address {
	return common.BytesToAddress(st.GetState(slotHashIdx(nsModelMember, spec, idx)).Bytes())
}

// appendModelMember adds op to spec's array if not already present (idempotent
// via the per-(spec,op) seen flag, so re-registration after withdraw never
// duplicates an enumeration entry).
func appendModelMember(st QuorumState, spec common.Hash, op common.Address) {
	seenSlot := slotHashAddr(nsModelSeen, spec, op)
	if isSet(st.GetState(seenSlot)) {
		return
	}
	n := modelCount(st, spec)
	st.SetState(slotHashIdx(nsModelMember, spec, n), common.BytesToHash(common.LeftPadBytes(op.Bytes(), 32)))
	st.SetState(slotHash(nsModelIndex, spec), h32(uint256.NewInt(uint64(n)+1)))
	st.SetState(seenSlot, oneHash())
}

// RegisterOperator bonds `stake` from `operator` and advertises a ModelSpec. The
// operator becomes eligible iff stake >= MinProviderBond. One active
// registration per operator (re-register requires Deregister + cooldown +
// WithdrawStake first). The bond is pulled into EscrowAccount FIRST, so a
// registry write only happens if the operator can fund the bond (fail-closed).
func (e *Engine) RegisterOperator(st QuorumState, lg QuorumLedger, operator common.Address, stake *uint256.Int, modelSpecHash, endpointHash common.Hash) error {
	if modelSpecHash == (common.Hash{}) {
		return ErrEmptyModelSpec
	}
	if stake.Lt(MinProviderBond) {
		return ErrStakeBelowMin
	}
	rec := readOperator(st, operator)
	if rec.Exists {
		return ErrOperatorExists
	}
	if err := lg.Pull(operator, stake); err != nil {
		return err
	}
	writeStake(st, operator, stake)
	st.SetState(opSpecSlot(operator), modelSpecHash)
	st.SetState(opEndpSlot(operator), endpointHash)
	writeOperatorMeta(st, operator, operatorRecord{Exists: true})
	appendModelMember(st, modelSpecHash, operator)
	return nil
}

// DeregisterOperator marks the operator unbonding at `block`. Stake is returned
// later by WithdrawStake after the cooldown. Marking unbonding immediately makes
// the operator ineligible for NEW tasks.
func (e *Engine) DeregisterOperator(st QuorumState, operator common.Address, block uint64) error {
	rec := readOperator(st, operator)
	if !rec.Exists {
		return ErrOperatorUnknown
	}
	if rec.Unbonding {
		return ErrOperatorUnbonding
	}
	rec.Unbonding = true
	rec.UnbondBlock = block
	writeOperatorMeta(st, operator, rec)
	return nil
}

// WithdrawStake returns bonded stake to a fully-unbonded operator after the
// cooldown, clearing the registry record. The operator stays in the per-
// ModelSpec enumeration array (stake now 0 -> selection skips it as ineligible);
// pruning would shift indices and break beacon reproducibility.
func (e *Engine) WithdrawStake(st QuorumState, lg QuorumLedger, operator common.Address, block uint64) (*uint256.Int, error) {
	rec := readOperator(st, operator)
	if !rec.Exists {
		return nil, ErrOperatorUnknown
	}
	if !rec.Unbonding {
		return nil, ErrOperatorUnbonding // must Deregister first
	}
	if block < rec.UnbondBlock+UnbondCooldownBlocks {
		return nil, ErrCooldownActive
	}
	stake := readStake(st, operator)
	if !stake.IsZero() {
		if err := lg.Pay(operator, stake); err != nil {
			return nil, err
		}
	}
	writeStake(st, operator, uint256.NewInt(0))
	writeOperatorMeta(st, operator, operatorRecord{Exists: false})
	return stake, nil
}

// eligibleSet builds the eligible working set for a ModelSpec in registry-
// insertion order: operators that exist, are not unbonding, advertise the
// ModelSpec, and hold stake >= MinProviderBond. It is the SINGLE source of "who
// is eligible" — both the margin check and the beacon draw consume it, so they
// can never disagree about the eligible universe.
func eligibleSet(st QuorumState, modelSpecHash common.Hash) []common.Address {
	total := modelCount(st, modelSpecHash)
	eligible := make([]common.Address, 0, total)
	for i := uint32(0); i < total; i++ {
		op := modelMember(st, modelSpecHash, i)
		rec := readOperator(st, op)
		if !rec.Exists || rec.Unbonding {
			continue
		}
		if rec.ModelSpecHash != modelSpecHash {
			continue
		}
		if readStake(st, op).Lt(MinProviderBond) {
			continue
		}
		eligible = append(eligible, op)
	}
	return eligible
}

// ---------------------------------------------------------------------------
// Credit ledger (withdrawable rewards / slashed-stake bonuses)
// ---------------------------------------------------------------------------

func readCredit(st QuorumState, a common.Address) *uint256.Int {
	return new(uint256.Int).SetBytes(st.GetState(slotAddr(nsCredit, a)).Bytes())
}

func writeCredit(st QuorumState, a common.Address, v *uint256.Int) {
	st.SetState(slotAddr(nsCredit, a), h32(v))
}

// addCredit credits `amount` to `a`, checked for overflow. State is written only
// on success.
func addCredit(st QuorumState, a common.Address, amount *uint256.Int) error {
	cur := readCredit(st, a)
	nv := new(uint256.Int)
	if _, overflow := nv.AddOverflow(cur, amount); overflow {
		return ErrCreditOverflow
	}
	writeCredit(st, a, nv)
	return nil
}

// WithdrawRewards pays the operator's entire accrued credit out of escrow and
// zeroes the ledger. Fails closed if nothing is owed; an escrow shortfall is a
// hard invariant breach.
func (e *Engine) WithdrawRewards(st QuorumState, lg QuorumLedger, operator common.Address) (*uint256.Int, error) {
	credit := readCredit(st, operator)
	if credit.IsZero() {
		return nil, ErrNoCredit
	}
	if err := lg.Pay(operator, credit); err != nil {
		return nil, err
	}
	writeCredit(st, operator, uint256.NewInt(0))
	return credit, nil
}

// ---------------------------------------------------------------------------
// Read-only views
// ---------------------------------------------------------------------------

// GetOperator reads an operator's registry record + live stake.
func (e *Engine) GetOperator(st QuorumState, op common.Address) (exists, unbonding bool, stake *uint256.Int, modelSpecHash, endpointHash common.Hash) {
	rec := readOperator(st, op)
	return rec.Exists, rec.Unbonding, readStake(st, op), rec.ModelSpecHash, rec.EndpointHash
}

// GetCredit reads an operator's withdrawable credit.
func (e *Engine) GetCredit(st QuorumState, op common.Address) *uint256.Int { return readCredit(st, op) }

// IsEligible reports whether op is currently eligible for the given ModelSpec.
func (e *Engine) IsEligible(st QuorumState, op common.Address, modelSpecHash common.Hash) bool {
	rec := readOperator(st, op)
	if !rec.Exists || rec.Unbonding || rec.ModelSpecHash != modelSpecHash {
		return false
	}
	return !readStake(st, op).Lt(MinProviderBond)
}
