// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

// workload.go is the unit of agentic compute: some code, some input, an
// environment, what it may consume, what isolation it demands, which capability
// it needs, and who pays.
//
// A workload is content-addressed. Its id is a digest over everything that
// determines what running it means, so the same workload has the same id on every
// node and in every process, and two runs of one workload are runs of the same
// thing rather than two things that happen to look alike. Anything that varies
// without changing the meaning — the order the environment was written in, say —
// is normalised before the digest is taken, and anything ambiguous is refused
// rather than normalised away.
//
// The payer's signature is over the id, so authorising a workload authorises
// exactly one workload. A submission naming somebody else as payer carries no
// signature that recovers to them and is refused, which is what keeps a workload
// queue from being a way to spend another account's balance.

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Protocol bounds on a workload. Fixed, not configurable: every validator must
// reach the same verdict on the same workload, and a per-node limit would make
// admission a local opinion.
const (
	// MaxEnv bounds the number of environment variables.
	MaxEnv = 64
	// MaxArgs bounds the number of entry-point arguments.
	MaxArgs = 64
	// MaxName bounds the length of a variable name, an argument, or a code
	// reference.
	MaxName = 1024
	// MaxCPU is the largest CPU ask, in thousandths of a core.
	MaxCPU = 256_000
	// MaxMemory is the largest memory ask, in bytes.
	MaxMemory = 1 << 40
	// MaxGPU is the largest device count.
	MaxGPU = 64
	// MaxTimeout is the longest a run may take, in milliseconds.
	MaxTimeout = 3_600_000
	// MinDuplication is the fewest operators that may run one workload. It is
	// A-Chain's own floor: three is the smallest set in which a strict majority
	// is agreement between independent parties rather than one party agreeing
	// with itself.
	MinDuplication = 3
	// MaxDuplication is the most, so a draw and a tally are bounded work.
	MaxDuplication = 256
)

// CodeKind names how code is delivered.
type CodeKind uint8

const (
	// CodeImage is an OCI image reference.
	CodeImage CodeKind = 0
	// CodeModule is a WebAssembly module.
	CodeModule CodeKind = 1
	// CodeScript is a script run by an interpreter named in Ref.
	CodeScript CodeKind = 2

	codeKindCount = 3
)

// String names the code kind.
func (k CodeKind) String() string {
	switch k {
	case CodeImage:
		return "image"
	case CodeModule:
		return "module"
	case CodeScript:
		return "script"
	default:
		return "unknown"
	}
}

// Known reports whether k is a code kind this build knows.
func (k CodeKind) Known() bool { return k < codeKindCount }

// Code is what to run. Digest is the identity — the content digest of the image,
// module or script — and Ref is only how to obtain it. Two references that fetch
// the same bytes are the same code.
type Code struct {
	Kind   CodeKind    `json:"kind"`
	Ref    string      `json:"ref"`
	Digest common.Hash `json:"digest"`
	Args   []string    `json:"args,omitempty"`
}

// Var is one environment entry.
type Var struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Resource is what a run may consume. On a receipt it is what the run was
// GIVEN, which is not the same as what it used: the shipped local runners
// report the ask back verbatim and clamp the elapsed time to it, because a
// process's true peak memory is not something they measure. Receipt.Check still
// enforces Within, and the cluster runner reports the limits Kubernetes actually
// applied, so an overrun there is caught -- but on the local path the check is
// a bound that honest runners cannot exceed rather than a measurement of them.
// Price is over the ask for the same reason (see price.go).
type Resource struct {
	CPU     uint32 `json:"cpu"`     // thousandths of a core
	Memory  uint64 `json:"memory"`  // bytes
	GPU     uint32 `json:"gpu"`     // devices
	Timeout uint32 `json:"timeout"` // milliseconds of wall time
}

// resourceLen is the fixed width of a Resource on the wire.
const resourceLen = 4 + 8 + 4 + 4

// encode writes the Resource in its fixed-width canonical form.
func (r Resource) encode() []byte {
	buf := make([]byte, 0, resourceLen)
	buf = append(buf, u32be(r.CPU)...)
	buf = append(buf, u64be(r.Memory)...)
	buf = append(buf, u32be(r.GPU)...)
	buf = append(buf, u32be(r.Timeout)...)
	return buf
}

// Within reports whether r fits inside the ask cap. A run that consumed more than
// it was allowed is not a run that succeeded within its limits.
func (r Resource) Within(cap Resource) bool {
	return r.CPU <= cap.CPU && r.Memory <= cap.Memory &&
		r.GPU <= cap.GPU && r.Timeout <= cap.Timeout
}

// Capability names what a workload needs to be served: a group of operations, in
// a specific version of the capability catalog. Which providers serve that group
// is separate state with its own lifecycle (see scheduler.go); this value only
// says what is needed.
type Capability struct {
	Catalog common.Hash `json:"catalog"`
	Group   common.Hash `json:"group"`
}

// Workload is one unit of agentic compute.
type Workload struct {
	Code Code `json:"code"`
	// Input names the bytes to run on. It is a handle, never the bytes: nothing
	// large rides on chain, and the digest is what a run is checked against.
	Input      Handle     `json:"input"`
	Env        []Var      `json:"env,omitempty"`
	Resource   Resource   `json:"resource"`
	Demand     Properties `json:"demand"`
	Placement  Placement  `json:"placement"`
	Capability Capability `json:"capability"`
	// Duplication is how many independent operators run this workload. It is the
	// third axis beside isolation and durability, and it is a count rather than a
	// set member because that is what it is. It becomes the draw size the
	// settlement engine already takes.
	Duplication uint32         `json:"duplication"`
	Payer       common.Address `json:"payer"`
	Nonce       common.Hash    `json:"nonce"`
	Signature   []byte         `json:"signature,omitempty"`
}

// Threshold is how many of the operators must agree for the answer to stand: a
// strict majority of the duplication. It is derived, not named, so a workload
// cannot ask for duplication and then accept agreement from a minority of it.
func (w Workload) Threshold() uint32 { return w.Duplication/2 + 1 }

// digestStrings folds a list of strings into one digest, length-prefixed in the
// order given. Order is meaning here: arguments are positional.
func digestStrings(ss []string) common.Hash {
	buf := u32be(uint32(len(ss)))
	for _, s := range ss {
		buf = append(buf, blob([]byte(s))...)
	}
	return common.BytesToHash(crypto.Keccak256(buf))
}

// digestEnv folds the environment into one digest. Entries are taken in the order
// held; Validate requires that order to be sorted by name and free of duplicates,
// so one environment has exactly one digest.
func digestEnv(vars []Var) common.Hash {
	buf := u32be(uint32(len(vars)))
	for _, v := range vars {
		buf = append(buf, blob([]byte(v.Name))...)
		buf = append(buf, blob([]byte(v.Value))...)
	}
	return common.BytesToHash(crypto.Keccak256(buf))
}

// ID is the workload's identity: a digest over everything that determines what
// running it means. The signature is not part of it — an id names a workload, and
// authorising the workload is a separate act performed over that name.
func (w Workload) ID() common.Hash {
	buf := make([]byte, 0, 256)
	buf = append(buf, []byte(DomainWorkload)...)
	buf = append(buf, byte(w.Code.Kind))
	buf = append(buf, w.Code.Digest.Bytes()...)
	buf = append(buf, crypto.Keccak256([]byte(w.Code.Ref))...)
	buf = append(buf, digestStrings(w.Code.Args).Bytes()...)
	buf = append(buf, w.Input.ID().Bytes()...)
	buf = append(buf, digestEnv(w.Env).Bytes()...)
	buf = append(buf, w.Resource.encode()...)
	buf = append(buf, u16be(uint16(w.Demand))...)
	buf = append(buf, u32be(w.Duplication)...)
	buf = append(buf, byte(w.Placement))
	buf = append(buf, w.Capability.Catalog.Bytes()...)
	buf = append(buf, w.Capability.Group.Bytes()...)
	buf = append(buf, w.Payer.Bytes()...)
	buf = append(buf, w.Nonce.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

// Authorize signs the workload's id with the payer's key, which is what makes the
// workload spendable against the payer's balance.
func (w *Workload) Authorize(key Signer) error {
	sig, err := key.Sign(w.ID())
	if err != nil {
		return err
	}
	w.Signature = sig
	return nil
}

// Authorized reports whether the workload carries a signature that recovers to
// its declared payer. Anyone may deliver a workload; only its payer can authorise
// spending against their balance, so this is what admission turns on.
func (w Workload) Authorized() error {
	if len(w.Signature) != 65 {
		return ErrWorkloadUnauthorized
	}
	pub, err := crypto.Ecrecover(w.ID().Bytes(), w.Signature)
	if err != nil {
		return ErrWorkloadUnauthorized
	}
	if common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]) != w.Payer {
		return ErrWorkloadUnauthorized
	}
	return nil
}

// Validate refuses a workload that is malformed, ambiguous, or outside the
// protocol bounds — before it can reach selection or move any value. The
// environment must arrive sorted by name and free of duplicates: sorting it here
// would silently accept two spellings of one workload, and a duplicate name has
// no single meaning to normalise to.
func (w Workload) Validate() error {
	if !w.Code.Kind.Known() {
		return ErrWorkloadCode
	}
	if w.Code.Digest == (common.Hash{}) {
		return ErrWorkloadCode
	}
	if len(w.Code.Ref) > MaxName {
		return ErrWorkloadCode
	}
	if len(w.Code.Args) > MaxArgs {
		return ErrWorkloadCode
	}
	for _, a := range w.Code.Args {
		if len(a) > MaxName {
			return ErrWorkloadCode
		}
	}
	if err := w.Input.Validate(); err != nil {
		return err
	}
	if len(w.Env) > MaxEnv {
		return ErrWorkloadEnv
	}
	for i, v := range w.Env {
		if v.Name == "" || len(v.Name) > MaxName || len(v.Value) > MaxName {
			return ErrWorkloadEnv
		}
		if i > 0 && w.Env[i-1].Name >= v.Name {
			return ErrWorkloadEnv
		}
	}
	if w.Resource.CPU == 0 || w.Resource.CPU > MaxCPU {
		return ErrWorkloadResource
	}
	if w.Resource.Memory == 0 || w.Resource.Memory > MaxMemory {
		return ErrWorkloadResource
	}
	if w.Resource.GPU > MaxGPU {
		return ErrWorkloadResource
	}
	if w.Resource.Timeout == 0 || w.Resource.Timeout > MaxTimeout {
		return ErrWorkloadResource
	}
	if !w.Demand.Wellformed() {
		return ErrDemandMalformed
	}
	if !w.Placement.Known() {
		return ErrWorkloadPlacement
	}
	if w.Duplication < MinDuplication || w.Duplication > MaxDuplication {
		return ErrWorkloadDuplication
	}
	if w.Capability.Catalog == (common.Hash{}) || w.Capability.Group == (common.Hash{}) {
		return ErrWorkloadCapability
	}
	if w.Payer == (common.Address{}) {
		return ErrWorkloadUnauthorized
	}
	return w.Authorized()
}
