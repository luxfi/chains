// Package oraclevm is a thin re-export of the canonical O-Chain VM
// implementation in github.com/luxfi/oracle/vm. The canonical source lives
// in luxfi/oracle so the standalone `oracled` operator daemon and the
// in-luxd plugin share one code path.
package oraclevm

import (
	"github.com/luxfi/constants"
	oraclevm "github.com/luxfi/oracle/vm"
	"github.com/luxfi/vm/chain"
)

// Re-exported public surface.
type (
	Config          = oraclevm.Config
	Feed            = oraclevm.Feed
	Observation     = oraclevm.Observation
	AggregatedValue = oraclevm.AggregatedValue
	RequestKind     = oraclevm.RequestKind
	OracleRequest   = oraclevm.OracleRequest
	RequestStatus   = oraclevm.RequestStatus
	OracleRecord    = oraclevm.OracleRecord
	OracleCommit    = oraclevm.OracleCommit
	VM              = oraclevm.VM
	Block           = oraclevm.Block
	Genesis         = oraclevm.Genesis
	Service         = oraclevm.Service
	Factory         = oraclevm.Factory
	FeedRoundKey    = oraclevm.FeedRoundKey
	OracleVertex    = oraclevm.OracleVertex
)

// Service args/replies — re-exported.
type (
	RegisterFeedArgs       = oraclevm.RegisterFeedArgs
	RegisterFeedReply      = oraclevm.RegisterFeedReply
	GetFeedArgs            = oraclevm.GetFeedArgs
	GetFeedReply           = oraclevm.GetFeedReply
	GetValueArgs           = oraclevm.GetValueArgs
	GetValueReply          = oraclevm.GetValueReply
	SubmitObservationArgs  = oraclevm.SubmitObservationArgs
	SubmitObservationReply = oraclevm.SubmitObservationReply
	GetAttestationArgs     = oraclevm.GetAttestationArgs
	GetAttestationReply    = oraclevm.GetAttestationReply
	HealthArgs             = oraclevm.HealthArgs
	HealthReply            = oraclevm.HealthReply
)

// VMID identifies O-Chain. It is constants.OracleVMID and nothing else.
//
// A vmID is an immutable one-way door: it is baked into the CreateChainTx at
// genesis, it is the plugin binary's filename, and it is what the P-Chain
// stores forever. So it is named from the one source of truth rather than
// re-exported from luxfi/oracle, which declares it as a private literal
// (`ids.ID{'o','r','a','c','l','e','v','m'}`) that agrees with constants by
// coincidence and nothing else. This repo builds the plugin binary, so this
// repo is where the two must be proven to agree: TestVMID_IsCanonicalAndStable
// compares all three.
var VMID = constants.OracleVMID

// Factory.New satisfies the node's vms.Factory and so returns interface{}.
// What the plugin serves is a chain.ChainVM, and this is where that is
// established — a build error here rather than a type assertion that fails at
// the moment an operator starts the chain.
var _ chain.ChainVM = (*VM)(nil)
