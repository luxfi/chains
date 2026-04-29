// Package oraclevm is a thin re-export of the canonical O-Chain VM
// implementation in github.com/luxfi/oracle/vm. The canonical source lives
// in luxfi/oracle so the standalone `oracled` operator daemon and the
// in-luxd plugin share one code path.
package oraclevm

import (
	oraclevm "github.com/luxfi/oracle/vm"
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
