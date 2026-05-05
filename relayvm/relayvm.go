// Package relayvm is a thin re-export of the canonical R-Chain VM
// implementation in github.com/luxfi/relay/vm. The canonical source lives
// in luxfi/relay so the standalone `relayd` operator daemon and the
// in-luxd plugin share one code path.
package relayvm

import (
	relayvm "github.com/luxfi/relay/vm"
)

// Re-exported public surface — type aliases keep existing import paths working.
type (
	Config          = relayvm.Config
	Channel         = relayvm.Channel
	Message         = relayvm.Message
	MessageReceipt  = relayvm.MessageReceipt
	VM              = relayvm.VM
	Genesis         = relayvm.Genesis
	SignedReceipt   = relayvm.SignedReceipt
	ReceiptCommit   = relayvm.ReceiptCommit
	Service         = relayvm.Service
	Factory         = relayvm.Factory
	DestNonceKey    = relayvm.DestNonceKey
	RelayVertex     = relayvm.RelayVertex
)

// Service args/replies — re-exported.
type (
	OpenChannelArgs        = relayvm.OpenChannelArgs
	OpenChannelReply       = relayvm.OpenChannelReply
	GetChannelArgs         = relayvm.GetChannelArgs
	ChannelReply           = relayvm.ChannelReply
	GetChannelReply        = relayvm.GetChannelReply
	CloseChannelArgs       = relayvm.CloseChannelArgs
	CloseChannelReply      = relayvm.CloseChannelReply
	ListChannelsArgs       = relayvm.ListChannelsArgs
	ListChannelsReply      = relayvm.ListChannelsReply
	SendMessageArgs        = relayvm.SendMessageArgs
	SendMessageReply       = relayvm.SendMessageReply
	GetMessageArgs         = relayvm.GetMessageArgs
	MessageReply           = relayvm.MessageReply
	GetMessageReply        = relayvm.GetMessageReply
	ReceiveMessageArgs     = relayvm.ReceiveMessageArgs
	ReceiveMessageReply    = relayvm.ReceiveMessageReply
	GetVerifiedMessageArgs = relayvm.GetVerifiedMessageArgs
	GetVerifiedMessageReply = relayvm.GetVerifiedMessageReply
	HealthArgs             = relayvm.HealthArgs
	HealthReply            = relayvm.HealthReply
)

// VMID is the canonical R-Chain VM identifier.
var VMID = relayvm.VMID
