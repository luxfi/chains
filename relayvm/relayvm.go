// Package relayvm is a thin re-export of the canonical R-Chain VM
// implementation in github.com/luxfi/relay/vm. The canonical source lives
// in luxfi/relay so the standalone `relayd` operator daemon and the
// in-luxd plugin share one code path.
package relayvm

import (
	"github.com/luxfi/constants"
	relayvm "github.com/luxfi/relay/vm"
	"github.com/luxfi/vm/chain"
)

// Re-exported public surface — type aliases keep existing import paths working.
type (
	Config         = relayvm.Config
	Channel        = relayvm.Channel
	Message        = relayvm.Message
	MessageReceipt = relayvm.MessageReceipt
	VM             = relayvm.VM
	Genesis        = relayvm.Genesis
	SignedReceipt  = relayvm.SignedReceipt
	ReceiptCommit  = relayvm.ReceiptCommit
	Service        = relayvm.Service
	Factory        = relayvm.Factory
	DestNonceKey   = relayvm.DestNonceKey
	RelayVertex    = relayvm.RelayVertex
)

// Service args/replies — re-exported.
type (
	OpenChannelArgs         = relayvm.OpenChannelArgs
	OpenChannelReply        = relayvm.OpenChannelReply
	GetChannelArgs          = relayvm.GetChannelArgs
	ChannelReply            = relayvm.ChannelReply
	GetChannelReply         = relayvm.GetChannelReply
	CloseChannelArgs        = relayvm.CloseChannelArgs
	CloseChannelReply       = relayvm.CloseChannelReply
	ListChannelsArgs        = relayvm.ListChannelsArgs
	ListChannelsReply       = relayvm.ListChannelsReply
	SendMessageArgs         = relayvm.SendMessageArgs
	SendMessageReply        = relayvm.SendMessageReply
	GetMessageArgs          = relayvm.GetMessageArgs
	MessageReply            = relayvm.MessageReply
	GetMessageReply         = relayvm.GetMessageReply
	ReceiveMessageArgs      = relayvm.ReceiveMessageArgs
	ReceiveMessageReply     = relayvm.ReceiveMessageReply
	GetVerifiedMessageArgs  = relayvm.GetVerifiedMessageArgs
	GetVerifiedMessageReply = relayvm.GetVerifiedMessageReply
	HealthArgs              = relayvm.HealthArgs
	HealthReply             = relayvm.HealthReply
)

// VMID identifies R-Chain. It is constants.RelayVMID and nothing else.
//
// A vmID is an immutable one-way door: it is baked into the CreateChainTx at
// genesis, it is the plugin binary's filename, and it is what the P-Chain
// stores forever. So it is named from the one source of truth rather than
// re-exported from luxfi/relay, which declares it as a private literal
// (`ids.ID{'r','e','l','a','y','v','m'}`) that agrees with constants by
// coincidence and nothing else. This repo builds the plugin binary, so this
// repo is where the two must be proven to agree: TestVMID_IsCanonicalAndStable
// compares all three.
var VMID = constants.RelayVMID

// Factory.New satisfies the node's vms.Factory and so returns interface{}.
// What the plugin serves is a chain.ChainVM, and this is where that is
// established — a build error here rather than a type assertion that fails at
// the moment an operator starts the chain.
var _ chain.ChainVM = (*VM)(nil)
