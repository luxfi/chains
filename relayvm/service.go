// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/luxfi/ids"
)

// Service provides RPC access to the RelayVM
type Service struct {
	vm *VM
}

// ======== Channel API ========

// OpenChannelArgs are arguments for OpenChannel
type OpenChannelArgs struct {
	SourceChain string `json:"sourceChain"`
	DestChain   string `json:"destChain"`
	Ordering    string `json:"ordering"` // "ordered" or "unordered"
	Version     string `json:"version"`
}

// OpenChannelReply is the reply for OpenChannel
type OpenChannelReply struct {
	ChannelID string `json:"channelId"`
}

// OpenChannel opens a new cross-chain channel
func (s *Service) OpenChannel(r *http.Request, args *OpenChannelArgs, reply *OpenChannelReply) error {
	sourceChain, err := ids.FromString(args.SourceChain)
	if err != nil {
		return err
	}

	destChain, err := ids.FromString(args.DestChain)
	if err != nil {
		return err
	}

	ordering := args.Ordering
	if ordering == "" {
		ordering = "unordered"
	}

	version := args.Version
	if version == "" {
		version = "1.0"
	}

	channel, err := s.vm.OpenChannel(sourceChain, destChain, ordering, version)
	if err != nil {
		return err
	}

	reply.ChannelID = channel.ID.String()
	return nil
}

// GetChannelArgs are arguments for GetChannel
type GetChannelArgs struct {
	ChannelID string `json:"channelId"`
}

// ChannelReply represents a channel in RPC responses
type ChannelReply struct {
	ID          string            `json:"id"`
	SourceChain string            `json:"sourceChain"`
	DestChain   string            `json:"destChain"`
	Ordering    string            `json:"ordering"`
	Version     string            `json:"version"`
	State       string            `json:"state"`
	CreatedAt   string            `json:"createdAt"`
	Metadata    map[string]string `json:"metadata"`
}

// GetChannelReply is the reply for GetChannel
type GetChannelReply struct {
	Channel ChannelReply `json:"channel"`
}

// GetChannel returns a channel by ID
func (s *Service) GetChannel(r *http.Request, args *GetChannelArgs, reply *GetChannelReply) error {
	channelID, err := ids.FromString(args.ChannelID)
	if err != nil {
		return err
	}

	channel, err := s.vm.GetChannel(channelID)
	if err != nil {
		return err
	}

	reply.Channel = ChannelReply{
		ID:          channel.ID.String(),
		SourceChain: channel.SourceChain.String(),
		DestChain:   channel.DestChain.String(),
		Ordering:    channel.Ordering,
		Version:     channel.Version,
		State:       channel.State,
		CreatedAt:   channel.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Metadata:    channel.Metadata,
	}

	return nil
}

// CloseChannelArgs are arguments for CloseChannel
type CloseChannelArgs struct {
	ChannelID string `json:"channelId"`
}

// CloseChannelReply is the reply for CloseChannel
type CloseChannelReply struct {
	Success bool `json:"success"`
}

// CloseChannel closes a channel
func (s *Service) CloseChannel(r *http.Request, args *CloseChannelArgs, reply *CloseChannelReply) error {
	channelID, err := ids.FromString(args.ChannelID)
	if err != nil {
		return err
	}

	if err := s.vm.CloseChannel(channelID); err != nil {
		return err
	}

	reply.Success = true
	return nil
}

// ListChannelsArgs are arguments for ListChannels
type ListChannelsArgs struct {
	State string `json:"state"` // Optional filter by state
}

// ListChannelsReply is the reply for ListChannels
type ListChannelsReply struct {
	Channels []ChannelReply `json:"channels"`
}

// ListChannels lists all channels
func (s *Service) ListChannels(r *http.Request, args *ListChannelsArgs, reply *ListChannelsReply) error {
	s.vm.mu.RLock()
	defer s.vm.mu.RUnlock()

	reply.Channels = make([]ChannelReply, 0, len(s.vm.channels))
	for _, channel := range s.vm.channels {
		if args.State != "" && channel.State != args.State {
			continue
		}

		reply.Channels = append(reply.Channels, ChannelReply{
			ID:          channel.ID.String(),
			SourceChain: channel.SourceChain.String(),
			DestChain:   channel.DestChain.String(),
			Ordering:    channel.Ordering,
			Version:     channel.Version,
			State:       channel.State,
			CreatedAt:   channel.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Metadata:    channel.Metadata,
		})
	}

	return nil
}

// ======== Message API ========

// SendMessageArgs are arguments for SendMessage
type SendMessageArgs struct {
	ChannelID string `json:"channelId"`
	Payload   string `json:"payload"`  // Base64-encoded
	Sender    string `json:"sender"`   // Base64-encoded
	Receiver  string `json:"receiver"` // Base64-encoded
	Timeout   int64  `json:"timeout"`  // Unix timestamp
}

// SendMessageReply is the reply for SendMessage
type SendMessageReply struct {
	MessageID string `json:"messageId"`
	Sequence  uint64 `json:"sequence"`
}

// SendMessage sends a cross-chain message
func (s *Service) SendMessage(r *http.Request, args *SendMessageArgs, reply *SendMessageReply) error {
	channelID, err := ids.FromString(args.ChannelID)
	if err != nil {
		return err
	}

	payload, err := base64.StdEncoding.DecodeString(args.Payload)
	if err != nil {
		return err
	}

	sender, err := base64.StdEncoding.DecodeString(args.Sender)
	if err != nil {
		return err
	}

	receiver, err := base64.StdEncoding.DecodeString(args.Receiver)
	if err != nil {
		return err
	}

	msg, err := s.vm.SendMessage(channelID, payload, sender, receiver, args.Timeout)
	if err != nil {
		return err
	}

	reply.MessageID = msg.ID.String()
	reply.Sequence = msg.Sequence
	return nil
}

// GetMessageArgs are arguments for GetMessage
type GetMessageArgs struct {
	MessageID string `json:"messageId"`
}

// MessageReply represents a message in RPC responses
type MessageReply struct {
	ID           string `json:"id"`
	ChannelID    string `json:"channelId"`
	SourceChain  string `json:"sourceChain"`
	DestChain    string `json:"destChain"`
	Sequence     uint64 `json:"sequence"`
	Payload      string `json:"payload"` // Base64-encoded
	Sender       string `json:"sender"`
	Receiver     string `json:"receiver"`
	Timeout      int64  `json:"timeout"`
	State        string `json:"state"`
	SourceHeight uint64 `json:"sourceHeight,omitempty"`
	ConfirmedAt  int64  `json:"confirmedAt,omitempty"`
}

// GetMessageReply is the reply for GetMessage
type GetMessageReply struct {
	Message MessageReply `json:"message"`
}

// GetMessage returns a message by ID
func (s *Service) GetMessage(r *http.Request, args *GetMessageArgs, reply *GetMessageReply) error {
	msgID, err := ids.FromString(args.MessageID)
	if err != nil {
		return err
	}

	msg, err := s.vm.GetMessage(msgID)
	if err != nil {
		return err
	}

	reply.Message = MessageReply{
		ID:           msg.ID.String(),
		ChannelID:    msg.ChannelID.String(),
		SourceChain:  msg.SourceChain.String(),
		DestChain:    msg.DestChain.String(),
		Sequence:     msg.Sequence,
		Payload:      base64.StdEncoding.EncodeToString(msg.Payload),
		Sender:       base64.StdEncoding.EncodeToString(msg.Sender),
		Receiver:     base64.StdEncoding.EncodeToString(msg.Receiver),
		Timeout:      msg.Timeout,
		State:        msg.State,
		SourceHeight: msg.SourceHeight,
		ConfirmedAt:  msg.ConfirmedAt,
	}

	return nil
}

// ReceiveMessageArgs are arguments for ReceiveMessage
type ReceiveMessageArgs struct {
	MessageID    string `json:"messageId"`
	Proof        string `json:"proof"`        // Base64-encoded Merkle proof
	SourceHeight uint64 `json:"sourceHeight"` // Block height on source chain
}

// ReceiveMessageReply is the reply for ReceiveMessage
type ReceiveMessageReply struct {
	Success     bool   `json:"success"`
	ResultHash  string `json:"resultHash"` // Base64-encoded
	BlockHeight uint64 `json:"blockHeight"`
}

// ReceiveMessage processes an incoming message with proof
func (s *Service) ReceiveMessage(r *http.Request, args *ReceiveMessageArgs, reply *ReceiveMessageReply) error {
	msgID, err := ids.FromString(args.MessageID)
	if err != nil {
		return err
	}

	proof, err := base64.StdEncoding.DecodeString(args.Proof)
	if err != nil {
		return err
	}

	receipt, err := s.vm.ReceiveMessage(msgID, proof, args.SourceHeight)
	if err != nil {
		return err
	}

	reply.Success = receipt.Success
	reply.ResultHash = base64.StdEncoding.EncodeToString(receipt.ResultHash)
	reply.BlockHeight = receipt.BlockHeight
	return nil
}

// GetVerifiedMessageArgs are arguments for GetVerifiedMessage
type GetVerifiedMessageArgs struct {
	MessageID string `json:"messageId"`
}

// GetVerifiedMessageReply is the reply for GetVerifiedMessage
type GetVerifiedMessageReply struct {
	SourceChain  string `json:"sourceChain"`
	DestChain    string `json:"destChain"`
	Nonce        uint64 `json:"nonce"`
	Payload      string `json:"payload"`
	Proof        string `json:"proof"`
	SourceHeight uint64 `json:"sourceHeight"`
	Timestamp    int64  `json:"timestamp"`
}

// GetVerifiedMessage returns a VerifiedMessage artifact
func (s *Service) GetVerifiedMessage(r *http.Request, args *GetVerifiedMessageArgs, reply *GetVerifiedMessageReply) error {
	msgID, err := ids.FromString(args.MessageID)
	if err != nil {
		return err
	}

	msg, err := s.vm.GetMessage(msgID)
	if err != nil {
		return err
	}

	verifiedMsg, err := s.vm.CreateVerifiedMessage(msg)
	if err != nil {
		return err
	}

	reply.SourceChain = verifiedMsg.SrcDomain.String()
	reply.DestChain = verifiedMsg.DstDomain.String()
	reply.Nonce = verifiedMsg.Nonce
	reply.Payload = base64.StdEncoding.EncodeToString(verifiedMsg.Payload)
	reply.Proof = base64.StdEncoding.EncodeToString(verifiedMsg.SrcFinalityProof)
	reply.SourceHeight = 0 // Not in artifact
	reply.Timestamp = 0    // Not in artifact
	return nil
}

// ======== Health Check ========

// HealthArgs are arguments for Health
type HealthArgs struct{}

// HealthReply is the reply for Health
type HealthReply struct {
	Healthy         bool `json:"healthy"`
	Channels        int  `json:"channels"`
	PendingMessages int  `json:"pendingMessages"`
}

// Health returns health status
func (s *Service) Health(r *http.Request, args *HealthArgs, reply *HealthReply) error {
	health, err := s.vm.HealthCheck(context.Background())
	if err != nil {
		return err
	}

	s.vm.mu.RLock()
	defer s.vm.mu.RUnlock()

	reply.Healthy = health.Healthy
	reply.Channels = len(s.vm.channels)
	reply.PendingMessages = s.vm.countPendingMessages()
	return nil
}
