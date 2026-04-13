// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"fmt"

	"github.com/luxfi/log"
)

// InitializeMPCKeys performs threshold key generation when signer set is ready
// This should be called when the signer set reaches the threshold or is frozen
func (vm *VM) InitializeMPCKeys(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	numSigners := len(vm.signerSet.Signers)
	if numSigners == 0 {
		return fmt.Errorf("no signers in set")
	}

	threshold := vm.signerSet.ThresholdT
	if threshold == 0 {
		return fmt.Errorf("threshold not set")
	}

	vm.log.Info("initializing MPC threshold keys",
		log.Int("totalSigners", numSigners),
		log.Int("threshold", threshold),
	)

	// Generate threshold keys using trusted dealer
	// In production, this would use proper DKG protocol
	if err := vm.mpcKeyManager.GenerateKeys(ctx, threshold, numSigners); err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	// Store group public key in signer set
	vm.signerSet.PublicKey = vm.mpcKeyManager.GetGroupPublicKey()

	vm.log.Info("MPC keys initialized",
		log.Int("groupKeyLen", len(vm.signerSet.PublicKey)),
	)

	return nil
}

// TriggerKeygen should be called when signer set changes
func (vm *VM) TriggerKeygen(ctx context.Context) error {
	// Check if we have enough signers
	vm.mu.RLock()
	numSigners := len(vm.signerSet.Signers)
	threshold := vm.signerSet.ThresholdT
	vm.mu.RUnlock()

	if numSigners < 3 {
		vm.log.Debug("not enough signers for keygen",
			log.Int("numSigners", numSigners),
		)
		return nil
	}

	// Perform keygen
	if err := vm.InitializeMPCKeys(ctx); err != nil {
		return fmt.Errorf("keygen failed: %w", err)
	}

	vm.log.Info("keygen triggered successfully",
		log.Int("numSigners", numSigners),
		log.Int("threshold", threshold),
	)

	return nil
}

// ProcessBridgeMessage handles an incoming bridge message
func (vm *VM) ProcessBridgeMessage(ctx context.Context, message *BridgeMessage) error {
	vm.log.Info("processing bridge message",
		log.String("messageID", message.ID.String()),
		log.String("sourceChain", message.SourceChain),
		log.String("destChain", message.DestChain),
	)

	// Validate message before accepting
	if err := vm.messageValidator.ValidateBeforeRelay(message); err != nil {
		return fmt.Errorf("message validation failed: %w", err)
	}

	// If this node is a signer, we can participate in signing
	vm.mu.RLock()
	isSigner := vm.HasSigner(vm.rt.NodeID)
	vm.mu.RUnlock()

	if isSigner {
		// Create our signature share
		shareBytes, publicShare, err := vm.bridgeSigner.CreateSignatureShare(ctx, message)
		if err != nil {
			vm.log.Error("failed to create signature share",
				"messageID", message.ID.String(),
				"error", err,
			)
		} else {
			vm.log.Debug("created signature share for bridge message",
				log.String("messageID", message.ID.String()),
				log.Int("shareLen", len(shareBytes)),
			)

			// In production, broadcast this share to other signers
			// For now, we just log it
			_ = publicShare
		}
	}

	return nil
}

// InitiateBridgeTransfer initiates a new bridge transfer with MPC signing
func (vm *VM) InitiateBridgeTransfer(ctx context.Context, message *BridgeMessage) error {
	vm.log.Info("initiating bridge transfer",
		log.String("messageID", message.ID.String()),
		log.String("sourceChain", message.SourceChain),
		log.String("destChain", message.DestChain),
		log.Uint64("amount", message.Amount),
	)

	// Get active signers
	vm.mu.RLock()
	activeSigners := make([]int, 0, len(vm.signerSet.Signers))
	for _, signer := range vm.signerSet.Signers {
		if signer.Active && !signer.Slashed {
			activeSigners = append(activeSigners, signer.SlotIndex)
		}
	}
	threshold := vm.signerSet.ThresholdT
	vm.mu.RUnlock()

	if len(activeSigners) < threshold+1 {
		return fmt.Errorf("insufficient active signers: %d < %d", len(activeSigners), threshold+1)
	}

	// Request threshold signature
	if err := vm.bridgeSigner.SignBridgeMessage(ctx, message, activeSigners); err != nil {
		return fmt.Errorf("failed to sign bridge message: %w", err)
	}

	vm.log.Info("bridge message signed",
		log.String("messageID", message.ID.String()),
		log.Int("numSigners", len(activeSigners)),
	)

	// In production, relay message to destination chain
	// For now, just add to pending bridges
	vm.mu.Lock()
	vm.pendingBridges[message.ID] = &BridgeRequest{
		ID:            message.ID,
		SourceChain:   message.SourceChain,
		DestChain:     message.DestChain,
		Asset:         message.Asset,
		Amount:        message.Amount,
		Recipient:     message.Recipient,
		SourceTxID:    message.SourceTxID,
		Confirmations: message.Confirmations,
		Status:        "signed",
		MPCSignatures: [][]byte{message.Signature},
		CreatedAt:     message.Timestamp,
	}
	vm.mu.Unlock()

	return nil
}

// ConfirmDelivery confirms delivery of a bridge message on the destination chain
func (vm *VM) ConfirmDelivery(ctx context.Context, message *BridgeMessage, confirmation *DeliveryConfirmation) error {
	vm.log.Info("confirming bridge message delivery",
		log.String("messageID", message.ID.String()),
		log.String("destTxID", confirmation.DestTxID.String()),
	)

	// Get active signers
	vm.mu.RLock()
	activeSigners := make([]int, 0, len(vm.signerSet.Signers))
	for _, signer := range vm.signerSet.Signers {
		if signer.Active && !signer.Slashed {
			activeSigners = append(activeSigners, signer.SlotIndex)
		}
	}
	vm.mu.RUnlock()

	// Sign delivery confirmation
	if err := vm.deliverySigner.SignDeliveryConfirmation(ctx, message.ID, confirmation, activeSigners); err != nil {
		return fmt.Errorf("failed to sign delivery confirmation: %w", err)
	}

	// Attach confirmation to message
	message.DeliveryConfirmation = confirmation

	// Validate complete message
	if err := vm.messageValidator.ValidateMessage(message); err != nil {
		return fmt.Errorf("message validation failed: %w", err)
	}

	vm.log.Info("delivery confirmed",
		log.String("messageID", message.ID.String()),
		log.String("destTxID", confirmation.DestTxID.String()),
	)

	// Mark as completed in registry
	vm.mu.Lock()
	if bridge, exists := vm.pendingBridges[message.ID]; exists {
		bridge.Status = "completed"

		vm.bridgeRegistry.CompletedBridges[message.ID] = &CompletedBridge{
			RequestID:    message.ID,
			SourceTxID:   message.SourceTxID,
			DestTxID:     confirmation.DestTxID,
			CompletedAt:  confirmation.ConfirmedAt,
			MPCSignature: message.Signature,
		}

		delete(vm.pendingBridges, message.ID)
	}
	vm.mu.Unlock()

	return nil
}

// GetMPCStatus returns the current MPC status
func (vm *VM) GetMPCStatus() map[string]interface{} {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	groupKey := vm.mpcKeyManager.GetGroupPublicKey()

	status := map[string]interface{}{
		"initialized":  len(groupKey) > 0,
		"groupKeyLen":  len(groupKey),
		"numSigners":   len(vm.signerSet.Signers),
		"threshold":    vm.signerSet.ThresholdT,
		"currentEpoch": vm.signerSet.CurrentEpoch,
		"setFrozen":    vm.signerSet.SetFrozen,
	}

	if vm.mpcKeyManager.keyShare != nil {
		status["hasKeyShare"] = true
		status["keyShareIndex"] = vm.mpcKeyManager.keyShare.Index()
	} else {
		status["hasKeyShare"] = false
	}

	return status
}
