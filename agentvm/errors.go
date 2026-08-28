// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import "errors"

// Every error here is a refusal that leaves state unchanged. A rejected operation
// makes no write and moves no value, so the whole surface is fail-closed and
// auditable in one place.
var (
	// the demand itself
	ErrDemandMalformed = errors.New("agentvm: demand names two values on one axis")
	ErrUnknownProperty = errors.New("agentvm: property unknown to this build")

	// the workload
	ErrWorkloadCode         = errors.New("agentvm: workload code is malformed")
	ErrWorkloadEnv          = errors.New("agentvm: workload environment is unsorted, duplicated or oversized")
	ErrWorkloadResource     = errors.New("agentvm: workload resource ask is zero or above the protocol bound")
	ErrWorkloadPlacement    = errors.New("agentvm: workload placement unknown to this build")
	ErrWorkloadCapability   = errors.New("agentvm: workload names no capability")
	ErrWorkloadDuplication  = errors.New("agentvm: workload duplication outside the protocol bounds")
	ErrWorkloadUnauthorized = errors.New("agentvm: workload carries no signature recovering to its payer")
	ErrWorkloadAlreadyUsed  = errors.New("agentvm: workload already opened a task")

	// the object handles
	ErrHandleEmpty    = errors.New("agentvm: handle names no bytes")
	ErrHandleLocation = errors.New("agentvm: handle names no manifest location")

	// the run
	ErrReceiptWorkload = errors.New("agentvm: receipt is for a different workload")
	ErrReceiptOperator = errors.New("agentvm: receipt is not this operator's")
	ErrReceiptOutput   = errors.New("agentvm: receipt produced no output")
	ErrReceiptResource = errors.New("agentvm: run consumed more than the workload asked for")

	// the evidence
	ErrEvidenceMechanism = errors.New("agentvm: the witnessed mechanism does not provide this property")
	ErrEvidenceWitness   = errors.New("agentvm: the run witnessed no kernel, or not the one it declared")
	ErrEvidenceKernel    = errors.New("agentvm: no guest kernel and root filesystem measurement")
	ErrEvidenceFilter    = errors.New("agentvm: no syscall filter was applied")
	ErrEvidenceSignature = errors.New("agentvm: evidence signature missing or not the operator's")
	ErrEvidencePlacement = errors.New("agentvm: the run happened somewhere the workload did not ask for")
	ErrEvidenceMissing   = errors.New("agentvm: no attestation for this answer")

	// the hardware quote
	ErrQuoteMalformed      = errors.New("agentvm: quote does not match a report layout this build knows")
	ErrQuoteKeyNotAdmitted = errors.New("agentvm: quote signed by a key this chain has not admitted")
	ErrQuoteSignature      = errors.New("agentvm: quote signature does not verify")
	ErrQuoteBinding        = errors.New("agentvm: quote was produced for a different run")
	ErrEmptyAttestingKey   = errors.New("agentvm: attesting key digest is empty")

	// the durability claim
	ErrRootEmpty          = errors.New("agentvm: state root is empty")
	ErrRootNotAdmitted    = errors.New("agentvm: pin names a state root this chain has not admitted")
	ErrDurabilityPin      = errors.New("agentvm: durability claim names no stored blob")
	ErrDurabilityReplicas = errors.New("agentvm: too few copies read back at distinct store addresses")
	ErrDurabilityWitness  = errors.New("agentvm: no copy read back the bytes the handle names")
	ErrDurabilityShards   = errors.New("agentvm: shards do not rebuild the handle's coding")

	// the catalog
	ErrCatalogVersion      = errors.New("agentvm: catalog version is zero")
	ErrCatalogGroups       = errors.New("agentvm: catalog groups are empty, unsorted, duplicated or oversized")
	ErrCatalogVersionTaken = errors.New("agentvm: catalog version already registered with a different surface")
	ErrCatalogUnknown      = errors.New("agentvm: catalog digest is not registered")
	ErrCapabilityUnknown   = errors.New("agentvm: catalog does not hold this group")

	// the advertisement
	ErrOperatorUnknown       = errors.New("agentvm: operator is not registered and staked")
	ErrAdvertiseMechanisms   = errors.New("agentvm: advertisement offers no mechanism")
	ErrAdvertisePlacement    = errors.New("agentvm: advertisement names no placement")
	ErrAdvertiseDomain       = errors.New("agentvm: advertisement names no failure domain")
	ErrAdvertiseCapacity     = errors.New("agentvm: advertised capacity is zero or above the protocol bound")
	ErrAdvertiseGroups       = errors.New("agentvm: advertised group is empty, oversized, or absent from the catalog")
	ErrAdvertiseUnauthorized = errors.New("agentvm: advertisement carries no signature recovering to its operator")
	ErrAdvertiseReplay       = errors.New("agentvm: advertisement nonce does not exceed the last one accepted")

	// the task lifecycle
	ErrTaskUnknown     = errors.New("agentvm: task not found")
	ErrTaskNotAgentic  = errors.New("agentvm: task was not opened by agentvm")
	ErrTaskSettled     = errors.New("agentvm: task has already reached a verdict")
	ErrNotSelected     = errors.New("agentvm: operator was not selected for this task")
	ErrAttestNotOpen   = errors.New("agentvm: attestation window not open")
	ErrAttestClosed    = errors.New("agentvm: attestation window closed")
	ErrAlreadyAttested = errors.New("agentvm: operator already attested this task")

	// pricing
	ErrPriceOverflow = errors.New("agentvm: price does not fit in a uint256")
)
