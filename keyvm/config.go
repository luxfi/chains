// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import "encoding/json"

// Config is the K-Chain's per-chain configuration, supplied by the node as the
// chain's config blob. It carries the network the chain is part of and nothing
// else: the gas schedule, the gas price, the authorization model and the
// threshold parameters of a key are CONSENSUS RULES or per-key transaction
// fields, not deployment knobs — a validator that could tune them locally would
// compute a different block than its peers.
//
// The 25-field config this replaces declared exactly one field the VM ever read
// (this one), plus a threshold/validator/algorithm surface duplicated by the
// per-key record and the gas schedule, plus a ShareCacheSize for a VM whose
// defining invariant is that it never holds a share.
type Config struct {
	NetworkID uint32 `json:"networkId"`
}

// ParseConfig decodes the node-supplied chain config. An empty blob is the
// zero config, which takes the network id from the consensus runtime.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	if len(data) == 0 {
		return c, nil
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}
