// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package liquidity

import (
	"github.com/luxfi/ids"
)

// GetPoolsByTokenPair returns all pools for a given token pair.
func (m *Manager) GetPoolsByTokenPair(token0, token1 ids.ID) []*Pool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Ensure canonical ordering
	if token0.Compare(token1) > 0 {
		token0, token1 = token1, token0
	}

	pairKey := makePairKey(token0, token1)
	poolID, exists := m.pairToPool[pairKey]
	if !exists {
		return nil
	}

	pool, exists := m.pools[poolID]
	if !exists {
		return nil
	}

	return []*Pool{pool}
}
