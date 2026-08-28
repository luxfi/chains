// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// B learns of a bridge from the source chain itself: a gateway emits Locked when
// value is locked, and B routes an attested release to the destination. Until
// something reads those events there is nothing for a block to carry, so the
// chain sits at genesis no matter how much is bridged through the gateways.
//
// This is that reader.

const (
	// watchInterval is how often each chain is asked what it has locked.
	// Bridges are not latency-critical — a release still has to be attested by
	// M and broadcast — so this is set for cheap polling rather than speed.
	watchInterval = 5 * time.Second

	// minWatchLag is how far behind its head a chain is read at the very
	// least. A lock that a reorg takes back must never become a request, and a
	// request is only ever created once, so B reads only what the source chain
	// is unlikely to reconsider. The chain's own MinConfirmations raises this
	// when it asks for more.
	minWatchLag = 12

	// watchSpan bounds one pass. A node that has been down for a week asks for
	// its backlog a piece at a time rather than in one query no endpoint will
	// answer.
	watchSpan = 2000
)

// lockSource is the part of a chain client this needs: where the chain has got
// to, and what it locked over a range of its blocks. Narrow on purpose — a
// client that cannot answer these is simply not a source of locks.
type lockSource interface {
	HeadBlock(ctx context.Context) (uint64, error)
	FetchLockEvents(ctx context.Context, from, to *big.Int) ([]lock, error)
}

// lock is one Locked event: the transfer it authorises, and the transaction it
// was emitted by.
type lock struct {
	Transfer bridgeattest.BridgeTransfer
	TxID     ids.ID
	Block    uint64
}

// watcher turns what the source chains locked into requests a block can carry.
type watcher struct {
	vm     *VM
	cursor map[uint32]uint64 // chain id -> last block read
	quit   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

func newWatcher(vm *VM, chains []ExternalChainConfig) *watcher {
	w := &watcher{
		vm:     vm,
		cursor: make(map[uint32]uint64, len(chains)),
		quit:   make(chan struct{}),
	}
	w.wg.Add(1)
	go w.run()
	return w
}

func (w *watcher) stop() {
	w.once.Do(func() { close(w.quit) })
	w.wg.Wait()
}

func (w *watcher) run() {
	defer w.wg.Done()
	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.quit:
			return
		case <-ticker.C:
			w.pass()
		}
	}
}

// pass reads each source chain once. A chain that cannot be reached is left for
// the next pass with its cursor untouched, so nothing is skipped by an endpoint
// having a bad minute.
func (w *watcher) pass() {
	ctx, cancel := context.WithTimeout(context.Background(), watchInterval)
	defer cancel()

	w.vm.mu.RLock()
	clients := make(map[uint32]ChainClient, len(w.vm.evmByChainID))
	for id, c := range w.vm.evmByChainID {
		clients[id] = c
	}
	w.vm.mu.RUnlock()

	for id, client := range clients {
		source, ok := client.(lockSource)
		if !ok {
			continue
		}
		if err := w.read(ctx, id, source); err != nil {
			w.vm.log.Debug("bridgevm: watch pass failed",
				log.Uint32("chain", id), log.String("err", err.Error()))
		}
	}
}

// lag is how far behind a source chain's head this node reads.
//
// It is the deeper of the reorg margin and what the chain's own configuration
// demands, so anything read is by construction buried deep enough to be
// carried. Reading at a fixed margin and stamping each request with the depth
// it happened to have at that moment left a transfer observed at depth 12 by a
// chain requiring 100 permanently ineligible: the depth was never revisited and
// the cursor had already moved past the lock.
func (w *watcher) lag() uint64 {
	if conf := uint64(w.vm.config.MinConfirmations); conf > minWatchLag {
		return conf
	}
	return minWatchLag
}

func (w *watcher) read(ctx context.Context, chain uint32, source lockSource) error {
	head, err := source.HeadBlock(ctx)
	if err != nil {
		return err
	}
	lag := w.lag()
	if head < lag {
		return nil
	}
	to := head - lag

	from, seen := w.cursor[chain]
	if !seen {
		// First sight of this chain. Start at the settled head rather than at
		// its genesis: anything locked before B was watching was either already
		// released or is not B's to release now, and the destination gateway is
		// the authority on which.
		w.cursor[chain] = to
		return nil
	}
	if to <= from {
		return nil
	}
	from++
	if to-from >= watchSpan {
		to = from + watchSpan - 1
	}

	locks, err := source.FetchLockEvents(ctx, new(big.Int).SetUint64(from), new(big.Int).SetUint64(to))
	if err != nil {
		return err
	}
	for _, l := range locks {
		w.enqueue(l)
	}
	w.cursor[chain] = to
	return nil
}

// enqueue turns a lock into a request a block can carry. The transfer's digest
// is its identity: it is what M signs, what the destination gateway keys its
// replay guard by, and what this chain names the request, so two chains reusing
// a nonce cannot collide and the same lock read twice is the same request.
func (w *watcher) enqueue(l lock) {
	transfer := l.Transfer
	id := ids.ID(transfer.Digest())

	req := &BridgeRequest{
		ID:         id,
		SrcChainID: transfer.SrcChainID,
		DstChainID: transfer.DstChainID,
		Nonce:      transfer.Nonce,
		Asset:      ids.ID(transfer.Asset),
		Amount:     transfer.Amount,
		Recipient:  append([]byte(nil), transfer.Recipient[:]...),
		SourceTxID: l.TxID,
	}

	// A lock this chain can never carry is not held: it would be proposed,
	// refused, and proposed again for as long as the node runs. What can be
	// decided without the chain's state is decided here, once.
	if err := admissible(&w.vm.config, req); err != nil {
		w.vm.log.Warn("bridgevm: lock not admitted",
			log.Stringer("requestID", id), log.String("reason", err.Error()))
		return
	}

	w.vm.mu.Lock()
	if _, pending := w.vm.pendingBridges[id]; pending {
		w.vm.mu.Unlock()
		return
	}
	w.vm.pendingBridges[id] = req
	w.vm.mu.Unlock()

	w.vm.log.Info("bridgevm: lock observed",
		log.Stringer("requestID", id),
		log.Uint32("src", transfer.SrcChainID),
		log.Uint32("dst", transfer.DstChainID),
		log.Uint64("nonce", transfer.Nonce),
	)
	w.vm.work.Signal()
}
