//go:build cgo && lux_cevm_native

package cevm

import "testing"

// The block context reaches the device path and is read there: the same
// funded transfer that a device runs is declined when the block's base fee is
// above its price, and when the block's gas limit cannot hold its limit.
// Either would be run as a valid transfer by a path that dropped the context.
func TestTheBlockContextReachesTheDevice(t *testing.T) {
	for _, b := range deviceLanes(t) {
		t.Run(BackendName(b), func(t *testing.T) {
			txs, ctx, state := transfers(1)
			r, err := ExecuteBlock(b, 0, txs, &ctx, state)
			ranTransfers(t, r, err, 1)

			priced := ctx
			priced.BaseFee = txs[0].GasPrice + 1
			r, err = ExecuteBlock(b, 0, txs, &priced, state)
			declined(t, r, err)

			full := ctx
			full.GasLimit = txs[0].GasLimit - 1
			r, err = ExecuteBlock(b, 0, txs, &full, state)
			declined(t, r, err)
		})
	}
}
