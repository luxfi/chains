// What this binary can execute with: the C++ library's ABI, the backends it
// offers, and what each answered to the health battery.
//
// There is nothing to select. Choosing an EVM is choosing which plugin binary
// the host runs, not a switch inside the Go EVM, so this only says what came
// up. The cevm package carries its own build tags, so one file serves every
// build: without the native library linked it reports the one backend it has.
package main

import (
	"github.com/luxfi/chains/evm/cevm"
	"github.com/luxfi/log"
)

func reportCevm(logger log.Logger) {
	logger.Info("cevm linked",
		"abi", cevm.LibraryABIVersion(),
		"backends", cevm.AvailableBackends(),
	)
	for _, h := range cevm.Health() {
		report(logger, h)
	}
}

// report says what one cevm backend answered to the health battery.
//
// It is separate from the report above because it is the only part that
// depends on what the health check found: a build with no library linked has
// exactly one report and it is never healthy, so a check folded into the loop
// could only ever be read one way.
func report(logger log.Logger, h cevm.HealthReport) {
	if h.OK {
		logger.Info("cevm backend healthy",
			"backend", h.Name, "probes", h.ProbesRun, "gas", h.GasUsed)
		return
	}
	logger.Warn("cevm backend not healthy",
		"backend", h.Name, "probe", h.Probe, "err", h.Err)
}
