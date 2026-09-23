// What this binary can execute with: the C++ library's ABI, the backends it
// offers, and what each answered to the health battery.
//
// There is nothing to select. Choosing an EVM is choosing which plugin binary
// the host runs, not a switch inside the Go EVM, so this only says what came
// up. The cevm package carries its own build tags, so one file serves every
// build: without the native library linked it reports the one backend it has.
package main

import (
	"errors"

	"github.com/luxfi/chains/evm/cevm"
	"github.com/luxfi/log"
)

func reportCevm(logger log.Logger) {
	abi := cevm.LibraryABIVersion()
	logger.Info("cevm linked", "abi", abi, "backends", cevm.AvailableBackends())
	if abi != cevm.ABIVersion {
		// Every block is declined, so no lane has anything to report.
		logger.Warn("cevm library speaks another ABI; the Go EVM runs every block",
			"library", abi, "reads", cevm.ABIVersion)
		return
	}
	reportHealth(logger, cevm.Health())
}

// reportHealth says what the backends answered to the health battery.
//
// A lane that runs no block in any build of this kind is said once, at info:
// a CPU lane, which cevm's Go entry passes no host and so runs nothing on,
// and the one lane of a build with no library. That is what the lane is, not
// something that went wrong, and a warning every start would bury the ones
// that did. Every other lane is reported on its own.
func reportHealth(logger log.Logger, reports []cevm.HealthReport) {
	var idle []string
	for _, h := range reports {
		if runsNothing(h) {
			idle = append(idle, h.Name)
			continue
		}
		report(logger, h)
	}
	if len(idle) > 0 {
		logger.Info("cevm runs no block on these backends; the Go EVM does", "backends", idle)
	}
}

// runsNothing reports whether h is a lane that runs no block by what it is: a
// CPU lane that declined, or a lane with no library behind it.
func runsNothing(h cevm.HealthReport) bool {
	if h.OK {
		return false
	}
	if errors.Is(h.Err, cevm.ErrNotLinked) {
		return true
	}
	cpu := h.Backend == cevm.CPUSequential || h.Backend == cevm.CPUParallel
	return cpu && errors.Is(h.Err, cevm.ErrDeclined)
}

// report says what one cevm backend answered to the health battery: at info
// when it ran it, and at warn, with the probe and the reason, when it did not.
// A GPU lane that declines the battery's funded transfer has no device, or a
// device that does not work, and the Go EVM is running every block it would.
func report(logger log.Logger, h cevm.HealthReport) {
	if h.OK {
		logger.Info("cevm backend healthy",
			"backend", h.Name, "probes", h.ProbesRun, "gas", h.GasUsed)
		return
	}
	logger.Warn("cevm backend not healthy",
		"backend", h.Name, "probe", h.Probe, "err", h.Err)
}
