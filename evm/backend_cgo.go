//go:build cgo

// Backend selection (cgo build): wire the C++ EVM (cevm) into the
// parallel-execution registry and pick the best available backend.
//
// Linking the github.com/luxfi/chains/evm/cevm package under cgo brings in the
// luxcpp/cevm shared libraries (libevm, libevm-gpu, libluxgpu,
// libcevm_precompiles), which is the prerequisite for cevm-based
// execution.
//
// Whether cevm is actually selected depends on the upstream luxfi/evm
// build tags: the C++ executor is registered by core/parallel only when
// luxfi/evm is itself built with `-tags cevm`. In that case AutoEVM
// resolves to CppEVM. Otherwise AutoEVM falls back to GoEVM (geth) — the
// pure-Go path — without losing the GPU ecrecover bridge that is
// registered separately under `cgo && darwin`.
package main

import (
	"github.com/luxfi/chains/evm/cevm"
	"github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/log"
)

func selectExecutionBackend(logger log.Logger) {
	parallel.SetBackend(parallel.AutoEVM)
	logger.Info("EVM execution backend selected",
		"active", parallel.ActiveBackend(),
		"available", parallel.AvailableBackends(),
		"cevm-abi", cevm.LibraryABIVersion(),
		"cevm-backends", cevm.AvailableBackends(),
	)
	for _, h := range cevm.Health() {
		if h.OK {
			logger.Info("cevm backend healthy",
				"backend", h.Name, "probes", h.ProbesRun, "gas", h.GasUsed)
			continue
		}
		logger.Warn("cevm backend not healthy",
			"backend", h.Name, "probe", h.Probe, "err", h.Err)
	}
}
