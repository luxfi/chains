//go:build !cgo

// Backend selection (nocgo build): no C++ EVM is linkable, so we leave
// the parallel-execution registry on its zero value (GoEVM = pure-Go
// geth interpreter). This is the portable fallback for builds without
// the luxcpp/cevm shared libraries.
package main

import (
	"github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/log"
)

func selectExecutionBackend(logger log.Logger) {
	parallel.SetBackend(parallel.GoEVM)
	logger.Info("EVM execution backend selected (nocgo)",
		"active", parallel.ActiveBackend(),
		"available", parallel.AvailableBackends(),
	)
}
