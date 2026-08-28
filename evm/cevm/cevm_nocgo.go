//go:build !cgo || !lux_cevm_native

// Pure-Go path, used whenever the native luxcpp EVM is NOT linked in —
// i.e. the default build (cgo without `-tags=lux_cevm_native`) and any
// no-cgo build. Opt in with `-tags=lux_cevm_native` (see cevm_cgo.go)
// once the lux-cevm pkg-config bundle is installed.

package cevm

import "fmt"

// No library linked, so there is no ABI to report.
const ABIVersion uint32 = 0

// AutoDetect returns CPUSequential: with no library there is no lane to detect.
func AutoDetect() Backend { return CPUSequential }

// AvailableBackends returns CPUSequential alone — the only lane a build with no
// library has, and it cannot execute either.
func AvailableBackends() []Backend { return []Backend{CPUSequential} }

// BackendName uses the local Go-side string; there is no library to ask.
func BackendName(b Backend) string { return b.String() }

// LibraryABIVersion returns the Go-side constant when there's no library.
func LibraryABIVersion() uint32 { return ABIVersion }

// ExecuteBlock returns an error when built without CGo. Mirrors the V4
// cgo signature so consumers can call it unconditionally.
func ExecuteBlock(backend Backend, numThreads uint32, txs []Transaction, ctx *BlockContext, state []StateAccount) (*BlockResult, error) {
	if len(txs) == 0 {
		return &BlockResult{ABIVersion: ABIVersion}, nil
	}
	_ = ctx
	_ = state
	return nil, fmt.Errorf("cevm: cannot execute %d transactions: %w", len(txs), ErrNotLinked)
}

// HealthProbeResult mirrors the cgo build's struct so consumers see the same
// API surface either way. Under nocgo the slice is always empty.
type HealthProbeResult struct {
	Name    string
	OK      bool
	GasUsed uint64
	Status  TxStatus
	Err     error
}

// HealthReport is the per-backend result of Health(). The nocgo build only
// reports CPUSequential and never executes — it returns OK=false with an
// explanatory error and an empty ProbeResults slice.
type HealthReport struct {
	Backend      Backend
	Name         string
	OK           bool
	Err          error
	Probe        string
	ProbesRun    int
	ProbeResults []HealthProbeResult
	GasUsed      uint64
	Status       TxStatus
	ExecTime     float64
}

// Health returns a single non-OK report naming the reason nothing can execute.
//
// The reason used to read "built without CGo", which is wrong on the default
// build: cgo is on, and what is missing is the lux_cevm_native tag and the
// luxcpp bundle behind it. An operator reading it went and checked
// CGO_ENABLED, which was already 1.
func Health() []HealthReport {
	return []HealthReport{{
		Backend: CPUSequential,
		Name:    CPUSequential.String(),
		OK:      false,
		Err:     ErrNotLinked,
	}}
}
