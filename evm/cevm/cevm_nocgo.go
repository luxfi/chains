//go:build !cgo

package cevm

import "fmt"

// No library linked, so there is no ABI to report.
const ABIVersion uint32 = 0

// AutoDetect returns CPUSequential when built without CGo.
func AutoDetect() Backend { return CPUSequential }

// AvailableBackends returns CPUSequential only when built without CGo.
func AvailableBackends() []Backend { return []Backend{CPUSequential} }

// BackendName uses the local Go-side string when CGo is off.
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
	return nil, fmt.Errorf("cevm: built without CGo, cannot execute transactions (rebuild with CGO_ENABLED=1)")
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

// Health returns a single non-OK report indicating CGo is disabled.
func Health() []HealthReport {
	return []HealthReport{{
		Backend: CPUSequential,
		Name:    CPUSequential.String(),
		OK:      false,
		Err:     fmt.Errorf("cevm: built without CGo, no backends executable"),
	}}
}
