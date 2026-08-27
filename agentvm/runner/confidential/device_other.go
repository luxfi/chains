// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !linux

package confidential

// device_other.go is the SEV-SNP guest device everywhere it does not exist.
// /dev/sev-guest and SNP_GET_REPORT are a Linux interface, so on any other
// system the constructor refuses and no attestor is built over it. The type is
// present so callers compile identically on every platform and discover the
// absence where every other absent mechanism is discovered: at construction.

import (
	"fmt"
	"runtime"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// Guest is the SEV-SNP guest device, which this system does not have.
type Guest struct{}

var _ Device = (*Guest)(nil)

// NewGuest refuses: there is no guest device to open here. The key is checked
// first all the same, so a badly shaped VCEK is the same error on every system
// and only the absence of hardware differs.
func NewGuest(vcek []byte) (*Guest, error) {
	if err := checkKey(vcek); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: the sev-snp guest device is a linux interface, this is %s",
		runner.ErrUnavailable, runtime.GOOS)
}

// Kind is the report layout AMD hardware produces.
func (g *Guest) Kind() agentvm.QuoteKind { return agentvm.QuoteSEVSNP }

// Close has nothing to release.
func (g *Guest) Close() error { return nil }

// Quote refuses. A Guest cannot be constructed on this system, so reaching here
// means one was fabricated rather than opened, and it has no hardware to ask.
func (g *Guest) Quote(binding common.Hash) (agentvm.Quote, error) {
	return agentvm.Quote{}, fmt.Errorf("%w: the sev-snp guest device is a linux interface, this is %s",
		runner.ErrUnavailable, runtime.GOOS)
}
