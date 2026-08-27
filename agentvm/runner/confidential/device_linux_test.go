// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build linux

package confidential

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/luxfi/chains/agentvm/runner"
)

// TestLayout pins the three structures against linux/include/uapi/linux/
// sev-guest.h. Nothing here talks to hardware, and nothing here needs any: the
// kernel reads these buffers at fixed offsets, so a struct that drifts writes
// the binding somewhere the firmware does not look and returns a report over
// whatever happened to be there.
//
// snp_guest_request_ioctl is 32 bytes and not 25, because none of these
// structures is packed: a __u64 needs 8-byte alignment, so the one-byte version
// field is followed by seven bytes of padding and req_data starts at offset 8.
// The sizes were measured against the header on a machine that has it.
func TestLayout(t *testing.T) {
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"snp_report_req", unsafe.Sizeof(ask{}), 96},
		{"snp_report_resp", unsafe.Sizeof(reply{}), 4000},
		{"snp_guest_request_ioctl", unsafe.Sizeof(call{}), 32},
	} {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d, want %d (drift from linux/sev-guest.h)", c.name, c.got, c.want)
		}
	}

	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"msg_version", unsafe.Offsetof(call{}.Version), 0},
		{"req_data", unsafe.Offsetof(call{}.Ask), 8},
		{"resp_data", unsafe.Offsetof(call{}.Reply), 16},
		{"exitinfo", unsafe.Offsetof(call{}.Exit), 24},
		{"vmpl", unsafe.Offsetof(ask{}.VMPL), 64},
	} {
		if c.got != c.want {
			t.Errorf("offsetof(%s) = %d, want %d (drift from linux/sev-guest.h)", c.name, c.got, c.want)
		}
	}
}

// TestNumber pins SNP_GET_REPORT. The size of the argument structure is part of
// the ioctl number, so this is the same assertion as the one above arriving by
// a different road: a 24-byte call would produce 0xc0185300 and the kernel
// would answer ENOTTY.
func TestNumber(t *testing.T) {
	const want = 0xc0205300
	if getReport != want {
		t.Errorf("SNP_GET_REPORT = %#x, want %#x", getReport, want)
	}
}

// TestNewGuestWithoutHardware is the path every machine without SEV-SNP takes.
// The device must be refused at construction, so no attestor is built over it
// and no run ever asks it for a quote.
func TestNewGuestWithoutHardware(t *testing.T) {
	g, err := NewGuest(vcek())
	if err == nil {
		t.Cleanup(func() { g.Close() })
		// This machine has the device. Then the constructor is right to have
		// succeeded, and there is nothing to refuse.
		return
	}
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("NewGuest on a machine without %s = %v, want ErrUnavailable", node, err)
	}
}
