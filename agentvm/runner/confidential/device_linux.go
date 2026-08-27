// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build linux

package confidential

// device_linux.go is the AMD SEV-SNP guest device: open /dev/sev-guest and
// issue SNP_GET_REPORT. It is the only file in the package that talks to a
// kernel; reading the bytes that come back is report.go's job.
//
// The three structures are linux/include/uapi/linux/sev-guest.h verbatim, at C
// alignment. None of them is packed, so snp_guest_request_ioctl pays seven
// bytes of padding after its one-byte version field before the first __u64.
// That padding is load bearing twice over: the kernel reads req_data at offset
// 8, and the ioctl number encodes the structure's size, so a Go struct one word
// short would produce a different ioctl number and the kernel would answer
// ENOTTY. The number is derived here from unsafe.Sizeof for exactly that
// reason, and layout_test.go pins both the sizes and the resulting number.

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// node is where the kernel exposes the guest interface.
const node = "/dev/sev-guest"

// ask is struct snp_report_req: the 64 bytes the report is bound to, and the
// privilege level to report at.
type ask struct {
	Data [64]byte
	VMPL uint32
	Rsvd [28]byte
}

// reply is struct snp_report_resp: a fixed buffer the firmware writes a
// msg_report_resp into.
type reply struct {
	Data [4000]byte
}

// call is struct snp_guest_request_ioctl: the message version, the addresses of
// the two buffers above, and the error word the firmware and the hypervisor
// write back. The blank field is the alignment padding a C compiler inserts.
type call struct {
	Version uint8
	_       [7]byte
	Ask     uint64
	Reply   uint64
	Exit    uint64
}

// The ioctl direction bits, from linux/include/uapi/asm-generic/ioctl.h.
const (
	iocWrite  = 1
	iocRead   = 2
	dirShift  = 30
	sizeShift = 16
	kindShift = 8
)

// number builds an ioctl number that both reads and writes its argument.
func number(kind byte, nr byte, size uintptr) uintptr {
	return (iocRead|iocWrite)<<dirShift | size<<sizeShift | uintptr(kind)<<kindShift | uintptr(nr)
}

// getReport is SNP_GET_REPORT, derived from the structure it carries so the two
// cannot drift apart.
var getReport = number('S', 0x0, unsafe.Sizeof(call{}))

// Guest is the SEV-SNP guest device on this machine.
type Guest struct {
	file *os.File
	key  []byte
}

var _ Device = (*Guest)(nil)

// NewGuest opens the guest device. The VCEK is supplied rather than read from
// the device because the device does not hold it: the certificate that proves a
// VCEK belongs to genuine AMD silicon comes from AMD's key distribution
// service, over the network, and the guest only ever gets the report.
//
// A machine without the device returns ErrUnavailable, so an attestor over it
// is never constructed and never enters a selection.
func NewGuest(vcek []byte) (*Guest, error) {
	if err := checkKey(vcek); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(node, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", runner.ErrUnavailable, err)
	}
	return &Guest{file: file, key: append([]byte(nil), vcek...)}, nil
}

// Kind is the report layout AMD hardware produces.
func (g *Guest) Kind() agentvm.QuoteKind { return agentvm.QuoteSEVSNP }

// Close releases the device.
func (g *Guest) Close() error { return g.file.Close() }

// Quote asks the firmware for a report bound to this value.
//
// The binding goes in the LOW 32 bytes of the 64-byte user data field, which is
// where agentvm.Quote.Binding reads it back out of REPORT_DATA. The report is
// requested at privilege level 0, which is where a guest runs when no service
// module sits beneath it.
//
// Both buffers are pinned for the duration of the ioctl. Their addresses ride
// inside a structure rather than as syscall arguments, so the compiler's own
// rule about pointers converted at a call site does not cover them.
func (g *Guest) Quote(binding common.Hash) (agentvm.Quote, error) {
	var req ask
	copy(req.Data[32:], binding[:])
	var resp reply

	var pin runtime.Pinner
	pin.Pin(&req)
	pin.Pin(&resp)
	defer pin.Unpin()

	arg := call{
		Version: 1,
		Ask:     uint64(uintptr(unsafe.Pointer(&req))),
		Reply:   uint64(uintptr(unsafe.Pointer(&resp))),
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, g.file.Fd(), getReport, uintptr(unsafe.Pointer(&arg)))
	if errno != 0 {
		return agentvm.Quote{}, fmt.Errorf("agentvm/runner/confidential: %s: %w", node, errno)
	}
	if arg.Exit != 0 {
		return agentvm.Quote{}, fmt.Errorf("agentvm/runner/confidential: %s: firmware error %#x, hypervisor error %#x",
			node, uint32(arg.Exit), uint32(arg.Exit>>32))
	}
	return parse(resp.Data[:], g.key)
}
