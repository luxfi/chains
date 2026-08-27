// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package confidential

// report.go reads an AMD SEV-SNP guest response and turns it into the quote
// shape the chain verifies. It touches no device, so the layout is testable
// everywhere and the only platform-specific code left is the ioctl itself.
//
// Two layouts meet here, both fixed by AMD:
//
//	msg_report_resp        status(4, LE) | report_size(4, LE) | rsvd[24] | report[]
//	ATTESTATION_REPORT     signed span [0, 0x2A0); signature at 0x2A0 as two
//	                       72-byte slots, r then s, each LITTLE-endian
//
// The signature is where the two worlds disagree. AMD writes each component
// little-endian into a 72-byte slot; every ECDSA verifier, including the one in
// agentvm/quote.go, reads r||s big-endian at the curve's field width, which for
// P-384 is 48 bytes. The conversion is a byte reversal of the low 48, and the
// high 24 bytes must be zero: a component that does not fit in the field is not
// a P-384 signature, and taking the low bytes anyway would hand the verifier a
// different number than the hardware signed with.

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/chains/agentvm"
)

var (
	// ErrReport means the guest response does not hold a report this build can
	// read.
	ErrReport = errors.New("agentvm/runner/confidential: malformed attestation report")
	// ErrKey means the supplied attesting key is not an uncompressed P-384
	// point.
	ErrKey = errors.New("agentvm/runner/confidential: attesting key is not an uncompressed p-384 point")
)

// Offsets and widths of the AMD layouts. Nothing outside this file knows them.
const (
	// head is the msg_report_resp preamble before the ATTESTATION_REPORT.
	head = 32
	// span is the length of the report bytes the hardware signs.
	span = 0x2A0
	// slotR and slotS are where the two signature components sit.
	slotR = 0x2A0
	slotS = 0x2E8
	// slot is the width AMD reserves for each component.
	slot = 72
	// width is the P-384 field width, so a signature is 2*width big-endian.
	width = 48
	// point is the length of an uncompressed SEC1 P-384 public key.
	point = 97
	// least is the shortest report that carries both signature components.
	least = slotS + slot
)

// element converts one signature component from AMD's little-endian slot to the
// big-endian field element a verifier reads. A component with a non-zero byte
// above the field width is refused, because truncating it would silently change
// the number.
func element(le []byte) ([]byte, error) {
	if len(le) != slot {
		return nil, fmt.Errorf("%w: signature component is %d bytes, want %d", ErrReport, len(le), slot)
	}
	for i := width; i < slot; i++ {
		if le[i] != 0 {
			return nil, fmt.Errorf("%w: signature component exceeds the p-384 field at byte %d", ErrReport, i)
		}
	}
	be := make([]byte, width)
	for i := 0; i < width; i++ {
		be[i] = le[width-1-i]
	}
	return be, nil
}

// checkKey refuses an attesting key that is not the shape a P-384 verifier
// parses. The VCEK is fetched from AMD's key distribution service out of band,
// so the guest never learns it from the device and cannot be trusted to have
// been handed the right shape.
func checkKey(key []byte) error {
	if len(key) != point {
		return fmt.Errorf("%w: %d bytes, want %d", ErrKey, len(key), point)
	}
	if key[0] != 4 {
		return fmt.Errorf("%w: leading byte is %#x, want 0x04", ErrKey, key[0])
	}
	return nil
}

// parse reads a guest response into a quote, under the given attesting key.
func parse(resp []byte, key []byte) (agentvm.Quote, error) {
	if err := checkKey(key); err != nil {
		return agentvm.Quote{}, err
	}
	if len(resp) < head {
		return agentvm.Quote{}, fmt.Errorf("%w: response is %d bytes, shorter than its own header", ErrReport, len(resp))
	}
	if st := binary.LittleEndian.Uint32(resp[0:4]); st != 0 {
		return agentvm.Quote{}, fmt.Errorf("%w: firmware reports status %d", ErrReport, st)
	}
	size := int(binary.LittleEndian.Uint32(resp[4:8]))
	if size < least {
		return agentvm.Quote{}, fmt.Errorf("%w: report is %d bytes, want at least %d", ErrReport, size, least)
	}
	if size > len(resp)-head {
		return agentvm.Quote{}, fmt.Errorf("%w: report claims %d bytes, response holds %d", ErrReport, size, len(resp)-head)
	}
	body := resp[head : head+size]

	r, err := element(body[slotR : slotR+slot])
	if err != nil {
		return agentvm.Quote{}, err
	}
	s, err := element(body[slotS : slotS+slot])
	if err != nil {
		return agentvm.Quote{}, err
	}

	return agentvm.Quote{
		Kind:      agentvm.QuoteSEVSNP,
		Report:    append([]byte(nil), body[:span]...),
		Key:       append([]byte(nil), key...),
		Signature: append(r, s...),
	}, nil
}
