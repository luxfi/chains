// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package firecracker

// console.go is the only channel out of the guest, and the frame that makes it
// readable.
//
// A microVM has no pipe to its guest process. What it has is a serial port, and
// everything the guest kernel and its init write lands on the same stream mixed
// together. So the guest brackets its answer: a begin line, the output in
// base64 one line at a time, and an end line carrying the exit status. Base64
// because a serial console mangles anything that looks like a control byte, and
// an explicit end line because a stream that simply stopped is a truncated
// stream, not a short answer.
//
// The parser refuses a frame that never closed. A partial frame is what a
// crashed guest, a killed VM and a full disk all look like, and none of those
// produced a result.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/luxfi/chains/agentvm/runner"
)

// The frame markers the guest init writes around its answer.
const (
	begin = "---agentvm-begin---"
	end   = "---agentvm-end---"
)

// parse reads the guest's answer out of the serial stream and returns the
// output and the exit status. Everything before the begin line is the kernel
// talking to itself and is discarded.
func parse(stream []byte) ([]byte, uint32, error) {
	lines := strings.Split(string(stream), "\n")
	open := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == begin {
			open = i
			break
		}
	}
	if open < 0 {
		return nil, 0, fmt.Errorf("%s: %w: console carried no frame", name, runner.ErrFailed)
	}
	var body strings.Builder
	for _, l := range lines[open+1:] {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, end) {
			code, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(l, end)), 10, 32)
			if err != nil {
				return nil, 0, fmt.Errorf("%s: %w: frame closed with %q", name, runner.ErrFailed, l)
			}
			out, err := base64.StdEncoding.DecodeString(body.String())
			if err != nil {
				return nil, 0, fmt.Errorf("%s: %w: frame body: %v", name, runner.ErrFailed, err)
			}
			return out, uint32(code), nil
		}
		if l == "" {
			continue
		}
		body.WriteString(l)
	}
	return nil, 0, fmt.Errorf("%s: %w: frame never closed", name, runner.ErrFailed)
}

// sink is a buffer the VMM writes to from its own goroutine while the run reads
// it, so the bytes are held under a lock.
type sink struct {
	lock sync.Mutex
	seen bytes.Buffer
}

// Write appends to the buffer.
func (s *sink) Write(p []byte) (int, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.seen.Write(p)
}

// bytes is a copy of everything written so far.
func (s *sink) bytes() []byte {
	s.lock.Lock()
	defer s.lock.Unlock()
	return append([]byte(nil), s.seen.Bytes()...)
}

// console is the guest's serial output: a sink that also notices when the guest
// has closed its frame.
type console struct {
	sink
	shut   chan struct{}
	closed bool
}

// listen builds a console ready to be attached to a VMM's standard output.
func listen() *console {
	return &console{shut: make(chan struct{})}
}

// Write takes serial output and closes the console once the guest has written a
// complete end line. The newline matters: the exit status is on that line, so a
// frame is finished only when the line is.
func (c *console) Write(p []byte) (int, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	n, err := c.seen.Write(p)
	if !c.closed {
		if i := bytes.Index(c.seen.Bytes(), []byte(end)); i >= 0 {
			if bytes.IndexByte(c.seen.Bytes()[i:], '\n') >= 0 {
				c.closed = true
				close(c.shut)
			}
		}
	}
	return n, err
}

// done is closed when the guest has written a complete end line.
func (c *console) done() <-chan struct{} { return c.shut }

// finished reports whether the guest closed its frame, without waiting.
func (c *console) finished() bool {
	select {
	case <-c.shut:
		return true
	default:
		return false
	}
}
