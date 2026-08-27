// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package firecracker

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/chains/agentvm/runner"
)

// spam is what a guest kernel writes on the console before init says anything.
const spam = "[    0.000000] Linux version 5.10.0\n[    0.121000] Run /init as init process\n"

// frame renders what a guest init writes around an answer.
func frame(body []byte, exit string) string {
	return begin + "\n" + base64.StdEncoding.EncodeToString(body) + "\n" + end + exit + "\n"
}

func TestParse(t *testing.T) {
	want := []byte("the answer\n")
	body, exit, err := parse([]byte(spam + frame(want, "0")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(body) != string(want) {
		t.Fatalf("output %q, want %q", body, want)
	}
	if exit != 0 {
		t.Fatalf("exit %d, want 0", exit)
	}
}

func TestParseExit(t *testing.T) {
	_, exit, err := parse([]byte(frame([]byte("failed"), "17")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if exit != 17 {
		t.Fatalf("exit %d, want 17", exit)
	}
}

func TestParseSplitBody(t *testing.T) {
	// A serial console wraps, so the body arrives as many lines and is one
	// value.
	want := strings.Repeat("output ", 40)
	coded := base64.StdEncoding.EncodeToString([]byte(want))
	var lines strings.Builder
	lines.WriteString(begin + "\n")
	for len(coded) > 0 {
		n := min(76, len(coded))
		lines.WriteString(coded[:n] + "\r\n")
		coded = coded[n:]
	}
	lines.WriteString(end + "0\r\n")

	body, exit, err := parse([]byte(lines.String()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(body) != want {
		t.Fatalf("output %q, want %q", body, want)
	}
	if exit != 0 {
		t.Fatalf("exit %d", exit)
	}
}

func TestParseEmptyBody(t *testing.T) {
	// A run that wrote nothing and exited cleanly is a complete frame. Whether
	// an empty answer is usable is the runner's question, not the parser's.
	body, exit, err := parse([]byte(frame(nil, "0")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(body) != 0 || exit != 0 {
		t.Fatalf("output %q exit %d, want an empty clean frame", body, exit)
	}
}

func TestParseRefusesTruncated(t *testing.T) {
	// The VM died mid-answer. Everything up to the cut looks perfect, which is
	// exactly why the closing line has to be required.
	cut := spam + begin + "\n" + base64.StdEncoding.EncodeToString([]byte("half an ans"))
	if _, _, err := parse([]byte(cut)); !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("error %v, want ErrFailed", err)
	}
}

func TestParseRefusesSilence(t *testing.T) {
	if _, _, err := parse([]byte(spam)); !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("error %v, want ErrFailed", err)
	}
	if _, _, err := parse(nil); !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("error %v, want ErrFailed", err)
	}
}

func TestParseRefusesUnclosedExit(t *testing.T) {
	if _, _, err := parse([]byte(begin + "\n" + end + "\n")); !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("error %v, want ErrFailed", err)
	}
	if _, _, err := parse([]byte(begin + "\nAA==\n" + end + "later\n")); !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("error %v, want ErrFailed", err)
	}
}

func TestParseRefusesGarbledBody(t *testing.T) {
	// Serial lines drop bytes. A body that is not what the guest encoded is not
	// a shorter answer, it is no answer.
	if _, _, err := parse([]byte(begin + "\nnot base64 at all!\n" + end + "0\n")); !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("error %v, want ErrFailed", err)
	}
}

func TestConsoleWaitsForWholeLine(t *testing.T) {
	c := listen()
	if _, err := c.Write([]byte(spam + begin + "\nAAAA\n")); err != nil {
		t.Fatal(err)
	}
	if c.finished() {
		t.Fatal("console closed before the guest said it was done")
	}
	// The exit status is on the closing line, so the line is not a frame until
	// it ends.
	if _, err := c.Write([]byte(end)); err != nil {
		t.Fatal(err)
	}
	if c.finished() {
		t.Fatal("console closed on a closing line that carried no status")
	}
	if _, err := c.Write([]byte("2\n")); err != nil {
		t.Fatal(err)
	}
	<-c.done()

	body, exit, err := parse(c.bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if exit != 2 {
		t.Fatalf("exit %d, want 2", exit)
	}
	if string(body) != "\x00\x00\x00" {
		t.Fatalf("output %q", body)
	}
}
