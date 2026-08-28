// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/chains/evm/cevm"
	"github.com/luxfi/log"
)

// A backend that answered the health battery is reported at info; one that did
// not is reported at warn, carrying the probe that failed and the reason.
//
// The level is the whole point: an operator's alerting reads it, and a backend
// that cannot execute a block reported at info is a chain that will not run
// with nothing raised about it.
func TestAnUnhealthyBackendIsReportedAtWarnWithItsReason(t *testing.T) {
	var buf bytes.Buffer
	logger := log.NewWriter(&buf)

	report(logger, cevm.HealthReport{
		Backend: cevm.GPUCUDA,
		Name:    "gpu-cuda",
		OK:      false,
		Probe:   "storage",
		Err:     errors.New("kernel did not launch"),
	})

	got := lines(t, &buf)
	if len(got) != 1 {
		t.Fatalf("one report produced %d log lines", len(got))
	}
	if lvl := strings.ToLower(str(got[0]["level"])); lvl != "warn" {
		t.Errorf("an unhealthy backend was logged at %q, want warn", lvl)
	}
	for k, want := range map[string]string{"backend": "gpu-cuda", "probe": "storage"} {
		if str(got[0][k]) != want {
			t.Errorf("log field %q = %q, want %q", k, str(got[0][k]), want)
		}
	}
	if !strings.Contains(str(got[0]["err"]), "kernel did not launch") {
		t.Errorf("log does not carry the reason: %v", got[0]["err"])
	}
}

func TestAHealthyBackendIsReportedAtInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := log.NewWriter(&buf)

	report(logger, cevm.HealthReport{
		Backend:   cevm.CPUParallel,
		Name:      "cpu-parallel",
		OK:        true,
		ProbesRun: 5,
		GasUsed:   105000,
	})

	got := lines(t, &buf)
	if len(got) != 1 {
		t.Fatalf("one report produced %d log lines", len(got))
	}
	if lvl := strings.ToLower(str(got[0]["level"])); lvl != "info" {
		t.Errorf("a healthy backend was logged at %q, want info", lvl)
	}
	if str(got[0]["backend"]) != "cpu-parallel" {
		t.Errorf("log names backend %q", got[0]["backend"])
	}
}

// This build links no native library, so the one report it has says so — and
// says the right thing. It used to blame CGo, which is enabled here; an
// operator who followed that checked CGO_ENABLED and found it already 1.
func TestThisBuildReportsWhyItCannotExecute(t *testing.T) {
	reports := cevm.Health()
	if len(reports) == 0 {
		t.Fatal("Health() said nothing at all")
	}
	for _, h := range reports {
		if h.OK {
			continue
		}
		if !errors.Is(h.Err, cevm.ErrNotLinked) {
			t.Errorf("backend %q is not healthy and blames %v, want cevm.ErrNotLinked",
				h.Name, h.Err)
		}
	}
}

func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q is not JSON: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
