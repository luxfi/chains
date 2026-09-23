// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/luxfi/chains/evm/cevm"
	"github.com/luxfi/log"
)

// A backend that should have run the health battery and did not is reported
// at warn, carrying the probe that failed and the reason; one that ran it is
// reported at info.
//
// The level is the whole point: an operator's alerting reads it, and a GPU
// lane that cannot run a block reported at info is a device doing nothing with
// nothing raised about it.
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
	if lvl := level(got[0]); lvl != "warn" {
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
		Backend:   cevm.GPUMetal,
		Name:      "gpu-metal",
		OK:        true,
		ProbesRun: 1,
		GasUsed:   21000,
	})

	got := lines(t, &buf)
	if len(got) != 1 {
		t.Fatalf("one report produced %d log lines", len(got))
	}
	if lvl := level(got[0]); lvl != "info" {
		t.Errorf("a healthy backend was logged at %q, want info", lvl)
	}
	if str(got[0]["backend"]) != "gpu-metal" {
		t.Errorf("log names backend %q", got[0]["backend"])
	}
}

// A CPU lane declines every block through cevm's Go entry, and a build with
// no library runs none: that is what those lanes are on every start, so they
// are said once, together, at info — never a warning per lane per start.
func TestALaneThatRunsNothingIsSaidOnceAtInfo(t *testing.T) {
	declined := fmt.Errorf("probe %q: %w", "transfer", cevm.ErrDeclined)
	for name, reports := range map[string][]cevm.HealthReport{
		"cpu lanes": {
			{Backend: cevm.CPUSequential, Name: "cpu-sequential", Err: declined},
			{Backend: cevm.CPUParallel, Name: "cpu-parallel (Block-STM)", Err: declined},
		},
		"no library": {
			{Backend: cevm.CPUSequential, Name: "cpu-sequential", Err: cevm.ErrNotLinked},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			reportHealth(log.NewWriter(&buf), reports)
			got := lines(t, &buf)
			if len(got) != 1 {
				t.Fatalf("%d lanes that run nothing produced %d log lines, want 1", len(reports), len(got))
			}
			if lvl := level(got[0]); lvl != "info" {
				t.Errorf("lanes that run nothing were logged at %q, want info", lvl)
			}
			named, _ := got[0]["backends"].([]any)
			if len(named) != len(reports) {
				t.Errorf("the line names %v, want every one of %d lanes", got[0]["backends"], len(reports))
			}
		})
	}
}

// A GPU lane that declines the funded transfer is not what a GPU lane is: it
// is warned about on its own, beside the CPU lanes' one info line and the
// healthy lane's.
func TestAGPULaneThatDeclinesIsWarnedAboutAlone(t *testing.T) {
	declined := fmt.Errorf("probe %q: %w", "transfer", cevm.ErrDeclined)
	var buf bytes.Buffer
	reportHealth(log.NewWriter(&buf), []cevm.HealthReport{
		{Backend: cevm.CPUSequential, Name: "cpu-sequential", Err: declined},
		{Backend: cevm.CPUParallel, Name: "cpu-parallel (Block-STM)", Err: declined},
		{Backend: cevm.GPUMetal, Name: "gpu-metal", OK: true, ProbesRun: 1, GasUsed: 21000},
		{Backend: cevm.GPUCUDA, Name: "gpu-cuda", Probe: "transfer", Err: declined},
	})
	var warns []string
	for _, l := range lines(t, &buf) {
		if level(l) == "warn" {
			warns = append(warns, str(l["backend"]))
		}
	}
	if len(warns) != 1 || warns[0] != "gpu-cuda" {
		t.Fatalf("warned about %v, want the declining GPU lane alone", warns)
	}
}

// What this build says at start: a lane that is not healthy says why, and
// nothing it is by construction — a CPU lane, or a build with no library — is
// a warning. Only a GPU lane that did not run the battery may warn.
func TestThisBuildWarnsOnlyAboutAGPULane(t *testing.T) {
	for _, h := range cevm.Health() {
		if !h.OK && h.Err == nil {
			t.Errorf("backend %q is not healthy and does not say why", h.Name)
		}
	}
	var buf bytes.Buffer
	reportCevm(log.NewWriter(&buf))
	for _, l := range lines(t, &buf) {
		if level(l) != "warn" {
			continue
		}
		if b := str(l["backend"]); !strings.HasPrefix(b, "gpu-") {
			t.Errorf("start warned about %q: %v", b, l)
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

func level(m map[string]any) string { return strings.ToLower(str(m["level"])) }

func str(v any) string {
	s, _ := v.(string)
	return s
}
