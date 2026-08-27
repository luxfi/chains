// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package firecracker

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// call is one request a VMM received.
type call struct {
	method string
	path   string
	body   map[string]any
	kind   string
}

// vmm is a stand-in firecracker: it listens on a unix socket, records what it
// was asked, and answers with the status the test chose for that path.
type vmm struct {
	lock   sync.Mutex
	calls  []call
	refuse map[string]string
}

func (v *vmm) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	doc, _ := io.ReadAll(req.Body)
	var body map[string]any
	_ = json.Unmarshal(doc, &body)

	v.lock.Lock()
	v.calls = append(v.calls, call{
		method: req.Method,
		path:   req.URL.Path,
		body:   body,
		kind:   req.Header.Get("Content-Type"),
	})
	said, refused := v.refuse[req.URL.Path]
	v.lock.Unlock()

	if refused {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, said)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// seen is a copy of what the VMM was asked, in order.
func (v *vmm) seen() []call {
	v.lock.Lock()
	defer v.lock.Unlock()
	return append([]call(nil), v.calls...)
}

// serve starts a stand-in VMM on a socket and returns the socket path.
func serve(t *testing.T, v *vmm) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: v}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// machine is the plan the tests boot.
func booting() plan {
	return plan{
		Kernel: "/var/lib/agentvm/vmlinux",
		Boot:   "console=ttyS0 agentvm.workload=abcd",
		Rootfs: "/var/lib/agentvm/rootfs.ext4",
		VCPU:   2,
		Memory: 512,
	}
}

func TestBootSequence(t *testing.T) {
	v := &vmm{}
	p := booting()
	if err := dial(serve(t, v)).start(context.Background(), p); err != nil {
		t.Fatalf("start: %v", err)
	}

	got := v.seen()
	want := []string{"/boot-source", "/drives/rootfs", "/machine-config", "/actions"}
	if len(got) != len(want) {
		t.Fatalf("%d requests, want %d: %+v", len(got), len(want), got)
	}
	for i, path := range want {
		if got[i].path != path {
			t.Fatalf("request %d went to %s, want %s", i, got[i].path, path)
		}
		if got[i].method != http.MethodPut {
			t.Fatalf("request %d used %s, want PUT", i, got[i].method)
		}
		if !strings.HasPrefix(got[i].kind, "application/json") {
			t.Fatalf("request %d sent %q", i, got[i].kind)
		}
	}

	if got[0].body["kernel_image_path"] != p.Kernel {
		t.Fatalf("kernel %v, want %s", got[0].body["kernel_image_path"], p.Kernel)
	}
	if got[0].body["boot_args"] != p.Boot {
		t.Fatalf("boot args %v, want %s", got[0].body["boot_args"], p.Boot)
	}

	drive := got[1].body
	if drive["drive_id"] != "rootfs" || drive["path_on_host"] != p.Rootfs {
		t.Fatalf("drive %+v", drive)
	}
	if drive["is_root_device"] != true {
		t.Fatalf("root filesystem is not attached as the root device: %+v", drive)
	}
	if drive["is_read_only"] != true {
		t.Fatalf("root filesystem is writable, so the next run measures something else: %+v", drive)
	}

	if got[2].body["vcpu_count"] != float64(p.VCPU) {
		t.Fatalf("vcpu %v, want %d", got[2].body["vcpu_count"], p.VCPU)
	}
	if got[2].body["mem_size_mib"] != float64(p.Memory) {
		t.Fatalf("memory %v, want %d", got[2].body["mem_size_mib"], p.Memory)
	}

	if got[3].body["action_type"] != "InstanceStart" {
		t.Fatalf("action %v, want InstanceStart", got[3].body["action_type"])
	}
}

func TestBootStopsAtRefusal(t *testing.T) {
	v := &vmm{refuse: map[string]string{"/machine-config": `{"fault_message":"vcpu_count too large"}`}}
	err := dial(serve(t, v)).start(context.Background(), booting())
	if err == nil {
		t.Fatal("a refused configuration booted")
	}
	if !strings.Contains(err.Error(), "/machine-config") {
		t.Fatalf("error %v does not name the request", err)
	}
	if !strings.Contains(err.Error(), "vcpu_count too large") {
		t.Fatalf("error %v does not carry what the vmm said", err)
	}
	// The boot is never issued once a step is refused: a machine configured
	// halfway is not a machine.
	if got := v.seen(); len(got) != 3 {
		t.Fatalf("%d requests, want the sequence to stop at the refusal", len(got))
	}
}

func TestBootWithoutListener(t *testing.T) {
	err := dial(filepath.Join(t.TempDir(), "api.sock")).start(context.Background(), booting())
	if err == nil {
		t.Fatal("configuring a vmm that is not there succeeded")
	}
	if !strings.Contains(err.Error(), "/boot-source") {
		t.Fatalf("error %v does not name the request", err)
	}
}

func TestBootHonoursContext(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if err := dial(serve(t, &vmm{})).start(ctx, booting()); err == nil {
		t.Fatal("a cancelled run configured a machine")
	}
}
