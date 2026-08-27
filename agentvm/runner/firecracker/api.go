// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package firecracker

// api.go is the conversation with one firecracker process: JSON over HTTP over
// its unix socket, four requests in the order the VMM requires them. Nothing
// here starts or stops a process, so the sequence can be driven against any
// listener.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

// plan is the machine a run boots.
type plan struct {
	Kernel string
	Boot   string
	Rootfs string
	VCPU   int64
	Memory int64 // MiB
}

// source is the kernel and the command line the guest boots with.
type source struct {
	Kernel string `json:"kernel_image_path"`
	Boot   string `json:"boot_args"`
}

// drive is one block device. The root filesystem is attached read-only, so a
// run cannot change the image the next run measures.
type drive struct {
	ID       string `json:"drive_id"`
	Path     string `json:"path_on_host"`
	Root     bool   `json:"is_root_device"`
	ReadOnly bool   `json:"is_read_only"`
}

// machine is the size of the guest.
type machine struct {
	VCPU   int64 `json:"vcpu_count"`
	Memory int64 `json:"mem_size_mib"`
}

// act is a VMM action. The only one a run issues is the boot.
type act struct {
	Type string `json:"action_type"`
}

// api talks to one firecracker over its socket. The host in the URL is a
// placeholder the transport never resolves; every connection is the socket.
type api struct{ client *http.Client }

// dial builds a client bound to one socket path.
func dial(sock string) *api {
	return &api{client: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}}
}

// put sends one configuration document and refuses anything but success. The
// VMM answers a rejected configuration with a body explaining it, which is the
// error worth carrying.
func (a *api) put(ctx context.Context, path string, body any) error {
	doc, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%s: %s: %w", name, path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://firecracker"+path, bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("%s: %s: %w", name, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %s: %w", name, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		said, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s: %s: %s: %s", name, path, resp.Status, trim(said))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// start configures the machine and boots it. The order is the VMM's: a boot
// source, a root device, a size, and only then the instruction to run.
func (a *api) start(ctx context.Context, p plan) error {
	if err := a.put(ctx, "/boot-source", source{Kernel: p.Kernel, Boot: p.Boot}); err != nil {
		return err
	}
	if err := a.put(ctx, "/drives/rootfs", drive{
		ID: "rootfs", Path: p.Rootfs, Root: true, ReadOnly: true,
	}); err != nil {
		return err
	}
	if err := a.put(ctx, "/machine-config", machine{VCPU: p.VCPU, Memory: p.Memory}); err != nil {
		return err
	}
	return a.put(ctx, "/actions", act{Type: "InstanceStart"})
}
