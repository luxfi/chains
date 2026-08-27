// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cluster runs a workload as a Kubernetes Job.
//
// Placement is fixed here and the mechanism is not. A pod runs whatever
// RuntimeClass the cluster hands it, so what isolates the workload is a
// deployment fact, not a property of this code. New therefore takes the class
// name and the mechanism that class actually is, and Mechanism reports that.
// Classes is the conventional mapping for the three classes an operator is
// likely to have installed; a class outside it is refused at construction,
// because guessing here would let a run under runc present itself as a microVM.
//
// The API server is reached with net/http and encoding/json. A Job is five
// nested objects and four requests, and client-go would bring a dependency
// tree larger than the whole chain to build them.
//
// The Job is deleted on every return path. A Job whose caller has gone away
// keeps its pod, and the pod keeps the CPU and the memory it reserved.
package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// Errors this runner raises on its own account. A run that did not complete is
// runner.ErrFailed and a run whose output could not be collected is
// runner.ErrOutput; those are the package's words and are not restated here.
var (
	// ErrClass means the RuntimeClass is not one whose mechanism is known.
	ErrClass = errors.New("agentvm/runner/cluster: unknown runtime class")
	// ErrConfig means the runner was asked for with something missing.
	ErrConfig = errors.New("agentvm/runner/cluster: incomplete configuration")
	// ErrAPI means the API server answered something other than success.
	ErrAPI = errors.New("agentvm/runner/cluster: api server refused the request")
)

// Classes maps a RuntimeClass name to the mechanism a pod under that class
// actually runs. This is the only place the two are connected, and a name
// outside it has no mechanism rather than a default one.
var Classes = map[string]agentvm.Mechanism{
	"runc":      agentvm.MechanismRunc,
	"gvisor":    agentvm.MechanismGVisor,
	"runsc":     agentvm.MechanismGVisor,
	"kata":      agentvm.MechanismFirecracker,
	"kata-qemu": agentvm.MechanismFirecracker,
}

// Where an in-cluster pod finds its own credentials. Fixed by the kubelet.
const (
	envHost   = "KUBERNETES_SERVICE_HOST"
	envPort   = "KUBERNETES_SERVICE_PORT"
	tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	nsPath    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

const (
	// input is the variable the workload's input bytes arrive in, base64
	// encoded. The bytes do not fit in a command line and a run that silently
	// lost them would look like a run that produced the wrong answer.
	input = "AGENTVM_INPUT"
	// poll is how often the Job's status is read while waiting.
	poll = 250 * time.Millisecond
	// maxBody bounds any single response, the pod log included. A response
	// over it is refused rather than truncated: the log is the run's output,
	// and half of an object is a different object.
	maxBody = 1 << 20
	// maxInput bounds the bytes handed to a run. They ride in an environment
	// variable and the kernel caps the whole environment at exec, so an input
	// past this would fail with nothing to read and no error worth the name.
	maxInput = 1 << 20
)

// Config is what an operator states about its cluster.
type Config struct {
	// RuntimeClass is the class pods are given. Its mechanism is read from
	// Classes.
	RuntimeClass string
	// Namespace is where Jobs are created. Empty means the pod's own
	// namespace, read from the service account.
	Namespace string
	// Image is the container image the workload's code runs in.
	Image string
}

// Option adjusts how the runner reaches the API server.
type Option func(*Runner) error

// WithBase points the runner at an API server given explicitly, instead of the
// one a pod discovers from its own service account. An address and a credential
// are inputs; a cluster reached through a proxy and a server stood up for a test
// are the same case, and neither is something this package can only discover.
// An empty ca uses the host's certificate pool.
func WithBase(base string, token string, ca []byte) Option {
	return func(r *Runner) error {
		u, err := url.Parse(base)
		if err != nil {
			return fmt.Errorf("%w: base %q: %w", ErrConfig, base, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%w: base %q needs a scheme and a host", ErrConfig, base)
		}
		r.base = strings.TrimSuffix(base, "/")
		r.token = token
		return r.connect(ca)
	}
}

// Runner submits Kubernetes Jobs and reads back what they produced.
type Runner struct {
	class  string
	mech   agentvm.Mechanism
	ns     string
	image  string
	base   string
	token  string
	client *http.Client
}

var _ runner.Runner = (*Runner)(nil)

// New builds a runner for one RuntimeClass. Without an Option naming the API
// server it reads the credentials a pod is given, and returns ErrUnavailable
// when it is not running in a cluster: a runner that cannot reach an API server
// is absent from the set rather than present and failing every run.
func New(cfg Config, opts ...Option) (*Runner, error) {
	mech, ok := Classes[cfg.RuntimeClass]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrClass, cfg.RuntimeClass)
	}
	if cfg.Image == "" {
		return nil, fmt.Errorf("%w: no image", ErrConfig)
	}
	r := &Runner{class: cfg.RuntimeClass, mech: mech, ns: cfg.Namespace, image: cfg.Image}
	for _, o := range opts {
		if err := o(r); err != nil {
			return nil, err
		}
	}
	if r.client == nil {
		if err := r.discover(); err != nil {
			return nil, err
		}
	}
	if r.ns == "" {
		return nil, fmt.Errorf("%w: no namespace", ErrConfig)
	}
	return r, nil
}

// discover reads the address and credentials the kubelet projects into a pod.
func (r *Runner) discover() error {
	host, port := os.Getenv(envHost), os.Getenv(envPort)
	if host == "" || port == "" {
		return fmt.Errorf("%w: %s and %s are unset", runner.ErrUnavailable, envHost, envPort)
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("%w: %w", runner.ErrUnavailable, err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("%w: %w", runner.ErrUnavailable, err)
	}
	if r.ns == "" {
		ns, err := os.ReadFile(nsPath)
		if err != nil {
			return fmt.Errorf("%w: %w", runner.ErrUnavailable, err)
		}
		r.ns = strings.TrimSpace(string(ns))
	}
	r.base = "https://" + net.JoinHostPort(host, port)
	r.token = strings.TrimSpace(string(token))
	return r.connect(ca)
}

// connect builds the HTTP client. A certificate authority that parses to no
// certificate is refused, rather than quietly leaving the host's pool in place.
func (r *Runner) connect(ca []byte) error {
	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(ca) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return fmt.Errorf("%w: certificate authority holds no certificate", ErrConfig)
		}
		conf.RootCAs = pool
	}
	r.client = &http.Client{Transport: &http.Transport{TLSClientConfig: conf}}
	return nil
}

// Mechanism is what a pod under this runner's RuntimeClass runs as.
func (r *Runner) Mechanism() agentvm.Mechanism { return r.mech }

// Placement is the cluster.
func (r *Runner) Placement() agentvm.Placement { return agentvm.PlacementCluster }

// Run creates the Job, waits for it to complete, and returns what its pod
// wrote. The Job is deleted on every path out, including every error.
func (r *Runner) Run(ctx context.Context, w agentvm.Workload, in []byte) (res runner.Result, err error) {
	if w.Resource.Timeout == 0 {
		return runner.Result{}, fmt.Errorf("%w: workload states no timeout", ErrConfig)
	}
	if len(in) > maxInput {
		return runner.Result{}, fmt.Errorf("%w: input is %d bytes, over %d", ErrConfig, len(in), maxInput)
	}
	// The workload names its input by digest. Bytes that do not hash to it are
	// a different object, and running on them would produce a receipt for a
	// run nobody asked for.
	if want := w.Input.Digest; want != (common.Hash{}) {
		if got := common.BytesToHash(crypto.Keccak256(in)); got != want {
			return runner.Result{}, fmt.Errorf("%w: input hashes to %s, workload names %s", ErrConfig, got, want)
		}
	}
	name, err := jobName(w)
	if err != nil {
		return runner.Result{}, err
	}

	guard := security{
		RunAsNonRoot:             true,
		AllowPrivilegeEscalation: false,
		ReadOnlyRootFilesystem:   true,
		Seccomp:                  seccomp{Type: "RuntimeDefault"},
	}
	body, err := json.Marshal(r.job(name, w, in, guard))
	if err != nil {
		return runner.Result{}, err
	}

	ctx, stop := context.WithTimeout(ctx, time.Duration(w.Resource.Timeout)*time.Millisecond)
	defer stop()

	start := time.Now()
	raw, err := r.call(ctx, http.MethodPost, r.path("/apis/batch/v1/namespaces/%s/jobs"), body)
	if err != nil {
		return runner.Result{}, err
	}
	// From here the Job exists, so it is removed on every way out. The delete
	// is by the name this runner chose, which is known whatever the create
	// response turns out to say. A Job outlives its caller unless it is
	// removed, and a delete that fails is reported rather than swallowed; it
	// does not mask the run's own error.
	defer func() {
		if cerr := r.remove(ctx, name); cerr != nil && err == nil {
			err = cerr
		}
	}()

	var created job
	if err := json.Unmarshal(raw, &created); err != nil {
		return runner.Result{}, err
	}
	if created.Meta.UID == "" {
		return runner.Result{}, fmt.Errorf("%w: created job carries no uid", ErrAPI)
	}

	if err := r.wait(ctx, name); err != nil {
		return runner.Result{}, err
	}
	out, err := r.output(ctx, name)
	if err != nil {
		return runner.Result{}, err
	}

	filter, err := digest(guard)
	if err != nil {
		return runner.Result{}, err
	}
	return runner.Result{
		Output: out,
		Exit:   0,
		// The pod held its request for its whole life, because requests and
		// limits are equal and the reservation is what the cluster gave away.
		// Wall time is measured; nothing here reads a metrics API.
		Consumed: agentvm.Resource{
			CPU:     w.Resource.CPU,
			Memory:  w.Resource.Memory,
			GPU:     w.Resource.GPU,
			Timeout: uint32(time.Since(start).Milliseconds()),
		},
		Observed: agentvm.Witness{
			Serves: r.mech,
			Digest: common.BytesToHash(crypto.Keccak256([]byte(r.class), []byte(created.Meta.UID))),
		},
		Filter: filter,
	}, nil
}

// wait polls the Job until it reports a completed pod or a failed one. A status
// that says neither is not success: the loop ends only on one of the two counts
// or on the context, and a context that ends first is a failure to complete.
func (r *Runner) wait(ctx context.Context, name string) error {
	path := r.path("/apis/batch/v1/namespaces/%s/jobs/") + name
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		raw, err := r.call(ctx, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		var j job
		if err := json.Unmarshal(raw, &j); err != nil {
			return err
		}
		if j.Status != nil {
			if j.Status.Failed >= 1 {
				return fmt.Errorf("%w: job %s reports %d failed pods", runner.ErrFailed, name, j.Status.Failed)
			}
			if j.Status.Succeeded >= 1 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: job %s did not complete: %w", runner.ErrFailed, name, ctx.Err())
		case <-tick.C:
		}
	}
}

// output reads what the Job's pod wrote. A completed Job whose pod is gone
// leaves nothing to read, which is a run without output rather than a run that
// wrote nothing.
func (r *Runner) output(ctx context.Context, name string) ([]byte, error) {
	list := r.path("/api/v1/namespaces/%s/pods") + "?labelSelector=" + url.QueryEscape("job-name="+name)
	raw, err := r.call(ctx, http.MethodGet, list, nil)
	if err != nil {
		return nil, err
	}
	var pods podList
	if err := json.Unmarshal(raw, &pods); err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("%w: job %s has no pod to read", runner.ErrOutput, name)
	}
	pod := pods.Items[0].Meta.Name
	if pod == "" {
		return nil, fmt.Errorf("%w: job %s lists a pod without a name", runner.ErrOutput, name)
	}
	out, err := r.call(ctx, http.MethodGet, r.path("/api/v1/namespaces/%s/pods/")+pod+"/log", nil)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: pod %s wrote nothing", runner.ErrOutput, pod)
	}
	return out, nil
}

// remove deletes the Job and the pods it owns. It runs on the way out of a run
// that may have exceeded its own deadline, so it carries its own.
func (r *Runner) remove(ctx context.Context, name string) error {
	ctx, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer stop()
	path := r.path("/apis/batch/v1/namespaces/%s/jobs/") + name + "?propagationPolicy=Background"
	_, err := r.call(ctx, http.MethodDelete, path, nil)
	return err
}

// path fills the namespace into an API path holding one verb.
func (r *Runner) path(format string) string { return fmt.Sprintf(format, r.ns) }

// call performs one request and returns the response body. A response over the
// bound is refused; truncating it would hand back bytes that are not what the
// run produced.
func (r *Runner) call(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBody {
		return nil, fmt.Errorf("%w: %s %s answered over %d bytes", ErrAPI, method, path, maxBody)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w: %s %s: %s: %s", ErrAPI, method, path, resp.Status, clip(raw))
	}
	return raw, nil
}

// clip shortens a response body for an error message.
func clip(b []byte) string {
	const most = 256
	if len(b) > most {
		return string(b[:most]) + "..."
	}
	return string(b)
}

// digest is keccak over the canonical JSON of a value. The security context
// submitted with the Job and the one digested here are the same value, so the
// digest names what the run was actually given.
func digest(v any) (common.Hash, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(crypto.Keccak256(b)), nil
}

// jobName is a DNS-1123 name naming the workload and this attempt at it. The
// workload's id makes the name readable against the chain; the random tail
// keeps two runs of one workload from colliding.
func jobName(w agentvm.Workload) (string, error) {
	var tail [4]byte
	if _, err := rand.Read(tail[:]); err != nil {
		return "", err
	}
	id := w.ID()
	return "agentvm-" + hex.EncodeToString(id[:8]) + "-" + hex.EncodeToString(tail[:]), nil
}

// job builds the Job to submit. Every field the run's isolation depends on is
// set here and nowhere else.
func (r *Runner) job(name string, w agentvm.Workload, in []byte, guard security) job {
	c := container(r.image, w, in, guard)
	// The pod's own deadline. Without it a Job whose caller died keeps its pod
	// for as long as the cluster will run it.
	deadline := int64(w.Resource.Timeout+999) / 1000
	if deadline < 1 {
		deadline = 1
	}
	return job{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Meta:       meta{Name: name},
		Spec: jobSpec{
			BackoffLimit: 0,
			Deadline:     deadline,
			Template: template{
				Spec: podSpec{
					RestartPolicy: "Never",
					RuntimeClass:  r.class,
					Containers:    []cont{c},
				},
			},
		},
	}
}

// container builds the single container the Job runs. Command and arguments
// keep the split Kubernetes gives them: the code reference is the program and
// the workload's arguments are its arguments, so an empty reference leaves the
// image's own entry point in place.
func container(image string, w agentvm.Workload, in []byte, guard security) cont {
	env := make([]variable, 0, len(w.Env)+1)
	for _, v := range w.Env {
		env = append(env, variable{Name: v.Name, Value: v.Value})
	}
	env = append(env, variable{Name: input, Value: base64.StdEncoding.EncodeToString(in)})

	ask := map[string]string{
		"cpu":    strconv.FormatUint(uint64(w.Resource.CPU), 10) + "m",
		"memory": strconv.FormatUint(w.Resource.Memory, 10),
	}
	if w.Resource.GPU > 0 {
		ask["nvidia.com/gpu"] = strconv.FormatUint(uint64(w.Resource.GPU), 10)
	}

	c := cont{
		Name:      "run",
		Image:     image,
		Args:      w.Code.Args,
		Env:       env,
		Resources: resources{Requests: ask, Limits: ask},
		Security:  guard,
	}
	if w.Code.Ref != "" {
		c.Command = []string{w.Code.Ref}
	}
	return c
}
