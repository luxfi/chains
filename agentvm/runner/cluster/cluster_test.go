// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cluster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

const (
	space = "lab"
	pod   = "agentvm-pod-abcde"
	uid   = "9f1c2b3a-0000-4444-8888-aaaabbbbcccc"
)

// server answers the four requests a run makes, and records what it was sent.
// It is the API server as far as the runner is concerned: the whole Run path
// executes against it, including the delete.
type server struct {
	mu sync.Mutex

	outcome string // "succeeded", "failed", or "" for a job that never finishes
	log     string
	id      string // the uid the create answers with

	body    []byte // the Job as submitted
	name    string
	polls   int
	deleted bool
	policy  string
	bearer  string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.bearer = r.Header.Get("Authorization")
	jobs := "/apis/batch/v1/namespaces/" + space + "/jobs"
	pods := "/api/v1/namespaces/" + space + "/pods"

	switch {
	case r.Method == http.MethodPost && r.URL.Path == jobs:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.body = body
		var j job
		if err := json.Unmarshal(body, &j); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.name = j.Meta.Name
		fmt.Fprintf(w, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":%q,"uid":%q}}`, s.name, s.id)

	case r.Method == http.MethodGet && r.URL.Path == jobs+"/"+s.name:
		s.polls++
		// The first read reports a Job that has started nothing. A runner that
		// read absence as success would stop here.
		if s.polls < 2 || s.outcome == "" {
			fmt.Fprint(w, `{"apiVersion":"batch/v1","kind":"Job","status":{}}`)
			return
		}
		fmt.Fprintf(w, `{"apiVersion":"batch/v1","kind":"Job","status":{%q:1}}`, s.outcome)

	case r.Method == http.MethodDelete && r.URL.Path == jobs+"/"+s.name:
		s.deleted = true
		s.policy = r.URL.Query().Get("propagationPolicy")
		fmt.Fprint(w, `{"kind":"Status","status":"Success"}`)

	case r.Method == http.MethodGet && r.URL.Path == pods:
		if got, want := r.URL.Query().Get("labelSelector"), "job-name="+s.name; got != want {
			http.Error(w, "selector "+got+" want "+want, http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, `{"items":[{"metadata":{"name":%q}}]}`, pod)

	case r.Method == http.MethodGet && r.URL.Path == pods+"/"+pod+"/log":
		fmt.Fprint(w, s.log)

	default:
		http.Error(w, "no route for "+r.Method+" "+r.URL.String(), http.StatusNotFound)
	}
}

// services is a running stub and a runner pointed at it.
type services struct {
	stub *server
	run  *Runner
}

// snap is what the stub recorded, read under its lock.
type snap struct {
	polls   int
	deleted bool
	policy  string
	bearer  string
	body    []byte
}

func (s *services) state() snap {
	s.stub.mu.Lock()
	defer s.stub.mu.Unlock()
	return snap{
		polls:   s.stub.polls,
		deleted: s.stub.deleted,
		policy:  s.stub.policy,
		bearer:  s.stub.bearer,
		body:    s.stub.body,
	}
}

func stand(t *testing.T, class string, outcome, log string) *services {
	t.Helper()
	stub := &server{outcome: outcome, log: log, id: uid}
	ts := httptest.NewTLSServer(stub)
	t.Cleanup(ts.Close)

	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if ca == nil {
		t.Fatal("could not encode the test authority")
	}
	r, err := New(
		Config{RuntimeClass: class, Namespace: space, Image: "ghcr.io/luxfi/agentvm:test"},
		WithBase(ts.URL, "token-under-test", ca),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &services{stub: stub, run: r}
}

// work is a workload with every field the Job derives from set to something
// recognisable in the submitted JSON.
func work(timeout uint32) agentvm.Workload {
	return agentvm.Workload{
		Code: agentvm.Code{
			Kind:   agentvm.CodeImage,
			Ref:    "/bin/solve",
			Digest: common.HexToHash("0x01"),
			Args:   []string{"--depth", "3"},
		},
		Env: []agentvm.Var{
			{Name: "LEVEL", Value: "debug"},
			{Name: "SEED", Value: "7"},
		},
		Resource: agentvm.Resource{CPU: 1500, Memory: 268435456, GPU: 2, Timeout: timeout},
		Nonce:    common.HexToHash("0x02"),
	}
}

func TestRun(t *testing.T) {
	s := stand(t, "gvisor", "succeeded", "the answer is 42")

	res, err := s.run.Run(t.Context(), work(10_000), []byte("input bytes"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got, want := string(res.Output), "the answer is 42"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
	if res.Exit != 0 {
		t.Errorf("exit = %d, want 0", res.Exit)
	}
	if res.Observed.Serves != agentvm.MechanismGVisor {
		t.Errorf("observed mechanism = %v, want gvisor", res.Observed.Serves)
	}
	want := common.BytesToHash(crypto.Keccak256([]byte("gvisor"), []byte(uid)))
	if res.Observed.Digest != want {
		t.Errorf("observed digest = %s, want %s", res.Observed.Digest, want)
	}
	if res.Consumed.CPU != 1500 || res.Consumed.Memory != 268435456 || res.Consumed.GPU != 2 {
		t.Errorf("consumed = %+v, want the reservation", res.Consumed)
	}

	// The filter digest is keccak over the canonical JSON of the security
	// context, and the canonical JSON is what went on the wire. Pinning the
	// literal here catches a field order change and a dropped field alike.
	const canonical = `{"runAsNonRoot":true,"allowPrivilegeEscalation":false,` +
		`"readOnlyRootFilesystem":true,"seccompProfile":{"type":"RuntimeDefault"}}`
	if got := common.BytesToHash(crypto.Keccak256([]byte(canonical))); res.Filter != got {
		t.Errorf("filter = %s, want keccak of the canonical security context %s", res.Filter, got)
	}

	st := s.state()
	if st.polls < 2 {
		t.Errorf("polled %d times; a job with no status must not read as done", st.polls)
	}
	if !st.deleted {
		t.Error("the job was not deleted after a successful run")
	}
	if st.policy != "Background" {
		t.Errorf("propagationPolicy = %q, want Background", st.policy)
	}
	if !strings.Contains(string(st.body), `"securityContext":`+canonical) {
		t.Errorf("submitted job does not carry the canonical security context:\n%s", st.body)
	}
	if st.bearer != "Bearer token-under-test" {
		t.Errorf("authorization = %q, want the bearer token", st.bearer)
	}
}

func TestSubmittedJob(t *testing.T) {
	s := stand(t, "kata", "succeeded", "done")
	if _, err := s.run.Run(t.Context(), work(10_000), []byte("input bytes")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var j job
	if err := json.Unmarshal(s.state().body, &j); err != nil {
		t.Fatalf("submitted job does not parse: %v", err)
	}
	spec := j.Spec.Template.Spec
	if spec.RuntimeClass != "kata" {
		t.Errorf("runtimeClassName = %q, want kata", spec.RuntimeClass)
	}
	if spec.RestartPolicy != "Never" {
		t.Errorf("restartPolicy = %q, want Never", spec.RestartPolicy)
	}
	if j.Spec.BackoffLimit != 0 {
		t.Errorf("backoffLimit = %d, want 0", j.Spec.BackoffLimit)
	}
	if j.Spec.Deadline != 10 {
		t.Errorf("activeDeadlineSeconds = %d, want 10", j.Spec.Deadline)
	}
	if len(spec.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(spec.Containers))
	}
	c := spec.Containers[0]
	if c.Image != "ghcr.io/luxfi/agentvm:test" {
		t.Errorf("image = %q", c.Image)
	}
	if len(c.Command) != 1 || c.Command[0] != "/bin/solve" {
		t.Errorf("command = %v, want the code reference", c.Command)
	}
	if len(c.Args) != 2 || c.Args[0] != "--depth" || c.Args[1] != "3" {
		t.Errorf("args = %v, want the workload arguments", c.Args)
	}
	want := security{
		RunAsNonRoot:             true,
		AllowPrivilegeEscalation: false,
		ReadOnlyRootFilesystem:   true,
		Seccomp:                  seccomp{Type: "RuntimeDefault"},
	}
	if c.Security != want {
		t.Errorf("securityContext = %+v, want %+v", c.Security, want)
	}
	for _, w := range []struct{ key, want string }{
		{"cpu", "1500m"},
		{"memory", "268435456"},
		{"nvidia.com/gpu", "2"},
	} {
		if got := c.Resources.Requests[w.key]; got != w.want {
			t.Errorf("requests[%s] = %q, want %q", w.key, got, w.want)
		}
		if got := c.Resources.Limits[w.key]; got != w.want {
			t.Errorf("limits[%s] = %q, want %q", w.key, got, w.want)
		}
	}
	env := map[string]string{}
	for _, v := range c.Env {
		env[v.Name] = v.Value
	}
	if env["LEVEL"] != "debug" || env["SEED"] != "7" {
		t.Errorf("env lost the workload's variables: %v", env)
	}
	if got, want := env[input], base64.StdEncoding.EncodeToString([]byte("input bytes")); got != want {
		t.Errorf("%s = %q, want %q", input, got, want)
	}
	if !strings.HasPrefix(j.Meta.Name, "agentvm-") {
		t.Errorf("job name = %q", j.Meta.Name)
	}
}

func TestRunFailed(t *testing.T) {
	s := stand(t, "runc", "failed", "")

	_, err := s.run.Run(t.Context(), work(10_000), nil)
	if !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("Run error = %v, want ErrFailed", err)
	}
	if st := s.state(); !st.deleted || st.policy != "Background" {
		t.Errorf("the job was not deleted after a failed run (deleted=%v policy=%q)", st.deleted, st.policy)
	}
}

func TestRunNeverCompletes(t *testing.T) {
	// The job reports neither count, forever. The run must end on its own
	// deadline and must end as a failure.
	s := stand(t, "runc", "", "")

	start := time.Now()
	_, err := s.run.Run(t.Context(), work(600), nil)
	if !errors.Is(err, runner.ErrFailed) {
		t.Fatalf("Run error = %v, want ErrFailed", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("run took %v; the workload timeout did not bound it", elapsed)
	}
	if !s.state().deleted {
		t.Error("the job was not deleted after a run that never completed")
	}
}

func TestRunWithoutOutput(t *testing.T) {
	s := stand(t, "runc", "succeeded", "")

	_, err := s.run.Run(t.Context(), work(10_000), nil)
	if !errors.Is(err, runner.ErrOutput) {
		t.Fatalf("Run error = %v, want ErrOutput", err)
	}
	if !s.state().deleted {
		t.Error("the job was not deleted after a run that produced nothing")
	}
}

func TestRunWithoutJobIdentity(t *testing.T) {
	// The create succeeded, so the Job exists, but the answer names no uid and
	// there is nothing to build the witness digest from. The refusal must not
	// leave the Job behind.
	s := stand(t, "runc", "succeeded", "x")
	s.stub.mu.Lock()
	s.stub.id = ""
	s.stub.mu.Unlock()

	if _, err := s.run.Run(t.Context(), work(10_000), nil); !errors.Is(err, ErrAPI) {
		t.Fatalf("Run against a create with no uid = %v, want ErrAPI", err)
	}
	if !s.state().deleted {
		t.Error("the job was left behind after a create this runner could not use")
	}
}

func TestUnknownClass(t *testing.T) {
	_, err := New(Config{RuntimeClass: "crun", Namespace: space, Image: "x"})
	if !errors.Is(err, ErrClass) {
		t.Fatalf("New with an unknown class = %v, want ErrClass", err)
	}
	_, err = New(Config{RuntimeClass: "", Namespace: space, Image: "x"})
	if !errors.Is(err, ErrClass) {
		t.Fatalf("New with no class = %v, want ErrClass", err)
	}
}

func TestClasses(t *testing.T) {
	for class, want := range map[string]agentvm.Mechanism{
		"runc":      agentvm.MechanismRunc,
		"gvisor":    agentvm.MechanismGVisor,
		"runsc":     agentvm.MechanismGVisor,
		"kata":      agentvm.MechanismFirecracker,
		"kata-qemu": agentvm.MechanismFirecracker,
	} {
		s := stand(t, class, "succeeded", "x")
		if got := s.run.Mechanism(); got != want {
			t.Errorf("%s runs as %v, want %v", class, got, want)
		}
		if got := s.run.Placement(); got != agentvm.PlacementCluster {
			t.Errorf("%s placement = %v, want cluster", class, got)
		}
	}
}

func TestNewOutsideCluster(t *testing.T) {
	t.Setenv(envHost, "")
	t.Setenv(envPort, "")
	_, err := New(Config{RuntimeClass: "runc", Namespace: space, Image: "x"})
	if !errors.Is(err, runner.ErrUnavailable) {
		t.Fatalf("New outside a cluster = %v, want ErrUnavailable", err)
	}
}

func TestNewWithoutImage(t *testing.T) {
	_, err := New(Config{RuntimeClass: "runc", Namespace: space})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("New without an image = %v, want ErrConfig", err)
	}
}

func TestNewWithoutNamespace(t *testing.T) {
	_, err := New(Config{RuntimeClass: "runc", Image: "x"}, WithBase("https://127.0.0.1:1", "", nil))
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("New without a namespace = %v, want ErrConfig", err)
	}
}

func TestBaseRefusesBadAuthority(t *testing.T) {
	_, err := New(
		Config{RuntimeClass: "runc", Namespace: space, Image: "x"},
		WithBase("https://127.0.0.1:1", "", []byte("not a certificate")),
	)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("New with an unparsable authority = %v, want ErrConfig", err)
	}
}

func TestBaseRefusesBadAddress(t *testing.T) {
	_, err := New(
		Config{RuntimeClass: "runc", Namespace: space, Image: "x"},
		WithBase("127.0.0.1:8080", "", nil),
	)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("New with an address that has no scheme = %v, want ErrConfig", err)
	}
}

func TestRunRefusesUnboundedWorkload(t *testing.T) {
	s := stand(t, "runc", "succeeded", "x")
	w := work(0)
	if _, err := s.run.Run(t.Context(), w, nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("Run of a workload with no timeout = %v, want ErrConfig", err)
	}
}

func TestRunRefusesOversizedInput(t *testing.T) {
	s := stand(t, "runc", "succeeded", "x")
	if _, err := s.run.Run(t.Context(), work(10_000), make([]byte, maxInput+1)); !errors.Is(err, ErrConfig) {
		t.Fatalf("Run with oversized input = %v, want ErrConfig", err)
	}
}

func TestRunRefusesWrongInput(t *testing.T) {
	s := stand(t, "runc", "succeeded", "x")
	w := work(10_000)
	w.Input = agentvm.Handle{
		Digest: common.BytesToHash(crypto.Keccak256([]byte("the bytes the workload names"))),
		Size:   28,
		Bucket: "runs",
		Key:    "in",
	}
	if _, err := s.run.Run(t.Context(), w, []byte("some other bytes")); !errors.Is(err, ErrConfig) {
		t.Fatalf("Run over bytes the handle does not name = %v, want ErrConfig", err)
	}
	if s.state().body != nil {
		t.Error("a job was submitted for input the workload does not name")
	}
	if _, err := s.run.Run(t.Context(), w, []byte("the bytes the workload names")); err != nil {
		t.Fatalf("Run over the named bytes: %v", err)
	}
}

func TestAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"kind":"Status","code":403}`, http.StatusForbidden)
	}))
	t.Cleanup(ts.Close)

	r, err := New(
		Config{RuntimeClass: "runc", Namespace: space, Image: "x"},
		WithBase(ts.URL, "", nil),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.Run(context.Background(), work(10_000), nil); !errors.Is(err, ErrAPI) {
		t.Fatalf("Run against a refusing server = %v, want ErrAPI", err)
	}
}
