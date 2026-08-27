// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cluster

// api.go is the shape of the Kubernetes objects this runner sends and reads.
// Only the fields it sets or consults are here; the API server supplies the
// rest and prunes what it does not know.
//
// Field order is declaration order, and encoding/json sorts map keys, so
// marshalling one of these values twice produces the same bytes. That is what
// lets the security context be digested as the canonical statement of what the
// run was given: the bytes digested and the bytes submitted come from the same
// value.
//
// All four fields of the security context sit on the CONTAINER. That is the one
// object where all four are honoured: a pod-level security context carries
// runAsNonRoot and seccompProfile but has no allowPrivilegeEscalation and no
// readOnlyRootFilesystem, and the API server prunes fields it does not know
// without saying so. Submitting them there would produce a Job that looks
// hardened and is not.

// job is a batch/v1 Job, in both directions. Status is a pointer so a submitted
// Job carries none and a Job read back carries what the controller wrote.
type job struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Meta       meta    `json:"metadata"`
	Spec       jobSpec `json:"spec"`
	Status     *status `json:"status,omitempty"`
}

// meta is the object metadata this runner reads or sets.
type meta struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// jobSpec bounds the Job. A backoff limit of zero means one attempt: a workload
// is not retried behind the chain's back, because two runs of one workload are
// two runs and the chain settles each.
type jobSpec struct {
	BackoffLimit int32    `json:"backoffLimit"`
	Deadline     int64    `json:"activeDeadlineSeconds"`
	Template     template `json:"template"`
}

// template is the pod template the Job stamps out.
type template struct {
	Spec podSpec `json:"spec"`
}

// podSpec is the pod. RuntimeClass is what decides the isolation the run
// actually gets, so it is the one field this runner exists to set.
type podSpec struct {
	RestartPolicy string `json:"restartPolicy"`
	RuntimeClass  string `json:"runtimeClassName"`
	Containers    []cont `json:"containers"`
}

// cont is the container the workload runs in.
type cont struct {
	Name      string     `json:"name"`
	Image     string     `json:"image"`
	Command   []string   `json:"command,omitempty"`
	Args      []string   `json:"args,omitempty"`
	Env       []variable `json:"env,omitempty"`
	Resources resources  `json:"resources"`
	Security  security   `json:"securityContext"`
}

// variable is one environment entry.
type variable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// resources is the reservation. Requests and limits are the same map, so the
// pod is guaranteed what it asked for and cannot exceed it.
type resources struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}

// security is what the run may do. Every field is written out, including the
// false ones: a missing allowPrivilegeEscalation is not the same statement as
// an explicit false, and the digest of this value is what the evidence carries
// as the filter the run was given.
type security struct {
	RunAsNonRoot             bool    `json:"runAsNonRoot"`
	AllowPrivilegeEscalation bool    `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   bool    `json:"readOnlyRootFilesystem"`
	Seccomp                  seccomp `json:"seccompProfile"`
}

// seccomp names the syscall filter profile the kubelet installs.
type seccomp struct {
	Type string `json:"type"`
}

// status is what the Job controller reports. Absent counts read as zero, and
// zero on both is a Job that has not finished rather than a Job that succeeded.
type status struct {
	Succeeded int32 `json:"succeeded"`
	Failed    int32 `json:"failed"`
}

// podList is the answer to a pod list request.
type podList struct {
	Items []struct {
		Meta meta `json:"metadata"`
	} `json:"items"`
}
