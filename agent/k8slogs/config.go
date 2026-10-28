// Package k8slogs ships the logs of Kubernetes pods to OpenPicket
// (openpicket-agent-k8s-collector): it follows the containers of the
// configured pods through the Kubernetes API, as `kubectl logs -f` does,
// and keeps, optionally in a file on a volume, the position of the last
// line the manager acknowledged in each container.
package k8slogs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/pkg/record"
)

// Config is the collector's configuration file.
type Config struct {
	// NodeID is the node registered in OpenPicket; the key's public half
	// is registered under it.
	NodeID  string `yaml:"node_id"`
	KeyFile string `yaml:"key_file"`
	// StateFile keeps the acknowledged positions (on a persistent volume):
	// after a restart each container resumes after its last shipped line,
	// and pods that started meanwhile are read from the last save. Empty:
	// stateless, a restart starts at the containers' current ends.
	StateFile string `yaml:"state_file"`
	LogLevel  string `yaml:"log_level"`

	OpenPicket struct {
		URL     string            `yaml:"url"`
		HostKey string            `yaml:"host_key"`
		Headers map[string]string `yaml:"headers"`
		CAFile  string            `yaml:"ca_file"`
		// TLSInsecureSkipVerify skips TLS verification (Noise still
		// authenticates the manager).
		TLSInsecureSkipVerify bool `yaml:"tls_insecure_skip_verify"`
		// InflightMaxBytes bounds the unacknowledged batches (default 4MiB).
		InflightMaxBytes int64 `yaml:"inflight_max_bytes"`
	} `yaml:"openpicket"`

	Kubernetes KubeConfig `yaml:"kubernetes"`

	// ScanInterval is how often the pods of the targets are listed
	// (default 10s).
	ScanInterval time.Duration `yaml:"scan_interval"`
	Targets      []Target      `yaml:"targets"`
}

// KubeConfig reaches the Kubernetes API; empty: in-cluster, with the
// pod's ServiceAccount.
type KubeConfig struct {
	APIURL             string `yaml:"api_url"`
	TokenFile          string `yaml:"token_file"`
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Target selects pods of a namespace and how their lines are named. Its
// selections combine (all must match); none selects every pod.
type Target struct {
	Namespace string `yaml:"namespace"`
	// Selector is a label selector ("app.kubernetes.io/name=nginx").
	Selector string `yaml:"selector"`
	// FieldSelector is a field selector ("spec.nodeName=node-1").
	FieldSelector string `yaml:"field_selector"`
	// Workload takes the pods of a workload's selector:
	// "deployment/<name>", "statefulset/<name>", "daemonset/<name>",
	// "replicaset/<name>".
	Workload string `yaml:"workload"`
	// ServiceAccount takes the pods running as it.
	ServiceAccount string `yaml:"service_account"`
	// Pod takes one pod by name.
	Pod string `yaml:"pod"`
	// Containers limits the target to these containers (default: all).
	Containers []string `yaml:"containers"`
	// Program names the lines' program, which selects the CrowdSec parser
	// (nginx, postgres; "syslog" for lines in syslog format). Default:
	// the container name.
	Program string `yaml:"program"`
}

// workload splits Workload.
func (t Target) workload() (kind, name string) {
	kind, name, _ = strings.Cut(t.Workload, "/")
	return kind, name
}

// Describe names the target in the node's status.
func (t Target) Describe() string {
	parts := []string{"k8s " + t.Namespace}
	for _, p := range []struct{ k, v string }{
		{"workload", t.Workload}, {"selector", t.Selector}, {"fields", t.FieldSelector},
		{"serviceaccount", t.ServiceAccount}, {"pod", t.Pod},
	} {
		if p.v != "" {
			parts = append(parts, p.k+"="+p.v)
		}
	}
	if len(t.Containers) > 0 {
		parts = append(parts, "containers="+strings.Join(t.Containers, ","))
	}
	return strings.Join(parts, " ")
}

// ProgramOf returns the program of a container's lines.
func (t Target) ProgramOf(container string) string {
	if t.Program != "" {
		return record.NormalizeProgram(t.Program)
	}
	if p := record.NormalizeProgram(container); p != "" {
		return p
	}
	return "unknown"
}

// dns1123 is a namespace, container or ServiceAccount name.
var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// Load reads and checks a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse reads a configuration.
func Parse(b []byte) (*Config, error) {
	c := &Config{LogLevel: "info", ScanInterval: 10 * time.Second}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	var errs []error
	if err := nodeid.Validate(c.NodeID); err != nil {
		errs = append(errs, fmt.Errorf("node_id: %w", err))
	}
	if c.KeyFile == "" {
		errs = append(errs, errors.New("key_file is required"))
	}
	o := c.OpenPicket
	if !strings.HasPrefix(o.URL, "ws://") && !strings.HasPrefix(o.URL, "wss://") {
		errs = append(errs, errors.New("openpicket.url must start with ws:// or wss://"))
	}
	if _, err := sshkey.ParsePublicKey(o.HostKey); err != nil {
		errs = append(errs, fmt.Errorf("openpicket.host_key: %w", err))
	}
	if c.ScanInterval < time.Second {
		errs = append(errs, errors.New("scan_interval: at least 1s"))
	}
	if len(c.Targets) == 0 {
		errs = append(errs, errors.New("targets: at least one"))
	}
	for i, t := range c.Targets {
		if err := t.validate(); err != nil {
			errs = append(errs, fmt.Errorf("targets[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func (t Target) validate() error {
	if !dns1123.MatchString(t.Namespace) {
		return fmt.Errorf("namespace %q", t.Namespace)
	}
	if t.Workload != "" {
		kind, name := t.workload()
		if _, ok := workloadResources[kind]; !ok || !dns1123.MatchString(name) {
			return fmt.Errorf("workload %q: deployment/<name>, statefulset/<name>, daemonset/<name> or replicaset/<name>", t.Workload)
		}
	}
	for k, v := range map[string]string{"service_account": t.ServiceAccount, "pod": t.Pod} {
		if v != "" && !dns1123.MatchString(v) {
			return fmt.Errorf("%s %q", k, v)
		}
	}
	for _, c := range t.Containers {
		if !dns1123.MatchString(c) {
			return fmt.Errorf("container %q", c)
		}
	}
	if t.Program != "" && record.NormalizeProgram(t.Program) != strings.ToLower(strings.TrimSpace(t.Program)) {
		return fmt.Errorf("program %q: letters, digits, '.', '_', '-' only", t.Program)
	}
	return nil
}
