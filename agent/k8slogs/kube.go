package k8slogs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// In-cluster ServiceAccount files.
const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	inClusterToken    = serviceAccountDir + "/token"
	inClusterCA       = serviceAccountDir + "/ca.crt"
)

// Kube reads pods and their logs from the Kubernetes API: what `kubectl
// get pods` and `kubectl logs -f` do, without client-go.
type Kube struct {
	base      *url.URL
	tokenFile string
	http      *http.Client
	stream    *http.Client

	mu      sync.Mutex
	token   string
	tokenAt time.Time
}

// NewKube connects to the API: the in-cluster ServiceAccount unless cfg
// names a server.
func NewKube(cfg KubeConfig) (*Kube, error) {
	api, tokenFile, caFile := cfg.APIURL, cfg.TokenFile, cfg.CAFile
	if api == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("kubernetes: not in a cluster (KUBERNETES_SERVICE_HOST unset): set kubernetes.api_url")
		}
		api = "https://" + net.JoinHostPort(host, port)
		if tokenFile == "" {
			tokenFile = inClusterToken
		}
		if caFile == "" {
			caFile = inClusterCA
		}
	}
	base, err := url.Parse(api)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("kubernetes.api_url %q: not a URL", api)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kubernetes: no certificate in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsCfg, ResponseHeaderTimeout: 30 * time.Second}
	return &Kube{base: base, tokenFile: tokenFile,
		http:   &http.Client{Transport: tr, Timeout: 30 * time.Second},
		stream: &http.Client{Transport: tr}}, nil
}

// bearer returns the token, read again every minute (projected
// ServiceAccount tokens rotate).
func (k *Kube) bearer() string {
	if k.tokenFile == "" {
		return ""
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.tokenAt) > time.Minute {
		if b, err := os.ReadFile(k.tokenFile); err == nil {
			k.token, k.tokenAt = strings.TrimSpace(string(b)), time.Now()
		}
	}
	return k.token
}

func (k *Kube) do(ctx context.Context, c *http.Client, path string, q url.Values) (*http.Response, error) {
	u := *k.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if t := k.bearer(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		var st struct {
			Message string `json:"message"`
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		if json.Unmarshal(b, &st) != nil || st.Message == "" {
			st.Message = strings.TrimSpace(string(b))
		}
		return nil, &APIError{Code: res.StatusCode, Message: st.Message}
	}
	return res, nil
}

// APIError is an error status of the API.
type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("kubernetes: %d %s", e.Code, e.Message) }

func (k *Kube) get(ctx context.Context, path string, q url.Values, v any) error {
	res, err := k.do(ctx, k.http, path, q)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(v)
}

// Pod is what the collector needs of a pod.
type Pod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Name string `json:"name"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name  string `json:"name"`
			State struct {
				Running *struct {
					StartedAt time.Time `json:"startedAt"`
				} `json:"running"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

// Running reports whether a container of the pod runs (its log can be
// followed).
func (p *Pod) Running(container string) bool {
	for _, s := range p.Status.ContainerStatuses {
		if s.Name == container {
			return s.State.Running != nil
		}
	}
	return false
}

// Pods lists the pods of a namespace matching the selectors.
func (k *Kube) Pods(ctx context.Context, namespace, labels, fields string) ([]Pod, error) {
	q := url.Values{}
	if labels != "" {
		q.Set("labelSelector", labels)
	}
	if fields != "" {
		q.Set("fieldSelector", fields)
	}
	var list struct {
		Items []Pod `json:"items"`
	}
	if err := k.get(ctx, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods", q, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// labelSelector is a metav1.LabelSelector.
type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

// String writes the selector in the API's label selector syntax.
func (s labelSelector) String() (string, error) {
	var parts []string
	keys := make([]string, 0, len(s.MatchLabels))
	for k := range s.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+s.MatchLabels[k])
	}
	for _, e := range s.MatchExpressions {
		switch e.Operator {
		case "In":
			parts = append(parts, e.Key+" in ("+strings.Join(e.Values, ",")+")")
		case "NotIn":
			parts = append(parts, e.Key+" notin ("+strings.Join(e.Values, ",")+")")
		case "Exists":
			parts = append(parts, e.Key)
		case "DoesNotExist":
			parts = append(parts, "!"+e.Key)
		default:
			return "", fmt.Errorf("selector operator %q", e.Operator)
		}
	}
	if len(parts) == 0 {
		return "", errors.New("empty selector (it would match every pod)")
	}
	return strings.Join(parts, ","), nil
}

// workloadResources maps workload kinds to their API resources.
var workloadResources = map[string]string{
	"deployment": "deployments", "statefulset": "statefulsets", "daemonset": "daemonsets", "replicaset": "replicasets",
}

// WorkloadSelector returns the label selector of a workload's pods.
func (k *Kube) WorkloadSelector(ctx context.Context, namespace, kind, name string) (string, error) {
	res, ok := workloadResources[kind]
	if !ok {
		return "", fmt.Errorf("workload kind %q", kind)
	}
	var w struct {
		Spec struct {
			Selector labelSelector `json:"selector"`
		} `json:"spec"`
	}
	if err := k.get(ctx, "/apis/apps/v1/namespaces/"+url.PathEscape(namespace)+"/"+res+"/"+url.PathEscape(name), nil, &w); err != nil {
		return "", err
	}
	return w.Spec.Selector.String()
}

// LogOptions select where a log stream starts: after SinceTime (second
// precision), the last TailLines lines (TailLines < 0: from the start).
type LogOptions struct {
	SinceTime time.Time
	TailLines int
}

// Logs follows a container's log, each line prefixed with its timestamp.
func (k *Kube) Logs(ctx context.Context, namespace, pod, container string, o LogOptions) (io.ReadCloser, error) {
	q := url.Values{"container": {container}, "follow": {"true"}, "timestamps": {"true"}}
	switch {
	case !o.SinceTime.IsZero():
		q.Set("sinceTime", o.SinceTime.UTC().Format(time.RFC3339))
	case o.TailLines >= 0:
		q.Set("tailLines", fmt.Sprint(o.TailLines))
	}
	res, err := k.do(ctx, k.stream, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods/"+url.PathEscape(pod)+"/log", q)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}
