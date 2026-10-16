package diagnostics

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/minkinad/portsentinel/internal/security"
)

type Result struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Detail     string `json:"detail,omitempty"`
}
type Report struct {
	Version   int       `json:"version"`
	Target    string    `json:"target"`
	CheckedAt time.Time `json:"checked_at"`
	Results   []Result  `json:"results"`
}

func (r Report) JSON(w io.Writer) error { return json.NewEncoder(w).Encode(r) }
func (r Report) Healthy() bool {
	for _, v := range r.Results {
		if v.Status == "FAIL" {
			return false
		}
	}
	return true
}

type Check interface {
	Name() string
	Run(context.Context, security.Target) Result
}
type Engine struct {
	Policy  security.Policy
	Checks  []Check
	Timeout time.Duration
}

// TODO(portsentinel): Add a bounded multi-target job runner around Engine.
// Suggested approach: use a fixed worker count and a context-aware queue;
// preserve the existing target policy for each job. Acceptance: cancellation
// stops queued work, concurrent jobs never exceed the configured limit.

func New(policy security.Policy, timeout time.Duration) Engine {
	return Engine{Policy: policy, Timeout: timeout, Checks: []Check{tcpCheck{}, tlsCheck{}, httpCheck{}}}
}

func (e Engine) Run(ctx context.Context, raw string) (Report, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	report := Report{Version: 1, Target: redactedTarget(raw), CheckedAt: time.Now().UTC(), Results: []Result{}}
	start := time.Now()
	t, err := e.Policy.Resolve(ctx, raw)
	if err != nil {
		return Report{}, err
	}
	report.Results = append(report.Results, Result{Name: "DNS", Status: "PASS", DurationMS: time.Since(start).Milliseconds(), Detail: t.IP.String()})
	for _, check := range e.Checks {
		if ctx.Err() != nil {
			report.Results = append(report.Results, Result{Name: check.Name(), Status: "SKIP", Detail: ctx.Err().Error()})
			continue
		}
		report.Results = append(report.Results, check.Run(ctx, t))
	}
	return report, nil
}

func redactedTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid target>"
	}
	if u.RawQuery != "" {
		u.RawQuery = "REDACTED"
	}
	u.User = nil
	return u.String()
}

func address(t security.Target) string { return net.JoinHostPort(t.IP.String(), strconv.Itoa(t.Port)) }

type tcpCheck struct{}

func (tcpCheck) Name() string { return "TCP" }
func (tcpCheck) Run(ctx context.Context, t security.Target) Result {
	start := time.Now()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address(t))
	if err != nil {
		return Result{Name: "TCP", Status: "FAIL", DurationMS: time.Since(start).Milliseconds(), Detail: err.Error()}
	}
	_ = c.Close()
	return Result{Name: "TCP", Status: "PASS", DurationMS: time.Since(start).Milliseconds(), Detail: address(t)}
}

type tlsCheck struct{}

func (tlsCheck) Name() string { return "TLS" }
func (tlsCheck) Run(ctx context.Context, t security.Target) Result {
	if t.URL.Scheme != "https" {
		return Result{Name: "TLS", Status: "SKIP", Detail: "HTTP target"}
	}
	start := time.Now()
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{ServerName: t.Host, MinVersion: tls.VersionTLS12}}
	c, err := dialer.DialContext(ctx, "tcp", address(t))
	if err != nil {
		return Result{Name: "TLS", Status: "FAIL", DurationMS: time.Since(start).Milliseconds(), Detail: err.Error()}
	}
	defer func() { _ = c.Close() }()
	state := c.(*tls.Conn).ConnectionState()
	detail := fmt.Sprintf("expires %s", state.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339))
	return Result{Name: "TLS", Status: "PASS", DurationMS: time.Since(start).Milliseconds(), Detail: detail}
}

type httpCheck struct{}

func (httpCheck) Name() string { return "HTTP" }
func (httpCheck) Run(ctx context.Context, t security.Target) Result {
	start := time.Now()
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.Host}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address(t))
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL.String(), nil)
	if err != nil {
		return Result{Name: "HTTP", Status: "FAIL", Detail: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			err = urlErr.Err
		}
		return Result{Name: "HTTP", Status: "FAIL", DurationMS: time.Since(start).Milliseconds(), Detail: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	status := "PASS"
	if resp.StatusCode >= 400 {
		status = "FAIL"
	}
	return Result{Name: "HTTP", Status: status, DurationMS: time.Since(start).Milliseconds(), Detail: fmt.Sprintf("status %d", resp.StatusCode)}
}
