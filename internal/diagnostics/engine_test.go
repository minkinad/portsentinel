package diagnostics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minkinad/portsentinel/internal/security"
)

func TestLocalDiagnostics(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer s.Close()
	u, _ := url.Parse(s.URL)
	port, _ := strconv.Atoi(u.Port())
	e := New(security.Policy{AllowPrivate: true, AllowedPorts: []int{port}}, time.Second)
	report, err := e.Run(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy() || len(report.Results) != 4 {
		t.Fatalf("report=%+v", report)
	}
	if report.Results[2].Status != "SKIP" {
		t.Fatalf("TLS status=%s", report.Results[2].Status)
	}
}

func TestReportRedactsQuery(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer s.Close()
	u, _ := url.Parse(s.URL)
	port, _ := strconv.Atoi(u.Port())
	e := New(security.Policy{AllowPrivate: true, AllowedPorts: []int{port}}, time.Second)
	report, err := e.Run(context.Background(), s.URL+"/?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(report.Target, "secret") || !strings.Contains(report.Target, "REDACTED") {
		t.Fatalf("target=%q", report.Target)
	}
}
