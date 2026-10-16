package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minkinad/portsentinel/internal/diagnostics"
	"github.com/minkinad/portsentinel/internal/security"
)

func TestServerRejectsPrivateTarget(t *testing.T) {
	s := New(diagnostics.New(security.Policy{AllowedPorts: []int{80, 443}}, time.Second), slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	for _, path := range []string{"/health/live", "/health/ready"} {
		r := httptest.NewRecorder()
		s.Handler().ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 200 {
			t.Fatalf("%s status=%d", path, r.Code)
		}
	}
	r := httptest.NewRecorder()
	s.Handler().ServeHTTP(r, httptest.NewRequest("POST", "/v1/check", strings.NewReader(`{"target":"http://127.0.0.1"}`)))
	if r.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", r.Code, r.Body.String())
	}
}
