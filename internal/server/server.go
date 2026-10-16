package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/minkinad/portsentinel/internal/diagnostics"
)

type Server struct {
	Engine    diagnostics.Engine
	Logger    *slog.Logger
	slots     chan struct{}
	requestID atomic.Uint64
}

func New(engine diagnostics.Engine, logger *slog.Logger, maxConcurrent int) *Server {
	return &Server{Engine: engine, Logger: logger, slots: make(chan struct{}, maxConcurrent)}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("POST /v1/check", s.check)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "\r\n") {
			id = strconv.FormatUint(s.requestID.Add(1), 10)
		}
		w.Header().Set("X-Request-ID", id)
		mux.ServeHTTP(w, r)
		s.Logger.Info("request", "request_id", id, "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}
func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "server busy", http.StatusTooManyRequests)
		return
	}
	defer func() { _ = r.Body.Close() }()
	var input struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil || strings.TrimSpace(input.Target) == "" {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	report, err := s.Engine.Run(r.Context(), input.Target)
	if err != nil {
		s.Logger.Warn("target rejected", "request_id", w.Header().Get("X-Request-ID"), "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}
