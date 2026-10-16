package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/minkinad/portsentinel/internal/config"
	"github.com/minkinad/portsentinel/internal/diagnostics"
	"github.com/minkinad/portsentinel/internal/security"
	"github.com/minkinad/portsentinel/internal/server"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 1 && args[0] == "healthcheck" {
		c := &http.Client{Timeout: time.Second}
		resp, err := c.Get("http://127.0.0.1:8081/health/live")
		if err != nil {
			return 1
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			return 1
		}
		return 0
	}
	fs := flag.NewFlagSet("portsentinel-server", flag.ContinueOnError)
	path := fs.String("config", "configs/portsentinel.yaml", "YAML settings")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	logger := c.Logger()
	d, _ := time.ParseDuration(c.Checks.Timeout)
	allow, deny := c.CIDRs()
	engine := diagnostics.New(security.Policy{AllowedPorts: c.Checks.AllowedPorts, AllowCIDRs: allow, DenyCIDRs: deny}, d)
	srv := &http.Server{Addr: c.Server.Listen, Handler: server.New(engine, logger, c.Server.MaxConcurrent).Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		end, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(end)
	}()
	logger.Info("listening", "address", c.Server.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		return 1
	}
	return 0
}
