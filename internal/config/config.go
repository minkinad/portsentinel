package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Listen        string `yaml:"listen"`
		MaxConcurrent int    `yaml:"max_concurrent"`
	} `yaml:"server"`
	Checks struct {
		Timeout      string   `yaml:"timeout"`
		AllowedPorts []int    `yaml:"allowed_ports"`
		AllowCIDRs   []string `yaml:"allow_cidrs"`
		DenyCIDRs    []string `yaml:"deny_cidrs"`
	} `yaml:"checks"`
	Log struct {
		Format string `yaml:"format"`
		Level  string `yaml:"level"`
	} `yaml:"log"`
}

func Load(path string) (Config, error) {
	c := Config{}
	c.Server.Listen = "127.0.0.1:8081"
	c.Server.MaxConcurrent = 4
	c.Checks.Timeout = "5s"
	c.Checks.AllowedPorts = []int{80, 443}
	c.Log.Format = "json"
	c.Log.Level = "info"
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("decode config: %w", err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return c, errors.New("multiple YAML documents are not supported")
		}
	}
	if v := os.Getenv("PORTSENTINEL_LISTEN"); v != "" {
		c.Server.Listen = v
	}
	if v := os.Getenv("PORTSENTINEL_TIMEOUT"); v != "" {
		c.Checks.Timeout = v
	}
	if v := os.Getenv("PORTSENTINEL_LOG_FORMAT"); v != "" {
		c.Log.Format = v
	}
	if v := os.Getenv("PORTSENTINEL_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Server.Listen); err != nil {
		return fmt.Errorf("server.listen: %w", err)
	}
	if c.Server.MaxConcurrent < 1 || c.Server.MaxConcurrent > 64 {
		return errors.New("server.max_concurrent must be 1..64")
	}
	d, err := time.ParseDuration(c.Checks.Timeout)
	if err != nil || d <= 0 || d > time.Minute {
		return errors.New("checks.timeout must be within (0, 1m]")
	}
	if c.Log.Format != "json" && c.Log.Format != "text" {
		return errors.New("log.format must be json or text")
	}
	if !strings.Contains(" debug info warn error ", " "+c.Log.Level+" ") {
		return errors.New("invalid log.level")
	}
	if len(c.Checks.AllowedPorts) == 0 {
		return errors.New("checks.allowed_ports must not be empty")
	}
	for _, p := range c.Checks.AllowedPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid allowed port %s", strconv.Itoa(p))
		}
	}
	for _, raw := range append(append([]string{}, c.Checks.AllowCIDRs...), c.Checks.DenyCIDRs...) {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
	}
	return nil
}

func (c Config) CIDRs() (allow, deny []netip.Prefix) {
	for _, raw := range c.Checks.AllowCIDRs {
		allow = append(allow, netip.MustParsePrefix(raw))
	}
	for _, raw := range c.Checks.DenyCIDRs {
		deny = append(deny, netip.MustParsePrefix(raw))
	}
	return
}

func (c Config) Logger() *slog.Logger {
	var level slog.Level
	switch c.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if c.Log.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}
