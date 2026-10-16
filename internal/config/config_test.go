package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsInvalidSecurityPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.WriteFile(path, []byte("checks:\n  timeout: 5s\n  allowed_ports: [80]\n  deny_cidrs: [not-a-cidr]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid CIDR error")
	}
}

func TestEnvironmentOverridesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: '127.0.0.1:9000'\n  max_concurrent: 2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORTSENTINEL_LISTEN", "127.0.0.1:9001")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != "127.0.0.1:9001" {
		t.Fatalf("listen=%q", c.Server.Listen)
	}
}
