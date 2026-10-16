package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/minkinad/portsentinel/internal/config"
	"github.com/minkinad/portsentinel/internal/diagnostics"
	"github.com/minkinad/portsentinel/internal/security"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(os.Stderr, "usage: portsentinel check [--config path] [--format text|json] [--timeout 5s] [--allow-private] URL")
		return 2
	}
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("config", "", "YAML settings")
	format := fs.String("format", "text", "text or json")
	timeout := fs.String("timeout", "", "check timeout")
	output := fs.String("output", "", "write report to file")
	allowPrivate := fs.Bool("allow-private", false, "allow private targets for local diagnostics")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
		return 2
	}
	c, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *timeout != "" {
		c.Checks.Timeout = *timeout
		if err := c.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	d, _ := time.ParseDuration(c.Checks.Timeout)
	allow, deny := c.CIDRs()
	report, err := diagnostics.New(security.Policy{AllowPrivate: *allowPrivate, AllowedPorts: c.Checks.AllowedPorts, AllowCIDRs: allow, DenyCIDRs: deny}, d).Run(context.Background(), fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	w := os.Stdout
	if *output != "" {
		w, err = os.Create(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		defer func() { _ = w.Close() }()
	}
	switch *format {
	case "json":
		err = report.JSON(w)
	case "text":
		err = writeTextReport(w, report)
	default:
		fmt.Fprintln(os.Stderr, "invalid format")
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !report.Healthy() {
		return 1
	}
	return 0
}

func writeTextReport(w io.Writer, report diagnostics.Report) error {
	if _, err := fmt.Fprintf(w, "Target: %s\n", report.Target); err != nil {
		return err
	}
	for _, v := range report.Results {
		if _, err := fmt.Fprintf(w, "%-5s %-4s %4dms %s\n", v.Name, v.Status, v.DurationMS, v.Detail); err != nil {
			return err
		}
	}
	return nil
}
