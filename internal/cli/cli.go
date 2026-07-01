// Package cli implements the fpcheck subcommands.
package cli

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/North-web-dev/fpcheck/internal/model"
	"github.com/North-web-dev/fpcheck/internal/profiles"
	"github.com/North-web-dev/fpcheck/internal/server"
)

const usage = `fpcheck - TLS/HTTP2 fingerprint tester and differ

Usage:
  fpcheck serve  [--addr :8443]
  fpcheck report [--url https://host:8443/api/all]
  fpcheck run    [--url ...] -- <client command...>
  fpcheck diff   --target <profile> [--url ...]

Commands:
  serve   Run the fingerprinting server (self-signed cert, h2 + http/1.1).
  report  Fetch /api/all and print the fingerprint the server saw.
  run     Execute a client command that hits the server, print its fingerprint.
  diff    Fetch your fingerprint and diff it against a reference profile.

Reference profiles: ` + "%s" + `
`

// Run dispatches argv (excluding the program name) and returns an exit code.
func Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, usage, strings.Join(profiles.Names(), ", "))
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "-h", "--help", "help":
		fmt.Printf(usage, strings.Join(profiles.Names(), ", "))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8443", "listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	srv, err := server.New(*addr)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("fpcheck listening on %s (https, h2 + http/1.1)\n", *addr)
	if err := srv.ListenAndServe(); err != nil {
		return fail(err)
	}
	return 0
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	url := fs.String("url", "https://127.0.0.1:8443/api/all", "fpcheck server /api/all URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fp, err := fetch(*url)
	if err != nil {
		return fail(err)
	}
	printFingerprint(fp)
	return 0
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	_ = fs.String("url", "", "informational: URL the client should target")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return fail(fmt.Errorf("run: provide a client command after --, e.g. -- curl -sk https://127.0.0.1:8443/api/all"))
	}
	out, err := exec.Command(cmdArgs[0], cmdArgs[1:]...).Output()
	if err != nil {
		return fail(fmt.Errorf("client command failed: %w", err))
	}
	fp, err := decode(out)
	if err != nil {
		return fail(fmt.Errorf("client output was not a fingerprint (did it hit /api/all?): %w", err))
	}
	printFingerprint(fp)
	return 0
}

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	target := fs.String("target", "", "reference profile name")
	url := fs.String("url", "https://127.0.0.1:8443/api/all", "fpcheck server /api/all URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" {
		return fail(fmt.Errorf("diff: --target required (have: %s)", strings.Join(profiles.Names(), ", ")))
	}
	ref, meta, err := profiles.Get(*target)
	if err != nil {
		return fail(err)
	}
	got, err := fetch(*url)
	if err != nil {
		return fail(err)
	}
	deltas := model.Diff(got, ref)
	fmt.Printf("diff vs %s (%s)\n  %s\n\n", meta.Name, meta.Description, meta.Accuracy)
	if len(deltas) == 0 {
		fmt.Println("  match: no differences on the reference fields")
		return 0
	}
	for _, d := range deltas {
		fmt.Printf("  %s\n", d)
	}
	return 1
}

func fetch(url string) (*model.Fingerprint, error) {
	// ForceAttemptHTTP2 is required: with a custom TLSClientConfig the transport
	// otherwise stays on HTTP/1.1, so the server never sees an h2 preface and the
	// Akamai fingerprint comes back empty.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
			ForceAttemptHTTP2: true,
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return decode(body)
}

func decode(body []byte) (*model.Fingerprint, error) {
	var fp model.Fingerprint
	if err := json.Unmarshal(body, &fp); err != nil {
		return nil, err
	}
	return &fp, nil
}

func printFingerprint(fp *model.Fingerprint) {
	row := func(k, v string) {
		if v != "" {
			fmt.Printf("  %-11s %s\n", k, v)
		}
	}
	row("JA3", fp.JA3Hash)
	row("JA4", fp.JA4)
	row("JA4H", fp.JA4H)
	row("Akamai H2", fp.AkamaiH2)
	row("TLS", fp.TLSDetail.Version)
	if len(fp.HeaderOrder) > 0 {
		row("Headers", strings.Join(fp.HeaderOrder, " "))
	}
	row("User-Agent", fp.UserAgent)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "fpcheck:", err)
	return 1
}
