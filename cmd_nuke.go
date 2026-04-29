// cmd_nuke.go — nuclei integration: fire critical/high templates at targets
//
// Bridges the gap between "Shodan found something interesting" and "nuclei
// confirmed the CVE." Takes a list of IPs, checks that nuclei is installed,
// and runs it with -severity critical,high.
//
// Usage:
//   goharvester nuke 209.10.208.54 66.17.1.5
//   goharvester nuke --severity critical 209.10.208.54
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func cmdNuke(args []string) {
	fs := flag.NewFlagSet("nuke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	severity := fs.String("severity", "critical,high", "nuclei severity filter")
	templatesDir := fs.String("templates", "", "path to custom nuclei templates dir (optional)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	targets := fs.Args()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage: goharvester nuke <ip> [ip...]")
		fmt.Fprintln(os.Stderr, "  e.g. goharvester nuke 209.10.208.54 66.17.1.5")
		os.Exit(1)
	}

	// ── Check nuclei is installed ─────────────────────────────────────────
	nucleiBin, err := exec.LookPath("nuclei")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: nuclei not found in PATH")
		fmt.Fprintln(os.Stderr, "install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
		os.Exit(1)
	}
	fmt.Printf("[*] nuclei: %s\n", nucleiBin)

	// ── Build target list ─────────────────────────────────────────────────
	// nuclei accepts -target per IP or a file with -list. We pass individual
	// -target flags so no temp file is needed.
	cmdArgs := []string{
		"-severity", *severity,
		"-no-color",           // clean output for piping / AI analysis
		"-stats",              // print scan stats at end
		"-timeout", "10",
		"-retries", "1",
	}

	if *templatesDir != "" {
		cmdArgs = append(cmdArgs, "-t", *templatesDir)
	}

	for _, t := range targets {
		// Add https:// prefix if not already present.
		if !strings.HasPrefix(t, "http") {
			t = "https://" + t
		}
		cmdArgs = append(cmdArgs, "-target", t)
	}

	fmt.Printf("[*] targets   : %s\n", strings.Join(targets, ", "))
	fmt.Printf("[*] severity  : %s\n", *severity)
	fmt.Printf("[*] running   : nuclei %s\n", strings.Join(cmdArgs, " "))
	fmt.Println(strings.Repeat("─", 70))

	// ── Execute ───────────────────────────────────────────────────────────
	// Inherit stdout/stderr directly so nuclei's output streams to the
	// terminal in real time. This also means nuclei's colored output appears
	// (unless -no-color suppresses it).
	cmd := exec.Command(nucleiBin, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// nuclei exits non-zero when it finds vulns — that's a success for us.
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Printf("\n[*] nuclei exit code: %d\n", exitErr.ExitCode())
		} else {
			fmt.Fprintf(os.Stderr, "error: nuclei execution failed: %v\n", err)
			os.Exit(1)
		}
	}
}
