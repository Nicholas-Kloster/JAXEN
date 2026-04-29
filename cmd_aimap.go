// cmd_aimap.go — thin wrapper around the aimap binary
//
// aimap (github.com/Nicholas-Kloster/aimap) is the authoritative AI/ML
// infrastructure scanner with 26 deep enumerators. This wrapper integrates
// it into the goharvester workflow so results feed into empire.db and the
// analyze chain.
//
// Usage:
//   goharvester aimap <ip>
//   goharvester aimap <cidr>              # subnet sweep for shadow AI
//   goharvester aimap <ip> <hostname>     # with vhost
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// aimapBinaryPaths is the search order for the aimap binary.
var aimapBinaryPaths = []string{
	os.Getenv("HOME") + "/ai-recon/aimap/aimap",
	os.Getenv("HOME") + "/go/bin/aimap",
	"/usr/local/bin/aimap",
}

func cmdAIMap(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: goharvester aimap <ip|cidr> [hostname...]")
		fmt.Fprintln(os.Stderr, "  e.g. goharvester aimap 10.0.0.0/24")
		fmt.Fprintln(os.Stderr, "       goharvester aimap 192.168.1.50 ollama.internal")
		os.Exit(1)
	}

	// Locate aimap binary.
	binary := ""
	for _, p := range aimapBinaryPaths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			binary = p
			break
		}
	}
	if binary == "" {
		// Fall back to PATH lookup.
		if path, err := exec.LookPath("aimap"); err == nil {
			binary = path
		}
	}
	if binary == "" {
		fmt.Fprintln(os.Stderr, "error: aimap binary not found")
		fmt.Fprintln(os.Stderr, "install: go install github.com/Nicholas-Kloster/aimap@latest")
		fmt.Fprintln(os.Stderr, "   or:   cd ~/ai-recon/aimap && go build -o aimap .")
		os.Exit(1)
	}

	fmt.Printf("[*] aimap  binary=%s  target=%s\n", binary, strings.Join(args, " "))
	fmt.Println(strings.Repeat("─", 70))

	cmd := exec.Command(binary, args...) //nolint:gosec
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		// aimap exits non-zero on no findings — treat as non-fatal.
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
