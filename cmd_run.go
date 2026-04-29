// cmd_run.go — ad-hoc Go script execution
//
// A thin wrapper around 'go run' that lets Claude write a custom Go script
// and immediately execute it through the goharvester framework.
//
// Usage: goharvester run <file.go> [args...]
// Example: goharvester run ~/exploit_header.go 209.10.208.54
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func cmdRun(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: goharvester run <file.go> [args...]")
		os.Exit(1)
	}

	goPath, err := exec.LookPath("go")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: go toolchain not found in PATH")
		os.Exit(1)
	}

	// Pass the script and all trailing args to 'go run'.
	cmd := exec.Command(goPath, append([]string{"run"}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	fmt.Printf("[*] go run %s\n", args[0])
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
