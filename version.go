// version.go — single source of truth for JAXEN's reported version.
//
// Version is set via -ldflags at build time:
//
//	go build -ldflags "-X main.version=v0.2.0 -X main.commit=$(git rev-parse --short HEAD) -X main.buildDate=$(date -u +%Y-%m-%d)" .
//
// If not set, falls back to the source-default below (kept current with the
// CHANGELOG entry so a vanilla `go build` still produces a meaningful string).
package main

import "fmt"

var (
	version   = "v0.2.0-dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func versionString() string {
	return fmt.Sprintf("jaxen %s (commit %s, built %s)", version, commit, buildDate)
}
