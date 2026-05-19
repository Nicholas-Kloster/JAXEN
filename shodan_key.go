// shodan_key.go — Shodan API key resolution with fallback chain.
//
// Order:
//   1. SHODAN_API_KEY environment variable
//   2. ~/.config/shodan/api_key (the canonical Shodan-CLI location)
//
// Returns "" if neither source has a key; callers decide whether that's fatal.
package main

import (
	"os"
	"path/filepath"
	"strings"
)

func shodanAPIKey() string {
	if k := strings.TrimSpace(os.Getenv("SHODAN_API_KEY")); k != "" {
		return k
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".config", "shodan", "api_key"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
