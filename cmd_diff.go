// cmd_diff.go — JSON diff: detect new IPs and newly opened ports over time
//
// Every time 'hunt' runs it auto-rotates the previous recon_dump.json to
// recon_dump.old.json before writing the new one. This command compares
// the two files and surfaces net-new assets — the delta of your attack surface.
//
// Flags:
//   --webhook <url>   POST findings to a Discord or Slack webhook URL
//
// Usage:
//   goharvester diff
//   goharvester diff recon_dump.old.json recon_dump.json
//   goharvester diff --webhook https://discord.com/api/webhooks/...
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── Host key ─────────────────────────────────────────────────────────────────

type ipPort struct {
	IP   string
	Port int
}

type hostEntry struct {
	IP        string
	Port      int
	Org       string
	Hostnames []string
	Product   string
}

// loadDumpHosts parses a recon_dump.json and returns a map of ip:port → entry.
func loadDumpHosts(path string) (map[ipPort]hostEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dump struct {
		Hosts []struct {
			IP        string   `json:"ip_str"`
			Port      int      `json:"port"`
			Org       string   `json:"org"`
			Hostnames []string `json:"hostnames"`
			Product   string   `json:"product"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil, err
	}

	m := make(map[ipPort]hostEntry, len(dump.Hosts))
	for _, h := range dump.Hosts {
		key := ipPort{h.IP, h.Port}
		m[key] = hostEntry{
			IP:        h.IP,
			Port:      h.Port,
			Org:       h.Org,
			Hostnames: h.Hostnames,
			Product:   h.Product,
		}
	}
	return m, nil
}

// ── Diff command ──────────────────────────────────────────────────────────────

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	webhookURL := fs.String("webhook", "", "Discord or Slack webhook URL for notifications")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Positional args override default filenames.
	oldFile, newFile := oldDumpFile, dumpFile
	if fs.NArg() >= 2 {
		oldFile, newFile = fs.Arg(0), fs.Arg(1)
	}

	oldHosts, err := loadDumpHosts(oldFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not load old dump (%s): %v\n", oldFile, err)
		fmt.Fprintln(os.Stderr, "hint: run hunt twice; the first run creates the baseline")
		os.Exit(1)
	}
	newHosts, err := loadDumpHosts(newFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not load new dump (%s): %v\n", newFile, err)
		os.Exit(1)
	}

	fmt.Printf("[*] diff: %s (%d) → %s (%d)\n", oldFile, len(oldHosts), newFile, len(newHosts))
	fmt.Println(strings.Repeat("─", 60))

	// ── Find new entries ───────────────────────────────────────────────────
	var newEntries []hostEntry
	for key, h := range newHosts {
		if _, existed := oldHosts[key]; !existed {
			newEntries = append(newEntries, h)
		}
	}

	// ── Find removed entries ───────────────────────────────────────────────
	var removedEntries []hostEntry
	for key, h := range oldHosts {
		if _, stillExists := newHosts[key]; !stillExists {
			removedEntries = append(removedEntries, h)
		}
	}

	if len(newEntries) == 0 && len(removedEntries) == 0 {
		fmt.Println("[+] No changes detected.")
		return
	}

	// ── Print new ─────────────────────────────────────────────────────────
	if len(newEntries) > 0 {
		fmt.Printf("\n%s[+] NEW ASSETS (%d)%s\n", bold, len(newEntries), reset)
		for _, h := range newEntries {
			hostStr := strings.Join(h.Hostnames, ", ")
			fmt.Printf("  %s[NEW]%s %s:%-5d  org=%-30s  hosts=%s  product=%s\n",
				green, reset, h.IP, h.Port, h.Org, hostStr, h.Product)
		}
	}

	// ── Print removed ─────────────────────────────────────────────────────
	if len(removedEntries) > 0 {
		fmt.Printf("\n%s[-] REMOVED ASSETS (%d)%s\n", bold, len(removedEntries), reset)
		for _, h := range removedEntries {
			fmt.Printf("  %s[RMV]%s %s:%-5d  org=%s\n", yellow, reset, h.IP, h.Port, h.Org)
		}
	}

	// ── Webhook notification ───────────────────────────────────────────────
	if *webhookURL != "" && len(newEntries) > 0 {
		if err := sendWebhook(*webhookURL, newEntries); err != nil {
			fmt.Fprintf(os.Stderr, "warn: webhook failed: %v\n", err)
		} else {
			fmt.Printf("\n[+] Webhook sent → %s\n", *webhookURL)
		}
	}
}

// ── Webhook ───────────────────────────────────────────────────────────────────

// webhookPayload adapts to both Discord and Slack based on the URL.
func sendWebhook(webhookURL string, entries []hostEntry) error {
	var lines []string
	lines = append(lines, fmt.Sprintf("🔍 **goharvester diff** — %d NEW ASSET(S) DETECTED", len(entries)))
	lines = append(lines, fmt.Sprintf("Time: %s", time.Now().UTC().Format(time.RFC3339)))
	lines = append(lines, "")
	for _, h := range entries {
		lines = append(lines, fmt.Sprintf("• `%s:%d`  %s  [%s]",
			h.IP, h.Port, h.Org, strings.Join(h.Hostnames, ", ")))
	}
	text := strings.Join(lines, "\n")

	// Discord uses {"content": "..."}, Slack uses {"text": "..."}
	var payload map[string]string
	if strings.Contains(webhookURL, "discord") {
		payload = map[string]string{"content": text}
	} else {
		payload = map[string]string{"text": text}
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// color constants shared across cmd files in the package
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	cyan    = "\033[36m"
	magenta = "\033[35m"
)
