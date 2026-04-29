// cmd_import.go — universal ingest: read IPs/domains from any tool's output
//
// Accepts plain text output from subfinder, assetfinder, nmap, masscan, etc.
// One IP or hostname per line. Enriches each entry via Shodan host lookup and
// upserts all discovered ports/services into the SQLite assets table.
//
// Flags:
//   --no-lookup        skip Shodan API; store entries directly with port=0
//   --delay <secs>     seconds between Shodan API calls (default 1.0)
//   --source <name>    tag the 'notes' field with the originating tool
//
// Usage:
//   subfinder -d target.com -silent | ./goharvester import /dev/stdin
//   ./goharvester import nmap_hosts.txt --source nmap
//   ./goharvester import ips.txt --no-lookup
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	shodan "github.com/ns3777k/go-shodan/v4/shodan"
)

func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	noLookup := fs.Bool("no-lookup", false, "skip Shodan enrichment; store entries with port=0")
	delay    := fs.Float64("delay", 1.0, "seconds between Shodan API calls")
	source   := fs.String("source", "", "tag entries with originating tool (e.g. subfinder)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: goharvester import <file>")
		fmt.Fprintln(os.Stderr, "  e.g. goharvester import hosts.txt")
		fmt.Fprintln(os.Stderr, "       subfinder -d target.com -silent | goharvester import /dev/stdin")
		os.Exit(1)
	}

	filename := fs.Arg(0)

	// ── Open input ────────────────────────────────────────────────────────
	var f *os.File
	var err error
	if filename == "/dev/stdin" || filename == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: open %s: %v\n", filename, err)
			os.Exit(1)
		}
		defer f.Close()
	}

	// ── Read entries ──────────────────────────────────────────────────────
	var entries []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", filename, err)
		os.Exit(1)
	}

	fmt.Printf("[*] import: %d entries from %s\n", len(entries), filename)
	if *noLookup {
		fmt.Println("[*] --no-lookup: storing raw entries without Shodan enrichment")
	}

	// ── Open DB ───────────────────────────────────────────────────────────
	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// ── Process ───────────────────────────────────────────────────────────
	if *noLookup {
		// Fast path: no API calls, just store the raw IP/domain.
		upserted := 0
		for _, entry := range entries {
			ip, port := parseEntry(entry)
			row := AssetRow{
				IP:       ip,
				Port:     port,
				Hostname: entry, // keep original for domains
				Notes:    buildNote(*source, "no-lookup"),
			}
			// If it parsed as an IP, clear the hostname field.
			if net.ParseIP(ip) != nil {
				row.Hostname = ""
			}
			if upsertAsset(db, row) == nil {
				upserted++
			}
		}
		fmt.Printf("[+] stored %d/%d entries → empire.db\n", upserted, len(entries))
		return
	}

	// ── Shodan-enriched path ──────────────────────────────────────────────
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: SHODAN_API_KEY not set (use --no-lookup to skip enrichment)")
		os.Exit(1)
	}
	client := shodan.NewClient(nil, apiKey)
	ctx := context.Background()

	totalUpserted := 0
	delayDur := time.Duration(*delay * float64(time.Second))

	for i, entry := range entries {
		fmt.Printf("[%d/%d] %s ... ", i+1, len(entries), entry)

		rawIP, _ := parseEntry(entry)
		isIP := net.ParseIP(rawIP) != nil

		if isIP {
			// ── IP: host lookup → multiple ports ─────────────────────────
			host, err := client.GetServicesForHost(ctx, rawIP, &shodan.HostServicesOptions{Minify: false})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				time.Sleep(delayDur)
				continue
			}

			portCount := len(host.Data)
			fmt.Printf("%d port(s)\n", portCount)

			for _, svc := range host.Data {
				hn := ""
				if len(host.Hostnames) > 0 {
					hn = host.Hostnames[0]
				}
				row := AssetRow{
					IP:       rawIP,
					Port:     svc.Port,
					Org:      host.Organization,
					ISP:      host.ISP,
					Hostname: hn,
					Product:  svc.Product,
					Version:  fmt.Sprintf("%v", svc.Version),
					Notes:    buildNote(*source, "shodan-host"),
				}
				if upsertAsset(db, row) == nil {
					totalUpserted++
				}
			}
		} else {
			// ── Domain: search API → hostname:<entry> ─────────────────────
			q := fmt.Sprintf("hostname:%s", entry)
			result, err := client.GetHostsForQuery(ctx, &shodan.HostQueryOptions{
				Query: q, Page: 1, Minify: false,
			})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				time.Sleep(delayDur)
				continue
			}

			fmt.Printf("%d result(s)\n", len(result.Matches))
			for _, h := range result.Matches {
				ip := ""
				if h.IP != nil {
					ip = h.IP.String()
				}
				hn := entry
				if len(h.Hostnames) > 0 {
					hn = h.Hostnames[0]
				}
				row := AssetRow{
					IP:       ip,
					Port:     h.Port,
					Org:      h.Organization,
					ISP:      h.ISP,
					Hostname: hn,
					Product:  h.Product,
					Version:  fmt.Sprintf("%v", h.Version),
					Notes:    buildNote(*source, "shodan-search"),
				}
				if upsertAsset(db, row) == nil {
					totalUpserted++
				}
			}
		}

		// Respect Shodan's API rate limit: 1 request/second on free tier.
		if i < len(entries)-1 {
			time.Sleep(delayDur)
		}
	}

	fmt.Printf("\n[+] import complete: %d records upserted → empire.db\n", totalUpserted)
}

// parseEntry splits "ip:port" or returns the raw string as ip with port 0.
func parseEntry(entry string) (ip string, port int) {
	// Handle "ip:port" format.
	if host, portStr, err := net.SplitHostPort(entry); err == nil {
		var p int
		fmt.Sscan(portStr, &p)
		return host, p
	}
	return entry, 0
}

// buildNote formats a source + method tag for the DB notes field.
func buildNote(source, method string) string {
	if source != "" {
		return fmt.Sprintf("imported via %s (%s)", source, method)
	}
	return fmt.Sprintf("imported (%s)", method)
}
