// cmd_hunt.go — hunt subcommand
//
// Flags:
//   --clean           strip Google/Amazon/Microsoft/CDN noise
//   --export          write summary.csv
//   --passive <domain> expand attack surface via crt.sh CT logs before querying
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	shodan "github.com/ns3777k/go-shodan/v4/shodan"
)

const dumpFile = "recon_dump.json"
const oldDumpFile = "recon_dump.old.json"
const csvFile = "summary.csv"

// HarvestResult is the top-level JSON structure written to recon_dump.json.
type HarvestResult struct {
	Query     string             `json:"query"`
	Timestamp string             `json:"timestamp"`
	Total     int                `json:"total_results_available"`
	Returned  int                `json:"returned"`
	Hosts     []*shodan.HostData `json:"hosts"`
}

// cdnOrgs are filtered by --clean (case-insensitive substring match on org).
var cdnOrgs = []string{"Google", "Amazon", "Microsoft", "Cloudflare", "Akamai", "Fastly"}

func isCloudNoise(org string) bool {
	up := strings.ToUpper(org)
	for _, n := range cdnOrgs {
		if strings.Contains(up, strings.ToUpper(n)) {
			return true
		}
	}
	return false
}

func cmdHunt(args []string) {
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: jaxen hunt [flags] "<query>"`)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "flags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "examples:")
		fmt.Fprintln(os.Stderr, `  jaxen hunt 'http.html:"Ollama is running"'`)
		fmt.Fprintln(os.Stderr, `  jaxen hunt --max 5000 'product:"Apache" port:8080'`)
		fmt.Fprintln(os.Stderr, `  jaxen hunt --clean --export 'http.title:"Sub2API"'`)
	}
	clean   := fs.Bool("clean", false, "strip CDN/cloud noise")
	export  := fs.Bool("export", false, "write summary.csv")
	passive := fs.String("passive", "", "expand via crt.sh CT logs for this domain (e.g. --passive tesla.com)")
	maxN    := fs.Int("max", 50, "maximum hosts to return (paginates 100/page; counts against Shodan query credits)")
	delay   := fs.Float64("delay", 1.0, "seconds between pages when paginating")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: hunt requires a query argument")
		fs.Usage()
		os.Exit(1)
	}
	query := fs.Arg(0)

	apiKey := shodanAPIKey()
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: no Shodan API key found")
		fmt.Fprintln(os.Stderr, "  set SHODAN_API_KEY or place key at ~/.config/shodan/api_key")
		os.Exit(1)
	}

	// ── Passive expansion via crt.sh ──────────────────────────────────────
	if *passive != "" {
		subs, err := crtshSubdomains(*passive)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: crt.sh expansion failed: %v\n", err)
		} else {
			fmt.Printf("[*] crt.sh: %d subdomains found for %s\n", len(subs), *passive)
			// Append hostname filters for discovered subdomains to the query.
			var extraFilters []string
			for _, s := range subs {
				extraFilters = append(extraFilters, fmt.Sprintf("hostname:%s", s))
			}
			if len(extraFilters) > 0 {
				// Shodan OR syntax: wrap original query and add subs.
				// Limit appended subs to first 10 to avoid overly long queries.
				cap := 10
				if len(extraFilters) < cap {
					cap = len(extraFilters)
				}
				query = fmt.Sprintf("(%s) OR (%s)", query, strings.Join(extraFilters[:cap], " OR "))
				fmt.Printf("[*] expanded query: %s\n", query)
			}
		}
	}

	client := shodan.NewClient(nil, apiKey)
	ctx := context.Background()

	fmt.Printf("[*] querying Shodan: %s\n", query)

	// ── Pagination loop ───────────────────────────────────────────────────
	// Shodan returns 100 matches per page. Paginate until we have *maxN
	// hosts OR the population is exhausted OR we hit a server error.
	var hosts []*shodan.HostData
	var total int
	page := 1
	for {
		opts := &shodan.HostQueryOptions{Query: query, Page: page, Minify: false}
		result, err := client.GetHostsForQuery(ctx, opts)
		if err != nil {
			if page == 1 {
				fmt.Fprintf(os.Stderr, "error: Shodan query failed: %v\n", err)
				os.Exit(1)
			}
			// Late-page failure (often page-~70 500 on basic plan per
			// Insight #35); preserve what we have, warn, and stop.
			fmt.Fprintf(os.Stderr, "warn: pagination stopped at page %d: %v\n", page, err)
			break
		}
		if total == 0 {
			total = result.Total
		}
		if len(result.Matches) == 0 {
			break
		}
		hosts = append(hosts, result.Matches...)
		if *maxN > 0 && len(hosts) >= *maxN {
			hosts = hosts[:*maxN]
			break
		}
		if total > 0 && len(hosts) >= total {
			break
		}
		fmt.Printf("[+] page %3d: cum=%5d / total=%d\n", page, len(hosts), total)
		page++
		if *delay > 0 {
			time.Sleep(time.Duration(*delay * float64(time.Second)))
		}
	}
	if *maxN > 0 && total > *maxN {
		fmt.Fprintf(os.Stderr, "[*] truncated to --max %d of %d available; raise --max to capture more\n", *maxN, total)
	}
	result := struct{ Total int }{Total: total} // for printf below

	// ── --clean ───────────────────────────────────────────────────────────
	if *clean {
		var filtered []*shodan.HostData
		dropped := 0
		for _, h := range hosts {
			if isCloudNoise(h.Organization) {
				dropped++
				continue
			}
			filtered = append(filtered, h)
		}
		fmt.Printf("[*] --clean: dropped %d CDN/cloud, %d remain\n", dropped, len(filtered))
		hosts = filtered
	}
	fmt.Printf("[*] total available: %d  |  returning: %d\n", result.Total, len(hosts))

	// ── Rotate old dump ───────────────────────────────────────────────────
	// Always keep the previous run so 'diff' has a baseline to compare against.
	if _, err := os.Stat(dumpFile); err == nil {
		os.Rename(dumpFile, oldDumpFile)
	}

	// ── Write JSON ────────────────────────────────────────────────────────
	harvest := HarvestResult{
		Query:     query,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Total:     result.Total,
		Returned:  len(hosts),
		Hosts:     hosts,
	}
	data, err := json.MarshalIndent(harvest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: JSON marshal failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(dumpFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", dumpFile, err)
		os.Exit(1)
	}
	fmt.Printf("[+] saved %d bytes → %s\n", len(data), dumpFile)

	// ── SQLite persistence ────────────────────────────────────────────────
	db, dbErr := openDB()
	if dbErr != nil {
		fmt.Fprintf(os.Stderr, "warn: SQLite unavailable: %v\n", dbErr)
	} else {
		defer db.Close()
		upserted := 0
		for _, h := range hosts {
			ip := ""
			if h.IP != nil {
				ip = h.IP.String()
			}
			hn := ""
			if len(h.Hostnames) > 0 {
				hn = h.Hostnames[0]
			}
			if upsertAsset(db, AssetRow{
				IP: ip, Port: h.Port, Org: h.Organization, ISP: h.ISP,
				Hostname: hn, Product: h.Product, Version: fmt.Sprintf("%v", h.Version),
			}) == nil {
				upserted++
			}
		}
		fmt.Printf("[+] empire.db: %d assets upserted\n", upserted)
	}

	// ── --export CSV ──────────────────────────────────────────────────────
	if *export {
		if err := writeCSV(hosts); err != nil {
			fmt.Fprintf(os.Stderr, "error: CSV export: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] CSV → %s (%d rows)\n", csvFile, len(hosts))
	}
}

// writeCSV writes IP,Port,Org,ISP,Hostnames,Product,Version to summary.csv.
func writeCSV(hosts []*shodan.HostData) error {
	f, err := os.Create(csvFile)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"IP", "Port", "Org", "ISP", "Hostnames", "Product", "Version"})
	for _, h := range hosts {
		ip := ""
		if h.IP != nil {
			ip = h.IP.String()
		}
		w.Write([]string{
			ip, fmt.Sprintf("%d", h.Port), h.Organization, h.ISP,
			strings.Join(h.Hostnames, "|"), h.Product, fmt.Sprintf("%v", h.Version),
		})
	}
	w.Flush()
	return w.Error()
}

// ── crt.sh passive expansion ─────────────────────────────────────────────────

// crtshSubdomains queries the Certificate Transparency log at crt.sh for all
// subdomains of the given domain and returns a deduplicated list.
func crtshSubdomains(domain string) ([]string, error) {
	queryURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", url.QueryEscape(domain))
	resp, err := http.Get(queryURL) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// crt.sh returns a JSON array with objects that have a "name_value" field.
	// name_value can contain wildcards (*.example.com) or newline-separated names.
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse: %w", err)
	}

	seen := make(map[string]struct{})
	var results []string
	for _, e := range entries {
		// name_value can be multi-line; split and clean each entry.
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			// Skip wildcards — we can't query them directly.
			if strings.HasPrefix(name, "*") || name == "" {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				results = append(results, name)
			}
		}
	}
	return results, nil
}
