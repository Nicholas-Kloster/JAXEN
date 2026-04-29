// cmd_profile.go — target intelligence classifier
//
// Classifies a target IP/org using heuristics from the aimap-profile research:
// port patterns, SSL cert fields, hostname patterns, and org/ISP data from
// empire.db or a live Shodan lookup.
//
// Classifications:
//   Clinical/HIPAA    — health/hospital/medical keywords in org or cert
//   Research/Academic — university, .edu, lab, academic cert issuers
//   AI Infrastructure — AI/ML service fingerprints detected
//   Personal          — residential ISP, home hosting
//   Honeypot          — known honeypot ISPs
//   Commercial        — standard enterprise/SaaS
//
// Usage:
//   goharvester profile <ip>
//   goharvester profile --org "Tesla"   # classify all empire.db assets for this org
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	hipaaKeywords    = []string{"hospital", "health", "medical", "clinic", "pharma", "patient", "healthcare", "uhmc", "sbuh", "memorial"}
	researchKeywords = []string{"university", "univ", "college", ".edu", "research", "laboratory", "institute", "academic", "suny", "mit", "stanford"}
	honeypotISPs     = []string{"shodan", "project honeypot", "shadowserver", "sans isc", "cymru"}
	aiProfileKW      = []string{"ollama", "vllm", "flowise", "langflow", "chromadb", "mlflow", "llm", "nvidia", "cuda", "gpu", "vector"}
	residentialISPs  = []string{"comcast", "spectrum", "cox", "frontier", "centurylink", "xfinity", "verizon fios"}
)

type profileClass struct {
	Label   string
	Risk    string // HIGH / MEDIUM / LOW
	Warning string
}

func classifyTarget(ip, org, isp string, hostnames []string, notes string) profileClass {
	combined := strings.ToLower(org + " " + isp + " " + strings.Join(hostnames, " ") + " " + notes)

	for _, kw := range honeypotISPs {
		if strings.Contains(combined, kw) {
			return profileClass{"Honeypot", "HIGH",
				"ISP matches known honeypot operator — do not probe further; document the detection signature"}
		}
	}
	for _, kw := range hipaaKeywords {
		if strings.Contains(combined, kw) {
			return profileClass{"Clinical/HIPAA", "HIGH",
				"Healthcare target — HIPAA data likely in scope; verify written authorization before active probing"}
		}
	}
	for _, kw := range researchKeywords {
		if strings.Contains(combined, kw) {
			return profileClass{"Research/Academic", "MEDIUM",
				"Academic institution — publicly funded, check bug bounty policy; responsible disclosure preferred"}
		}
	}
	for _, kw := range aiProfileKW {
		if strings.Contains(combined, kw) {
			return profileClass{"AI Infrastructure", "HIGH",
				"AI/ML service detected — run 'goharvester aimap' for deep enumeration; check for exposed model weights or API keys"}
		}
	}
	for _, kw := range residentialISPs {
		if strings.Contains(isp, kw) {
			return profileClass{"Personal/Residential", "MEDIUM",
				"Residential ISP — likely a personal device; confirm scope explicitly before active probing"}
		}
	}
	return profileClass{"Commercial", "LOW", "Standard enterprise/commercial profile — proceed per engagement rules"}
}

func printProfile(ip, org, isp string, hostnames []string, notes string) {
	p := classifyTarget(ip, org, isp, hostnames, notes)
	riskColor := green
	if p.Risk == "HIGH" {
		riskColor = bold + red
	} else if p.Risk == "MEDIUM" {
		riskColor = yellow
	}
	fmt.Printf("  %s[%s — %s]%s\n", riskColor, p.Label, p.Risk, reset)
	fmt.Printf("  %s\n", p.Warning)
}

func cmdProfile(args []string) {
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	orgFilter := fs.String("org", "", "classify all empire.db assets matching this org substring")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	fmt.Printf("%s%s=== Target Intelligence Profiler ===%s\n\n", bold, cyan, reset)

	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Org-filter mode: classify assets already in empire.db.
	if *orgFilter != "" || fs.NArg() == 0 {
		assets, err := queryAssets(db, *orgFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: query: %v\n", err)
			os.Exit(1)
		}
		if len(assets) == 0 {
			fmt.Printf("No assets in empire.db matching %q\n", *orgFilter)
			fmt.Println("Run a hunt first, or provide an IP: goharvester profile <ip>")
			return
		}
		seen := map[string]bool{}
		for _, a := range assets {
			key := a.Org + "|" + a.ISP
			if seen[key] {
				continue
			}
			seen[key] = true
			fmt.Printf("  org: %-35s  isp: %s\n", a.Org, a.ISP)
			printProfile(a.IP, a.Org, a.ISP, []string{a.Hostname}, a.Notes)
			fmt.Println()
		}
		return
	}

	// Single IP mode: live Shodan host lookup.
	ip := fs.Arg(0)
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: SHODAN_API_KEY not set — use --org to classify from empire.db")
		os.Exit(1)
	}

	fmt.Printf("[*] profiling %s via Shodan ...\n\n", ip)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s&minify=true", ip, apiKey)) //nolint:noctx
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var host struct {
		Org       string   `json:"org"`
		ISP       string   `json:"isp"`
		Hostnames []string `json:"hostnames"`
	}
	json.Unmarshal(body, &host) //nolint:errcheck — partial decode is fine

	fmt.Printf("  IP:       %s\n", ip)
	fmt.Printf("  Org:      %s\n", host.Org)
	fmt.Printf("  ISP:      %s\n", host.ISP)
	fmt.Printf("  Hosts:    %s\n\n", strings.Join(host.Hostnames, ", "))
	printProfile(ip, host.Org, host.ISP, host.Hostnames, "")
}
