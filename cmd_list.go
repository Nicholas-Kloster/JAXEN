// cmd_list.go — list the SQLite asset empire
//
// Queries empire.db and prints a formatted table of all discovered assets.
// Think of this as "show me my current attack surface."
//
// Usage:
//   goharvester list
//   goharvester list --org Tesla
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	orgFilter := fs.String("org", "", "filter by org name substring")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	total, newToday, orgs := empireStats(db)
	fmt.Printf("%s[*] Empire Stats%s  total=%-5d  new_today=%-4d  orgs=%d\n",
		bold, reset, total, newToday, orgs)
	fmt.Println(strings.Repeat("─", 90))

	assets, err := queryAssets(db, *orgFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: query failed: %v\n", err)
		os.Exit(1)
	}

	if len(assets) == 0 {
		fmt.Println("[+] No assets found. Run 'goharvester hunt' to populate the database.")
		return
	}

	// ── Print table ───────────────────────────────────────────────────────
	fmt.Printf("  %-18s %-6s %-30s %-25s %-15s %s\n",
		"IP", "PORT", "ORG", "HOSTNAME", "PRODUCT", "LAST_SEEN")
	fmt.Println(strings.Repeat("─", 90))

	for _, a := range assets {
		// Truncate long fields for alignment.
		org := truncate(a.Org, 29)
		hn := truncate(a.Hostname, 24)
		prod := truncate(a.Product+" "+a.Version, 14)
		lastSeen := a.LastSeen
		if len(lastSeen) > 10 {
			lastSeen = lastSeen[:10] // date only
		}

		statusColor := green
		if a.Status != "active" {
			statusColor = yellow
		}

		fmt.Printf("  %s%-18s%s %-6d %-30s %-25s %-15s %s\n",
			statusColor, a.IP, reset,
			a.Port, org, hn, prod, lastSeen,
		)
	}
	fmt.Printf("\n  %d assets\n", len(assets))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
