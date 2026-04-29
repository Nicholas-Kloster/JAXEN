// cmd_menlo_hunt.go — Menlo Security enterprise gateway analysis
//
// Searches for Menlo Security isolation infrastructure via JARM hashes,
// response headers, and TLS certificate patterns. For each identified
// Menlo node, extracts the protected organization's CN from the SSL cert
// and searches Shodan for the origin server exposed outside the gateway.
//
// Usage:
//   goharvester menlo-hunt
//   goharvester menlo-hunt --org "Tesla"   # scope to one org
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// menloQueries are the JARM-hash and header-based queries for Menlo infra.
var menloQueries = []struct {
	Label string
	Query string
	Note  string
}{
	{
		"Header — X-Menlo-Security-IP",
		`http.headers:"X-Menlo-Security-IP"`,
		"Menlo isolation cloud response header — confirms gateway relay",
	},
	{
		"Cert CN — *-isolation.com",
		`ssl.cert.subject.cn:"isolation.com"`,
		"Isolation subdomain cert — pivot to org cert for origin discovery",
	},
	{
		"Cert CN — *.menlosecurity.com",
		`ssl.cert.subject.cn:"menlosecurity.com"`,
		"Menlo infra cert — correlate with protected org name in Issuer O field",
	},
	{
		"Header — X-Menlo-Client-IP",
		`http.headers:"X-Menlo-Client-IP"`,
		"Forwarded client IP in Menlo headers — potential internal IP leak",
	},
	{
		"Title — Menlo Security",
		`http.title:"Menlo Security"`,
		"Menlo admin / status portal exposed externally",
	},
}

// menloSearchRaw performs a Shodan host search and returns the raw JSON.
func menloSearchRaw(apiKey, query string) ([]byte, error) {
	u := "https://api.shodan.io/shodan/host/search"
	params := url.Values{}
	params.Set("key", apiKey)
	params.Set("query", query)
	params.Set("minify", "false")
	params.Set("page", "1")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(u + "?" + params.Encode()) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf strings.Builder
	var tmp [4096]byte
	for {
		n, rerr := resp.Body.Read(tmp[:])
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if rerr != nil {
			break
		}
	}
	return []byte(buf.String()), nil
}

// originSearchQuery builds a Shodan dork to find origin servers for a given org name
// by searching for the org's SSL CN *excluding* Menlo Security's ASN.
func originSearchQuery(orgName string) string {
	// Strip wildcard prefix if present.
	clean := strings.TrimPrefix(orgName, "*.")
	// The idea: find hosts whose cert CN matches the target org but are NOT
	// hosted within Menlo's infrastructure (ASN 398101 or org:"Menlo Security").
	return fmt.Sprintf(`ssl.cert.subject.cn:"%s" -org:"Menlo Security"`, clean)
}

type menloHost struct {
	IP        string   `json:"ip_str"`
	Port      int      `json:"port"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
	Hostnames []string `json:"hostnames"`
	SSL       *struct {
		Cert *struct {
			Subject struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Issuer struct {
				O  string `json:"O"`
				CN string `json:"CN"`
			} `json:"issuer"`
		} `json:"cert"`
	} `json:"ssl"`
}

func cmdMenloHunt(args []string) {
	fs := flag.NewFlagSet("menlo-hunt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	orgFilter := fs.String("org", "", "restrict origin search to this org name")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: SHODAN_API_KEY not set")
		os.Exit(1)
	}

	fmt.Printf("%s[*] Menlo Security Hunt — enterprise gateway JARM + origin discovery%s\n", bold, reset)
	if *orgFilter != "" {
		fmt.Printf("[*] org filter: %q\n", *orgFilter)
	}
	fmt.Println(strings.Repeat("─", 70))

	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: SQLite unavailable: %v\n", err)
	}
	if db != nil {
		defer db.Close()
	}

	// Track unique CN values seen so we only run origin searches once per org.
	originSearched := map[string]bool{}
	totalGateway := 0
	totalOrigin := 0

	for qi, q := range menloQueries {
		fmt.Printf("\n[%d/%d] %s\n  query: %s\n  note:  %s\n",
			qi+1, len(menloQueries), q.Label, q.Query, q.Note)

		raw, err := menloSearchRaw(apiKey, q.Query)
		if err != nil {
			fmt.Printf("  error: %v\n", err)
			time.Sleep(time.Second)
			continue
		}

		var result struct {
			Total   int          `json:"total"`
			Matches []menloHost  `json:"matches"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			fmt.Printf("  parse error: %v\n", err)
			time.Sleep(time.Second)
			continue
		}

		fmt.Printf("  total=%d  returned=%d\n", result.Total, len(result.Matches))
		totalGateway += len(result.Matches)

		for _, m := range result.Matches {
			hn := strings.Join(m.Hostnames, ",")
			fmt.Printf("  %s[GATEWAY]%s %-18s :%d  org=%-30s  hosts=%s\n",
				yellow, reset, m.IP, m.Port, m.Org, hn)

			// Check for internal IP leak in X-Forwarded-For type headers (banner analysis).
			// The actual header values would be in the raw banner; we flag the host for goprobe.
			if strings.Contains(q.Label, "Client-IP") {
				fmt.Printf("    %s[!] Potential internal IP leak — probe with goprobe for header reflection%s\n", red, reset)
			}

			if db != nil {
				upsertAsset(db, AssetRow{
					IP:       m.IP,
					Port:     m.Port,
					Org:      m.Org,
					ISP:      m.ISP,
					Hostname: hn,
					Notes:    "menlo-hunt:gateway",
				})
			}

			// Extract CN from SSL cert and search for origin server.
			if m.SSL != nil && m.SSL.Cert != nil {
				cn := m.SSL.Cert.Subject.CN
				issuerOrg := m.SSL.Cert.Issuer.O

				// Skip Menlo's own wildcard certs.
				if cn != "" && !strings.Contains(cn, "menlosecurity.com") && !originSearched[cn] {
					// If an org filter is set, only chase CNs that match.
					if *orgFilter == "" || strings.Contains(strings.ToLower(cn), strings.ToLower(*orgFilter)) {
						originSearched[cn] = true
						originQ := originSearchQuery(cn)
						fmt.Printf("\n  %s[ORIGIN SEARCH]%s CN=%q  issuer=%q\n", cyan, reset, cn, issuerOrg)
						fmt.Printf("  query: %s\n", originQ)

						time.Sleep(time.Second)

						oRaw, err := menloSearchRaw(apiKey, originQ)
						if err != nil {
							fmt.Printf("  origin search error: %v\n", err)
							continue
						}

						var oResult struct {
							Total   int          `json:"total"`
							Matches []menloHost  `json:"matches"`
						}
						if err := json.Unmarshal(oRaw, &oResult); err != nil {
							fmt.Printf("  origin parse error: %v\n", err)
							continue
						}

						if oResult.Total == 0 {
							fmt.Printf("  %s[→] no exposed origin found for %s%s\n", yellow, cn, reset)
						} else {
							totalOrigin += len(oResult.Matches)
							for _, o := range oResult.Matches {
								oHN := strings.Join(o.Hostnames, ",")
								fmt.Printf("  %s[ORIGIN EXPOSED]%s %-18s :%d  org=%-25s  hosts=%s\n",
									bold+red, reset, o.IP, o.Port, o.Org, oHN)
								fmt.Printf("    → curl -sk --resolve '%s:%d:%s' 'https://%s/' -I\n",
									cn, o.Port, o.IP, cn)

								if db != nil {
									upsertAsset(db, AssetRow{
										IP:       o.IP,
										Port:     o.Port,
										Org:      o.Org,
										ISP:      o.ISP,
										Hostname: oHN,
										Notes:    fmt.Sprintf("menlo-hunt:origin cn=%s", cn),
									})
								}
							}
						}
					}
				}
			}
		}

		if qi < len(menloQueries)-1 {
			time.Sleep(time.Second)
		}
	}

	fmt.Printf("\n%s[+] menlo-hunt complete%s\n", bold, reset)
	fmt.Printf("    gateway nodes : %d\n", totalGateway)
	fmt.Printf("    exposed origins: %d\n", totalOrigin)
	if db != nil {
		fmt.Println("    results → empire.db")
	}

	if totalOrigin > 0 {
		fmt.Printf("\n%s[!] EXPOSED ORIGINS FOUND — run goprobe against these IPs immediately%s\n", bold+red, reset)
		fmt.Printf("    Cross-check with ai-hunt: if any origin runs AI/LLM services, flag as\n")
		fmt.Printf("    [CRITICAL: PROTECTED AI INFRASTRUCTURE — GATEWAY BYPASS POSSIBLE]\n")
	}
}
