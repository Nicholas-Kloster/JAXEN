// cmd_buckets.go — cloud storage bucket enumeration (no SDK required)
//
// Generates candidate bucket names from an org name using common naming
// conventions, then probes S3 / GCP / Azure with concurrent HEAD requests.
//
// Result codes:
//   200  → PUBLICLY READABLE — bucket exists and returns data without auth
//   403  → EXISTS (PRIVATE)  — bucket exists but access is denied
//   404  → not found
//   other/err → skip
//
// Finds are stored in the 'cloud_assets' SQLite table.
//
// Usage:
//   goharvester buckets Tesla
//   goharvester buckets "Tesla Motors" --workers 50
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Naming patterns ───────────────────────────────────────────────────────────

// bucketSuffixes are appended to the normalized org name.
// Based on common real-world exposure patterns.
var bucketSuffixes = []string{
	"", "-prod", "-production", "-dev", "-development", "-staging", "-stage",
	"-backup", "-backups", "-bak", "-internal", "-private",
	"-data", "-database", "-db", "-assets", "-static", "-media",
	"-logs", "-log", "-audit", "-public", "-files", "-uploads",
	"-archive", "-archives", "-old", "-new", "-temp", "-tmp",
	"-config", "-configs", "-secrets", "-keys", "-certs",
	"-reports", "-analytics", "-infra", "-infrastructure",
	"-security", "-test", "-testing", "-qa", "-sandbox",
	"-engineering", "-eng", "-cloud", "-ops", "-devops",
	"-hr", "-legal", "-finance", "-billing",
}

// bucketProviders maps provider name to a URL template.
// %s is replaced with the bucket/account name.
var bucketProviders = map[string]string{
	"S3":    "https://%s.s3.amazonaws.com/",
	"GCP":   "https://%s.storage.googleapis.com/",
	"Azure": "https://%s.blob.core.windows.net/",
}

// ── Name normalization ────────────────────────────────────────────────────────

var nonAlnum = regexp.MustCompile(`[^a-z0-9-]`)

// normalizeOrgName converts "Tesla Motors, Inc." → "tesla-motors"
// following S3/GCP bucket naming rules: lowercase, alphanumeric + hyphens.
func normalizeOrgName(org string) string {
	lower := strings.ToLower(org)
	// Replace spaces with hyphens.
	lower = strings.ReplaceAll(lower, " ", "-")
	// Strip non-alphanumeric/hyphen characters.
	clean := nonAlnum.ReplaceAllString(lower, "")
	// Collapse multiple consecutive hyphens.
	for strings.Contains(clean, "--") {
		clean = strings.ReplaceAll(clean, "--", "-")
	}
	return strings.Trim(clean, "-")
}

// ── Probe types ───────────────────────────────────────────────────────────────

type BucketTarget struct {
	Provider   string
	BucketName string
	URL        string
}

type BucketResult struct {
	BucketTarget
	StatusCode int
	Public     bool
	Err        error
}

// ── Probe function ────────────────────────────────────────────────────────────

// probeBucket fires a HEAD request to the bucket URL.
// HEAD is used because it's fast, doesn't download body, and S3/GCP return
// meaningful status codes (200/403/404) for HEAD requests on bucket roots.
func probeBucket(target BucketTarget, client *http.Client) BucketResult {
	res := BucketResult{BucketTarget: target}

	resp, err := client.Head(target.URL) //nolint:noctx
	if err != nil {
		res.Err = err
		return res
	}
	resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.Public = resp.StatusCode == 200
	return res
}

// ── Command ───────────────────────────────────────────────────────────────────

func cmdBuckets(args []string) {
	fs := flag.NewFlagSet("buckets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workers := fs.Int("workers", 30, "concurrent HEAD request workers")
	timeout := fs.Int("timeout", 8, "HTTP request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: goharvester buckets <org-name> [--workers N]")
		fmt.Fprintln(os.Stderr, `  e.g. goharvester buckets Tesla`)
		fmt.Fprintln(os.Stderr, `       goharvester buckets "Tesla Motors" --workers 50`)
		os.Exit(1)
	}

	orgName := strings.Join(fs.Args(), " ")
	base := normalizeOrgName(orgName)

	fmt.Printf("[*] buckets  org=%q  base=%q  workers=%d\n", orgName, base, *workers)

	// ── Generate targets ──────────────────────────────────────────────────
	var targets []BucketTarget
	for _, suffix := range bucketSuffixes {
		bucketName := base + suffix
		for provider, urlTemplate := range bucketProviders {
			targets = append(targets, BucketTarget{
				Provider:   provider,
				BucketName: bucketName,
				URL:        fmt.Sprintf(urlTemplate, bucketName),
			})
		}
	}
	fmt.Printf("[*] probing  %d candidate URLs (%d names × %d providers)\n",
		len(targets), len(bucketSuffixes), len(bucketProviders))
	fmt.Println(strings.Repeat("─", 70))

	// ── HTTP client ───────────────────────────────────────────────────────
	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		// Don't follow redirects — a 301 from S3 is itself information.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// ── Worker pool ───────────────────────────────────────────────────────
	// targetCh feeds work to workers; resultCh collects results.
	// This is the classic Go worker pool pattern: fixed number of goroutines
	// read from a shared channel until it's closed, then signal done via WaitGroup.
	targetCh := make(chan BucketTarget, len(targets))
	resultCh := make(chan BucketResult, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targetCh {
				resultCh <- probeBucket(t, client)
			}
		}()
	}

	// Feed all targets into the channel, then close it so workers exit.
	for _, t := range targets {
		targetCh <- t
	}
	close(targetCh)

	// Close resultCh once all workers are done.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// ── Collect and print findings ────────────────────────────────────────
	var found []BucketResult
	for r := range resultCh {
		if r.Err != nil || r.StatusCode == 0 || r.StatusCode == 404 {
			continue // not found or network error — expected, skip
		}
		found = append(found, r)

		switch r.StatusCode {
		case 200:
			fmt.Printf("  %s[PUBLIC 200]%s %-8s %s\n",
				bold+green, reset, r.Provider, r.URL)
		case 403:
			fmt.Printf("  %s[EXISTS 403]%s %-8s %s\n",
				bold+yellow, reset, r.Provider, r.URL)
		default:
			fmt.Printf("  %s[%d]%s         %-8s %s\n",
				yellow, r.StatusCode, reset, r.Provider, r.URL)
		}
	}

	// ── Summary ───────────────────────────────────────────────────────────
	public := 0
	exists := 0
	for _, r := range found {
		if r.Public {
			public++
		} else {
			exists++
		}
	}

	fmt.Printf("\n[*] results: %s%d public%s  %d exists-private  %d total found\n",
		bold+green, public, reset, exists, len(found))

	if len(found) == 0 {
		fmt.Println("[+] No buckets found.")
		return
	}

	// ── Persist to SQLite ─────────────────────────────────────────────────
	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: SQLite unavailable: %v\n", err)
		return
	}
	defer db.Close()

	saved := 0
	for _, r := range found {
		if upsertCloudAsset(db, CloudAssetRow{
			Org:        orgName,
			Provider:   r.Provider,
			BucketName: r.BucketName,
			URL:        r.URL,
			StatusCode: r.StatusCode,
			Public:     r.Public,
		}) == nil {
			saved++
		}
	}
	fmt.Printf("[+] saved %d cloud assets → empire.db (cloud_assets table)\n", saved)
}
