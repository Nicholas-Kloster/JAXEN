// cmd_pivot.go — favicon MurmurHash3 pivot
//
// Downloads a favicon from a URL, computes Shodan's exact hash, and prints
// the dork to find all internet assets sharing that favicon.
//
// How this works: Shodan indexes favicon hashes for every crawled HTTP(S)
// service. Two services with the same favicon hash are almost always running
// the same software or belong to the same organization — even if they're on
// different IPs, ASNs, or countries. This finds shadow assets that no DNS
// record or certificate points to.
//
// Usage: goharvester pivot <url>
// Example: goharvester pivot https://target.com
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func cmdPivot(args []string) {
	fs := flag.NewFlagSet("pivot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: goharvester pivot <url>")
		fmt.Fprintln(os.Stderr, "  e.g. goharvester pivot https://target.com")
		os.Exit(1)
	}

	targetURL := fs.Arg(0)

	// ── Resolve favicon URL ───────────────────────────────────────────────
	// Strategy: try /favicon.ico first (covers ~80% of sites), then attempt
	// to parse the HTML <link rel="icon"> tag for the remainder.
	faviconURL, err := resolveFaviconURL(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] favicon URL : %s\n", faviconURL)

	// ── Download ──────────────────────────────────────────────────────────
	raw, err := fetchBytes(faviconURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: fetch failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] size        : %d bytes\n", len(raw))

	// ── Hash ──────────────────────────────────────────────────────────────
	// Shodan's exact algorithm:
	//   1. Base64-encode the raw bytes with Python's encodebytes() line-wrapping
	//   2. MurmurHash3 32-bit (seed=0) the resulting base64 string
	b64 := shodanFaviconBase64(raw)
	hash := murmur3Hash32(b64)

	fmt.Printf("[*] murmur3     : %d\n", hash)
	fmt.Printf("\n")
	fmt.Printf("[+] Shodan dork :\n")
	fmt.Printf("    http.favicon.hash:%d\n", hash)
	fmt.Printf("\n")
	fmt.Printf("[+] Hunt command:\n")
	fmt.Printf("    SHODAN_API_KEY=xxx ./goharvester hunt \"http.favicon.hash:%d\"\n", hash)
	fmt.Printf("\n")
	fmt.Printf("[+] Browser search:\n")
	fmt.Printf("    https://www.shodan.io/search?query=http.favicon.hash%%3A%d\n", hash)
}

// resolveFaviconURL tries <base>/favicon.ico. If that returns a non-image
// content-type or 404, it falls back to the root page and parses the
// <link rel="icon"> tag from the HTML.
func resolveFaviconURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Normalize: ensure scheme is present
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	candidate := fmt.Sprintf("%s://%s/favicon.ico", u.Scheme, u.Host)

	// Quick HEAD to see if the path exists and returns an image type.
	client := insecureClient()
	resp, err := client.Head(candidate)
	if err == nil {
		defer resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if resp.StatusCode == 200 && (strings.Contains(ct, "image") || strings.Contains(ct, "octet-stream")) {
			return candidate, nil
		}
	}

	// Fallback: fetch root page and look for <link rel="icon" href="...">
	body, err := fetchBytes(fmt.Sprintf("%s://%s/", u.Scheme, u.Host))
	if err != nil {
		// Just return the candidate anyway — the fetch step will fail loudly.
		return candidate, nil
	}

	if href := extractFaviconHref(string(body)); href != "" {
		if !strings.HasPrefix(href, "http") {
			href = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, href)
		}
		return href, nil
	}

	return candidate, nil
}

// extractFaviconHref does a simple string search for the href in a
// <link rel="icon"> or <link rel="shortcut icon"> tag. Not a full HTML
// parser — fast and good enough for the common case.
func extractFaviconHref(html string) string {
	lower := strings.ToLower(html)
	idx := strings.Index(lower, `rel="icon"`)
	if idx == -1 {
		idx = strings.Index(lower, `rel='icon'`)
	}
	if idx == -1 {
		idx = strings.Index(lower, `rel="shortcut icon"`)
	}
	if idx == -1 {
		return ""
	}

	// Scan backward to find the <link tag start, then forward for href="..."
	tagStart := strings.LastIndex(html[:idx], "<link")
	if tagStart == -1 {
		return ""
	}
	tagEnd := strings.Index(html[tagStart:], ">")
	if tagEnd == -1 {
		return ""
	}
	tag := html[tagStart : tagStart+tagEnd+1]

	for _, quote := range []string{`href="`, `href='`} {
		i := strings.Index(strings.ToLower(tag), quote)
		if i == -1 {
			continue
		}
		rest := tag[i+len(quote):]
		end := strings.IndexAny(rest, `"'`)
		if end == -1 {
			continue
		}
		return rest[:end]
	}
	return ""
}

// fetchBytes downloads a URL and returns its raw body bytes.
func fetchBytes(targetURL string) ([]byte, error) {
	client := insecureClient()
	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, targetURL)
	}
	return io.ReadAll(resp.Body)
}

// insecureClient returns an HTTP client that skips TLS verification.
// Used for recon — we don't care about cert validity, we care about content.
func insecureClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}
