// cmd_cert_parse.go — parse and inspect TLS certificates from PEM/CRT files
//
// Surfaces: Subject CN, Issuer, SANs, expiry, client-auth EKU flag, and leaked
// internal URLs from AIA/CRL extensions. Works on single files or directories
// (walks the tree looking for .pem / .crt / .cer files — useful after a firmware
// extraction dump).
//
// Usage:
//   goharvester cert-parse <file.pem>
//   goharvester cert-parse <file.crt>
//   goharvester cert-parse <extracted-firmware-dir/>
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdCertParse(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: goharvester cert-parse <file.pem|file.crt|dir/>")
		os.Exit(1)
	}

	target := args[0]
	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s%s=== Certificate Inspector ===%s\n\n", bold, cyan, reset)

	if info.IsDir() {
		var found int
		filepath.Walk(target, func(path string, fi os.FileInfo, _ error) error { //nolint:errcheck
			if fi == nil || fi.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".pem", ".crt", ".cer", ".cert":
				if parseCertFile(path) {
					found++
				}
			}
			return nil
		})
		fmt.Printf("[+] %d certificate file(s) parsed in %s\n", found, target)
	} else {
		parseCertFile(target)
	}
}

func parseCertFile(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("  [!] read error %s: %v\n", path, err)
		return false
	}

	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return false
	}

	fmt.Printf("%s── %s ──%s\n", bold, path, reset)
	for i, cert := range certs {
		if len(certs) > 1 {
			fmt.Printf("  [cert %d/%d]\n", i+1, len(certs))
		}
		printCertDetails(cert)
	}
	return true
}

func printCertDetails(cert *x509.Certificate) {
	now := time.Now()
	expired := now.After(cert.NotAfter)

	expColor := green
	expNote := ""
	if expired {
		days := int(now.Sub(cert.NotAfter).Hours() / 24)
		expColor = bold + red
		expNote = fmt.Sprintf("  %s[EXPIRED %d days ago]%s", bold+red, days, reset)
	} else if cert.NotAfter.Sub(now) < 30*24*time.Hour {
		expColor = yellow
		expNote = fmt.Sprintf("  %s[expires in %d days]%s", yellow, int(cert.NotAfter.Sub(now).Hours()/24), reset)
	}

	fmt.Printf("  Subject CN   : %s%s%s\n", bold, cert.Subject.CommonName, reset)
	if len(cert.Subject.Organization) > 0 {
		fmt.Printf("  Subject O    : %s\n", strings.Join(cert.Subject.Organization, ", "))
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		fmt.Printf("  Subject OU   : %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", "))
	}
	fmt.Printf("  Issuer CN    : %s\n", cert.Issuer.CommonName)
	if len(cert.Issuer.Organization) > 0 {
		fmt.Printf("  Issuer O     : %s\n", strings.Join(cert.Issuer.Organization, ", "))
	}
	fmt.Printf("  Serial       : %X\n", cert.SerialNumber)
	fmt.Printf("  Not Before   : %s\n", cert.NotBefore.UTC().Format("2006-01-02"))
	fmt.Printf("  Not After    : %s%s%s%s\n", expColor, cert.NotAfter.UTC().Format("2006-01-02"), reset, expNote)

	if len(cert.DNSNames) > 0 {
		fmt.Printf("  SAN DNS      : %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		fmt.Printf("  SAN IPs      : %s\n", strings.Join(ips, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("  SAN Email    : %s%s%s\n", yellow, strings.Join(cert.EmailAddresses, ", "), reset)
	}

	// Key usage
	var usage []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usage = append(usage, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usage = append(usage, "KeyEncipherment")
	}
	if len(usage) > 0 {
		fmt.Printf("  Key Usage    : %s\n", strings.Join(usage, ", "))
	}

	clientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if clientAuth {
		fmt.Printf("  Client Auth  : %s[YES — usable for mTLS]%s\n", bold+green, reset)
	} else {
		fmt.Printf("  Client Auth  : no\n")
	}

	// AIA/CRL — these leak internal CA hostnames (forensic gold)
	if len(cert.IssuingCertificateURL) > 0 {
		fmt.Printf("  AIA CA URL   : %s%s%s\n", yellow, strings.Join(cert.IssuingCertificateURL, ", "), reset)
	}
	if len(cert.CRLDistributionPoints) > 0 {
		fmt.Printf("  CRL URL      : %s%s%s\n", yellow, strings.Join(cert.CRLDistributionPoints, ", "), reset)
	}
	if len(cert.OCSPServer) > 0 {
		fmt.Printf("  OCSP URL     : %s\n", strings.Join(cert.OCSPServer, ", "))
	}

	fmt.Println()
}
