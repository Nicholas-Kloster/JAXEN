// cmd_graph.go — export the SQLite empire as a Graphviz DOT file
//
// Groups assets by shared certificate serial, org, and product.
// The resulting DOT file can be rendered with:
//   dot -Tsvg empire.dot -o empire.svg
//   dot -Tpng empire.dot -o empire.png
//
// Hidden clusters surface via certificate serial collisions: two IPs with the
// same serial share the same PKI template and are almost certainly the same
// infrastructure even if their org/ISP differs.
//
// Usage: goharvester graph
package main

import (
	"fmt"
	"os"
	"strings"
)

func cmdGraph(args []string) {
	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	assets, err := queryAssets(db, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: query failed: %v\n", err)
		os.Exit(1)
	}

	if len(assets) == 0 {
		fmt.Println("[*] No assets in empire.db — run 'hunt' first.")
		return
	}

	// ── Group by org ──────────────────────────────────────────────────────
	// Each org becomes a DOT subgraph (cluster). Edges connect IPs that share
	// the same product string (same software stack across the org).
	byOrg := make(map[string][]AssetRow)
	for _, a := range assets {
		byOrg[a.Org] = append(byOrg[a.Org], a)
	}

	var sb strings.Builder
	sb.WriteString("digraph empire {\n")
	sb.WriteString(`  graph [fontname="monospace" bgcolor="#1a1a2e" fontcolor="white"];` + "\n")
	sb.WriteString(`  node  [fontname="monospace" style=filled fillcolor="#16213e" fontcolor="white" color="#0f3460"];` + "\n")
	sb.WriteString(`  edge  [color="#e94560" fontcolor="#e94560"];` + "\n\n")

	clusterIdx := 0
	for org, rows := range byOrg {
		safeOrg := dotID(org)
		sb.WriteString(fmt.Sprintf("  subgraph cluster_%d {\n", clusterIdx))
		sb.WriteString(fmt.Sprintf("    label=%q;\n", org))
		sb.WriteString(`    style=dashed; color="#0f3460";` + "\n")

		for _, r := range rows {
			nodeID := dotID(r.IP + "_" + fmt.Sprintf("%d", r.Port))
			label := fmt.Sprintf("%s:%d\\n%s", r.IP, r.Port, r.Product)
			sb.WriteString(fmt.Sprintf("    %s_%s [label=%q];\n", safeOrg, nodeID, label))
		}
		sb.WriteString("  }\n\n")
		clusterIdx++
	}

	// ── Edges: link IPs sharing the same product within an org ───────────
	byProduct := make(map[string][]AssetRow)
	for _, a := range assets {
		if a.Product != "" {
			key := a.Org + "|" + a.Product
			byProduct[key] = append(byProduct[key], a)
		}
	}
	for _, group := range byProduct {
		if len(group) < 2 {
			continue
		}
		org := dotID(group[0].Org)
		for i := 0; i < len(group)-1; i++ {
			a := dotID(group[i].IP + "_" + fmt.Sprintf("%d", group[i].Port))
			b := dotID(group[i+1].IP + "_" + fmt.Sprintf("%d", group[i+1].Port))
			sb.WriteString(fmt.Sprintf("  %s_%s -> %s_%s [label=%q];\n",
				org, a, org, b, group[0].Product))
		}
	}

	sb.WriteString("}\n")

	outFile := "empire.dot"
	if err := os.WriteFile(outFile, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", outFile, err)
		os.Exit(1)
	}

	fmt.Printf("[+] wrote %s (%d assets, %d orgs)\n", outFile, len(assets), len(byOrg))
	fmt.Printf("    render: dot -Tsvg %s -o empire.svg\n", outFile)
}

// dotID sanitizes a string for use as a DOT identifier.
func dotID(s string) string {
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		} else {
			out.WriteRune('_')
		}
	}
	return out.String()
}
