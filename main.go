// goharvester — Shodan recon platform
//
// Commands:
//   hunt      [--clean] [--export] [--passive <domain>] <query>
//   analyze[--fast]
//   cheatsheet
//   pivot     <url>
//   diff[--webhook <url>] [old.json] [new.json]
//   list      [--org <filter>]
//   nuke      <ip> [ip...]
//   graph
//   run       <file.go> [args...]
//   import    [--no-lookup] [--delay N] [--source name] <file>
//   buckets   [--workers N] [--timeout N] <org-name>
//   ai-hunt   [category]
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		printBanner()
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "hunt":
		cmdHunt(os.Args[2:])
	case "analyze":
		cmdAnalyze(os.Args[2:])
	case "cheatsheet":
		cmdCheatsheet()
	case "pivot":
		cmdPivot(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "nuke":
		cmdNuke(os.Args[2:])
	case "graph":
		cmdGraph(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "import":
		cmdImport(os.Args[2:])
	case "buckets":
		cmdBuckets(os.Args[2:])
	case "ai-hunt":
		cmdAIHunt(os.Args[2:])
	case "menlo-hunt":
		cmdMenloHunt(os.Args[2:])
	case "aimap":
		cmdAIMap(os.Args[2:])
	case "profile":
		cmdProfile(os.Args[2:])
	case "cert-parse":
		cmdCertParse(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "error: unknown subcommand %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printBanner() {
	const (
		tanBright = "\033[38;2;200;144;96m"
		tanDim    = "\033[38;2;130;90;58m"
		dimColor  = "\033[38;2;110;100;90m"
	)
	cat := [7]string{
		`   /\_/\   `,
		`  ( o.o )  `,
		`   > ^ <   `,
		`  /     \  `,
		` (   _   ) `,
		`  ^^   ^^  `,
		`           `,
	}
	logo := [7]string{
		"   `7MMF'    db      `YMM'   `MP' `7MM\"\"\"YMM  `7MN.   `7MF'",
		"     MM     ;MM:       VMb.  ,P     MM    `7    MMN.    M  ",
		"     MM    ,V^MM.       `MM.M'      MM   d      M YMb   M  ",
		"     MM   ,M  `MM         MMb       MMmmMM      M  `MN. M  ",
		"     MM   AbmmmqMA      ,M'`Mb.     MM   Y  ,   M   `MM.M  ",
		"(O)  MM  A'     VML    ,P   `MM.    MM     ,M   M     YMM  ",
		" Ymmm9 .AMA.   .AMMA..MM:.  .:MMa..JMMmmmmMMM .JML.    YM  ",
	}
	fmt.Fprintln(os.Stderr)
	for i := range logo {
		fmt.Fprintf(os.Stderr, "   %s%-11s%s   %s%s%s%s\n",
			tanDim, cat[i], reset, tanBright, bold, logo[i], reset)
	}
	meta := "────  recon platform · v0.1.0 · @nuclide  ────"
	fmt.Fprintf(os.Stderr, "\n%s%s%s\n\n", strings.Repeat(" ", 24), dimColor+meta, reset)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: jaxen <command> [flags] [args]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, `  hunt        [--clean] [--export][--passive <domain>] "<query>"`)
	fmt.Fprintln(os.Stderr, "  analyze     [--fast]")
	fmt.Fprintln(os.Stderr, "  cheatsheet")
	fmt.Fprintln(os.Stderr, "  pivot       <url>")
	fmt.Fprintln(os.Stderr, "  diff        [--webhook <url>] [old.json] [new.json]")
	fmt.Fprintln(os.Stderr, "  list        [--org <filter>]")
	fmt.Fprintln(os.Stderr, "  nuke        <ip> [ip...]")
	fmt.Fprintln(os.Stderr, "  graph")
	fmt.Fprintln(os.Stderr, "  run         <file.go> [args...]")
	fmt.Fprintln(os.Stderr, "  import[--no-lookup] [--delay N] [--source name] <file>")
	fmt.Fprintln(os.Stderr, "  buckets     [--workers N] [--timeout N] <org-name>")
	fmt.Fprintln(os.Stderr, "  ai-hunt     [category]            # e.g. vector-db, inference, orchestration, all")
	fmt.Fprintln(os.Stderr, "  menlo-hunt[--org name]          # enterprise gateway JARM + origin-IP discovery")
	fmt.Fprintln(os.Stderr, "  aimap       <ip|cidr> [hostname]  # AI service deep enumeration wrapper")
	fmt.Fprintln(os.Stderr, "  profile     [--org name] [<ip>]   # target intelligence classifier")
	fmt.Fprintln(os.Stderr, "  cert-parse  <path>                # deeply inspect TLS certs from PEM files or firmware")
}
