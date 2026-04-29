// goharvester — Shodan recon platform
//
// Commands:
//   hunt      [--clean] [--export] [--passive <domain>] <query>
//   analyze   [--fast]
//   cheatsheet
//   pivot     <url>
//   diff      [--webhook <url>] [old.json] [new.json]
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
	fmt.Fprint(os.Stderr, yellow)
	fmt.Fprintln(os.Stderr, "     _  _   __  _____ _  _ ")
	fmt.Fprintln(os.Stderr, "  _ | |/_\\  \\ \\/ / __| \\| |")
	fmt.Fprintln(os.Stderr, " | || / _ \\  >  <| _|| .` |")
	fmt.Fprintln(os.Stderr, "  \\__/_/ \\_\\/_/\\_\\___|_|\\_|")
	fmt.Fprint(os.Stderr, reset)
	fmt.Fprintln(os.Stderr, "")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: jaxen <command> [flags] [args]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, `  hunt        [--clean] [--export] [--passive <domain>] "<query>"`)
	fmt.Fprintln(os.Stderr, "  analyze     [--fast]")
	fmt.Fprintln(os.Stderr, "  cheatsheet")
	fmt.Fprintln(os.Stderr, "  pivot       <url>")
	fmt.Fprintln(os.Stderr, "  diff        [--webhook <url>] [old.json] [new.json]")
	fmt.Fprintln(os.Stderr, "  list        [--org <filter>]")
	fmt.Fprintln(os.Stderr, "  nuke        <ip> [ip...]")
	fmt.Fprintln(os.Stderr, "  graph")
	fmt.Fprintln(os.Stderr, "  run         <file.go> [args...]")
	fmt.Fprintln(os.Stderr, "  import      [--no-lookup] [--delay N] [--source name] <file>")
	fmt.Fprintln(os.Stderr, "  buckets     [--workers N] [--timeout N] <org-name>")
	fmt.Fprintln(os.Stderr, "  ai-hunt     [category]  # e.g. vector-db, inference, orchestration, all")
	fmt.Fprintln(os.Stderr, "  menlo-hunt  [--org name]          # enterprise gateway JARM + origin-IP discovery")
	fmt.Fprintln(os.Stderr, "  aimap       <ip|cidr> [hostname]  # AI service deep enumeration wrapper")
	fmt.Fprintln(os.Stderr, "  profile     [--org name] [<ip>]   # target intelligence classifier")
}
