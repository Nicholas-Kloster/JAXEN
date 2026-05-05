# JAXEN

Stateful, Go-based reconnaissance framework. Powered by Shodan + a local SQLite intelligence database (`empire.db`). Specializes in AI/LLM infrastructure hunting, enterprise gateway enumeration (Menlo Security), continuous attack-surface diffing, and deep TLS certificate forensics on live hosts and firmware root filesystems.

The Shodan-harvest stage of the NuClide chain. Output feeds aimap fingerprinting, VisorAgent target lists, and VisorLog ledger ingest.

## Language
Go 1.21+ (single static binary). SQLite via embedded driver — no external DB.

## Build & Run
```
go build -o jaxen .

export SHODAN_API_KEY="..."

# Hunting & recon
./jaxen hunt 'http.html:"Ollama is running"'   # raw Shodan query → empire.db
./jaxen ai-hunt --category vector-db           # pre-built AI/ML workflow
./jaxen menlo-hunt --org "Acme Corp"           # Menlo Security gateway hunt
./jaxen buckets --org "Acme Corp"              # public bucket enumeration

# Profiling & forensics
./jaxen profile <ip>                           # classify (clinical/commercial/honeypot/...)
./jaxen cert-parse <pem|squashfs-root|ip>      # deep TLS cert forensics
./jaxen pivot <url>                            # headers / JS secrets / open-redirect probe
./jaxen aimap <ip>                             # delegate to external aimap binary

# Analysis & ASM
./jaxen analyze                                # interactive analysis terminal
./jaxen graph                                  # ASCII node-graph of org network
./jaxen diff old.json new.json                 # snapshot diff + Slack/Discord alerts

# Database utilities
./jaxen list                                   # list assets in empire.db
./jaxen import <file>                          # ingest external Shodan dump
./jaxen run script.go                          # execute ad-hoc Go script vs empire.db
./jaxen nuke                                   # wipe empire.db (with confirm)

# tests (when added — currently 0)
go test ./...
```

## Layout

17 cmd_*.go files at repo root, one per subcommand:

```
main.go                  # CLI dispatch
db.go                    # empire.db schema + ORM-ish helpers (sqlite)
banner.py                # ASCII banner generator (build-time)

cmd_hunt.go              # raw Shodan query → DB ingest
cmd_ai_hunt.go           # AI/ML pre-built workflows (vector-db, inference, mlops, gateway)
cmd_menlo_hunt.go        # Menlo Security gateway + origin-IP hunt
cmd_buckets.go           # public bucket enumeration
cmd_aimap.go             # external aimap delegate
cmd_profile.go           # IP classification (clinical/honeypot/etc.)
cmd_cert_parse.go        # TLS cert forensics (live IP / PEM / firmware rootfs)
cmd_pivot.go             # URL deep-dive (headers / JS / redirects)
cmd_analyze.go           # interactive analysis terminal
cmd_graph.go             # ASCII network graph
cmd_diff.go              # snapshot diff + webhook alerts
cmd_list.go              # query empire.db
cmd_import.go            # external dump ingest
cmd_run.go               # ad-hoc Go script execution against empire.db
cmd_nuke.go              # DB wipe
cmd_cheatsheet.go        # built-in cheatsheet
```

## Claude Code Notes
- Read README for the AI-hunt category catalog, the firmware-cert-extraction workflow (squashfs-root parsing), and the Slack/Discord webhook setup
- `empire.db` is the load-bearing artifact — it persists across runs and lets `cmd_run` execute custom Go against accumulated recon
- Adding a new subcommand: drop a `cmd_<name>.go` at repo root following the existing pattern, register in `main.go` dispatch
- Output flows into the broader chain via `cmd_aimap` (delegate), JSON exports (Slack alerts), and direct VisorLog NDJSON ingest
- Built with [Claude Code](https://claude.ai/code)
