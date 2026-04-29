# JAXEN

```
  .'.   .'.                      
  : '.--'-/ ::                   
  :;'_';'`_'':                   
  ://o)._(o\ '.                           █████   █████████   █████ █████ ██████████ ██████   █████
 ;'  (O_.''.   ;                         ░░███   ███░░░░░███ ░░███ ░░███ ░░███░░░░░█░░██████ ░░███ 
  '._;|_/_: _.'                           ░███  ░███    ░███  ░░███ ███   ░███  █ ░  ░███░███ ░███ 
     .'-'.'\                              ░███  ░███████████   ░░█████    ░██████    ░███░░███░███ 
    ,'   ;  `'._                          ░███  ░███░░░░░███    ███░███   ░███░░█    ░███ ░░██████ 
    ';.   ;/    '-.    ____         ███   ░███  ░███    ░███   ███ ░░███  ░███ ░   █ ░███  ░░█████ 
    :';   :        :-'`  : '.      ░░████████   █████   █████ █████ █████ ██████████ █████  ░░█████
    :,,/:. \  ,.'   :     :  '.     ░░░░░░░░   ░░░░░   ░░░░░ ░░░░░ ░░░░░ ░░░░░░░░░░ ░░░░░    ░░░░░ 
   _; /;,:'|,,(   _.'-.__:_..'   
  :,,:    _: /'--;               
         :,,:-'-'                

                                  recon platform
```

---

## Install

```bash
git clone https://github.com/Nicholas-Kloster/JAXEN
cd JAXEN
go build -o jaxen .
```

Requires a Shodan API key:

```bash
export SHODAN_API_KEY=your_key_here
```

---

## Commands

| Command | Description |
|---------|-------------|
| `hunt` | Run a Shodan query and store results in empire.db |
| `analyze` | Interactively analyze stored results with probing suggestions |
| `ai-hunt` | Run pre-built Shodan dorks targeting AI/ML infrastructure |
| `menlo-hunt` | Discover Menlo Security gateway deployments and exposed origin IPs |
| `aimap` | Delegate to the aimap binary for deep AI/ML service enumeration |
| `profile` | Classify a target (honeypot / clinical / research / commercial / residential) |
| `cert-parse` | Inspect TLS certificates from PEM/CRT files or firmware dump directories |
| `pivot` | Deep-dive a single URL: headers, TLS cert, JS secrets, open redirects |
| `diff` | Compare two recon snapshots, optionally post a webhook alert on new findings |
| `import` | Import IPs/hostnames from a file into empire.db with optional Shodan enrichment |
| `buckets` | Enumerate public cloud storage buckets for a given org name |
| `list` | List stored results, optionally filtered by org |
| `nuke` | Remove one or more IPs from empire.db |
| `graph` | Print an ASCII graph of findings by org |
| `run` | Execute an ad-hoc Go script with access to the empire.db context |
| `cheatsheet` | Print Shodan dork cheatsheet by category |

---

## Usage Examples

```bash
# Discover exposed Spring Boot Actuator services on port 8081
./jaxen hunt --clean --export "port:8081 Actuator"

# Analyze stored results interactively
./jaxen analyze

# Hunt for exposed AI/ML infrastructure (all categories)
./jaxen ai-hunt all

# Hunt for vector databases only
./jaxen ai-hunt vector-db

# Find Menlo Security gateways and exposed origin servers
./jaxen menlo-hunt

# Parse certificates from a firmware extraction directory
./jaxen cert-parse /path/to/firmware/rootfs/

# Profile a target IP
./jaxen profile 1.2.3.4

# Diff two snapshots and post to Slack
./jaxen diff --webhook https://hooks.slack.com/... old.json new.json
```

---

## AI-Hunt Categories

| Category | Description |
|----------|-------------|
| `vector-db` | Exposed Qdrant, Weaviate, Milvus, ChromaDB instances |
| `inference` | Ollama, vLLM, llama.cpp, LocalAI servers |
| `orchestration` | LangChain, Flowise, n8n, Dify, Langfuse |
| `gpu` | NVIDIA DCGM, NVML management endpoints |
| `mlops` | MLflow, DVC, Weights & Biases, BentoML |
| `gateway` | LiteLLM, Kong AI Gateway, OpenRouter proxies |
| `all` | All of the above |

---

## cert-parse

Walks firmware dump directories looking for `.pem`, `.crt`, `.cer` files and surfaces:

- Subject CN / O / OU, Issuer, Serial
- SANs (DNS, IP, Email)
- Expiry with color-coded warning (30-day threshold)
- Client Auth EKU flag (`[YES — usable for mTLS]`)
- AIA CA URLs and CRL distribution points (leaks internal CA hostnames)

---

## Database

Results are stored in `empire.db` (SQLite). Schema includes `hosts`, `cloud_assets`, and session metadata. The `run` subcommand lets you execute arbitrary Go scripts against the database for custom analysis.

---

## Related Tools

- **[aimap](https://github.com/Nicholas-Kloster/aimap)** — AI/ML infrastructure deep enumerator (36 service types, 26 dedicated probes)
- **[BARE](https://github.com/Nicholas-Kloster/BARE)** — Semantic exploit matching against Metasploit corpus
- **[VisorGraph](https://github.com/Nicholas-Kloster/VisorGraph)** — Seed-polymorphic recon graph engine

---

## License

MIT
