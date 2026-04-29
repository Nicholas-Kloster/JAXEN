
      /\_/\           `7MMF'    db      `YMM'   `MP' `7MM"""YMM  `7MN.   `7MF'
     ( o.o )            MM     ;MM:       VMb.  ,P     MM    `7    MMN.    M  
      > ^ <             MM    ,V^MM.       `MM.M'      MM   d      M YMb   M  
     /     \            MM   ,M  `MM         MMb       MMmmMM      M  `MN. M  
    (   _   )           MM   AbmmmqMA      ,M'`Mb.     MM   Y  ,   M   `MM.M  
     ^^   ^^       (O)  MM  A'     VML    ,P   `MM.    MM     ,M   M     YMM  
                    Ymmm9 .AMA.   .AMMA..MM:.  .:MMa..JMMmmmmMMM .JML.    YM  

                        ────  recon platform · v0.1.0 · @nuclide  ────
```

**Advanced Reconnaissance & AI/ML Infrastructure Hunting Platform**

[![Go Report Card](https://goreportcard.com/badge/github.com/Nicholas-Kloster/JAXEN)](https://goreportcard.com/report/github.com/Nicholas-Kloster/JAXEN)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)

</div>

---

## 📖 Overview

**JAXEN** is a comprehensive, multi-stage OSINT and reconnaissance framework built in Go. Designed for security researchers, penetration testers, and threat hunters, JAXEN uses the Shodan API to map exposed enterprise assets. It specializes in **AI/LLM infrastructure discovery**, **enterprise gateway analysis**, and **certificate forensics**, tracking all findings in a local SQLite database for continuous attack surface management. 

## ✨ Key Features

- 🧠 **AI/LLM Infrastructure Mapping:** Pre-built, categorized dorks to expose Vector databases, Inference endpoints (Ollama, vLLM), ML orchestration systems (LangChain, n8n), and MLOps platforms.
- 🔐 **Deep Certificate Forensics:** Extract and analyze TLS certificates from live hosts, PEM/CRT files, or raw firmware dumps to identify mTLS flags, SANs, and internal CA leaks.
- 🏢 **Enterprise Gateway Hunting:** Dedicated modules to uncover enterprise setups like Menlo Security deployments and their exposed origin servers.
- 📊 **Continuous Recon & Alerting:** Diff snapshots of your reconnaissance data to detect new attack surfaces, and optionally pipe alerts to Slack/Discord webhooks.
- 🗄️ **Local Intelligence DB:** All results are stored in a local SQLite database (`empire.db`), allowing you to execute ad-hoc Go scripts against your recon context.

---

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Nicholas-Kloster/JAXEN.git
   cd JAXEN
   ```

2. **Build the binary:**
   ```bash
   go build -o jaxen .
   ```

3. **Configure your environment:**
   JAXEN requires a Shodan API key to perform passive reconnaissance.
   ```bash
   export SHODAN_API_KEY="your_shodan_api_key_here"
   ```

---

## 🛠️ Command Reference

JAXEN's capabilities are broken down into logical modules. Run `./jaxen <command> --help` for specific flags.

### 🕵️‍♂️ Hunting & Reconnaissance
| Command | Description |
|---|---|
| `hunt` | Run a raw Shodan query and ingest the results into the database. |
| `ai-hunt` | Execute pre-built intelligence workflows targeting exposed AI/ML infrastructure. |
| `menlo-hunt` | Discover Menlo Security gateway deployments and exposed origin IPs. |
| `buckets` | Enumerate public cloud storage buckets associated with a given organization. |

### 🔬 Profiling & Forensics
| Command | Description |
|---|---|
| `cert-parse` | Deep-inspect TLS certs from PEM files or firmware rootfs directories. |
| `profile` | Classify a target IP (e.g., honeypot, clinical, commercial, residential). |
| `pivot` | Deep-dive a single URL to extract headers, JS secrets, and test open redirects. |
| `aimap` | Delegate to the external `aimap` binary for active AI/ML service enumeration. |

### 📈 Analysis & Attack Surface Management
| Command | Description |
|---|---|
| `analyze` | Interactively analyze stored database results with automated probing suggestions. |
| `diff` | Compare two recon snapshots (JSON) and optionally trigger webhook alerts on new findings. |
| `graph` | Print an ASCII network/organizational graph of your current findings. |

### 🗄️ Database Utilities
| Command | Description |
|---|---|
| `import` | Import IPs or hostnames from a file into `empire.db` with Shodan enrichment. |
| `list` | List all stored results, with optional filtering by organization. |
| `nuke` | Purge one or more targeted IPs from your local database. |
| `run` | Execute ad-hoc Go scripts with direct access to the `empire.db` context. |
| `cheatsheet` | Display a built-in cheat sheet of Shodan dorks by category. |

---

## 🎯 Usage Examples

### AI Infrastructure Discovery
Hunt for exposed AI systems. You can target all categories or narrow it down to specific infrastructure (e.g., `vector-db`, `inference`, `orchestration`, `gpu`, `mlops`, `gateway`):
```bash
# Hunt for all exposed AI/ML infrastructure
./jaxen ai-hunt all

# Hunt specifically for vector databases (Qdrant, Milvus, Weaviate, etc.)
./jaxen ai-hunt vector-db
```

### Attack Surface Diffing & Webhooks
Great for continuous monitoring (Cron/CI). Compare today's findings against yesterday's and send new assets to Slack:
```bash
./jaxen diff --webhook "https://hooks.slack.com/services/T0000/B0000/XXXX" old_recon.json new_recon.json
```

### General Threat Hunting & Analysis
```bash
# Discover exposed Spring Boot Actuator services on a specific port
./jaxen hunt --clean --export "port:8081 Actuator"

# Start an interactive analysis session for the assets currently in your DB
./jaxen analyze
```

### Firmware Certificate Extraction
Feed JAXEN a directory containing extracted firmware file systems to hunt for internal PKI leaks and expiring certs:
```bash
./jaxen cert-parse /path/to/extracted/squashfs-root/
```

---

## 🧠 Supported AI-Hunt Categories

JAXEN maps the modern AI tech stack with highly specific queries:
- **`vector-db`**: Qdrant, Weaviate, Milvus, ChromaDB.
- **`inference`**: Ollama, vLLM, llama.cpp, LocalAI.
- **`orchestration`**: LangChain, Flowise, n8n, Dify, Langfuse.
- **`gpu`**: NVIDIA DCGM, NVML management interfaces.
- **`mlops`**: MLflow, DVC, Weights & Biases, BentoML.
- **`gateway`**: LiteLLM, Kong AI Gateway, OpenRouter proxies.

---

## 🔗 Related Ecosystem

JAXEN pairs beautifully with other specialized tools in the recon/exploit ecosystem:
* **[aimap](https://github.com/Nicholas-Kloster/aimap)** — Deep AI/ML infrastructure enumerator supporting 36 service types and 26 dedicated probes.
* **[BARE](https://github.com/Nicholas-Kloster/BARE)** — Semantic exploit matching engine against the Metasploit corpus.
* **[VisorGraph](https://github.com/Nicholas-Kloster/VisorGraph)** — Seed-polymorphic reconnaissance graph engine.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

> **Disclaimer:** JAXEN is built for educational, security research, and defensive purposes. Always ensure you have explicit permission before actively probing, pivoting, or exploiting targeted infrastructure.
```
