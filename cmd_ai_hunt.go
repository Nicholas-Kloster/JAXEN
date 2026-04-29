// cmd_ai_hunt.go — AI/LLM infrastructure OSINT
//
// Hardcodes T1 (unauthenticated) Shodan dorks from the
// Nicholas-Kloster/AI-LLM-Infrastructure-OSINT repository.
// Results are tagged with exposure tier and saved to SQLite.
//
// Usage:
//   goharvester ai-hunt                   # list categories
//   goharvester ai-hunt vector-db         # ChromaDB / Qdrant / Weaviate
//   goharvester ai-hunt inference         # Ollama / vLLM / LiteLLM
//   goharvester ai-hunt orchestration     # Flowise / Langflow / Dify
//   goharvester ai-hunt gpu               # NVIDIA DCGM compute dashboards
//   goharvester ai-hunt mlops             # MLflow / Kubeflow / Weights & Biases
//   goharvester ai-hunt gateway           # LiteLLM proxy / OpenRouter instances
//   goharvester ai-hunt all               # run every category sequentially
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

// aiDork defines a single Shodan query with OSINT metadata.
type aiDork struct {
	Category string
	Tier     string // T1 = unauth, T2 = partial auth, T3 = auth required
	Service  string
	Query    string
	Note     string
}

// aiDorks is the embedded dork library sourced from the AI-LLM-Infrastructure-OSINT repo.
// Tier 1 (unauthenticated) entries only — these are the highest-signal targets.
var aiDorks = []aiDork{
	// Vector DBs
	{"vector-db", "T1", "ChromaDB", `port:8000 "chroma"`, "Unauth vector store — /api/v1/collections lists all embeddings"},
	{"vector-db", "T1", "ChromaDB", `http.title:"Chroma" port:8000`, "ChromaDB web probe — verify /api/v1/collections"},
	{"vector-db", "T1", "Qdrant", `port:6333 "qdrant"`, "Qdrant REST API — /collections reveals data stored"},
	{"vector-db", "T1", "Weaviate", `port:8080 "weaviate"`, "Weaviate GraphQL unauth — schema and object dumps"},
	{"vector-db", "T1", "Milvus", `port:19530 "milvus"`, "Milvus gRPC port — often no auth on default deploy"},
	// Inference servers
	{"inference", "T1", "Ollama", `product:"Ollama" port:11434`, "Ollama LLM server — /api/tags lists models, /api/generate executes"},
	{"inference", "T1", "Ollama", `port:11434 "ollama"`, "Broader Ollama sweep including non-product-tagged hosts"},
	{"inference", "T1", "vLLM", `port:8000 "/v1/models"`, "OpenAI-compatible server — vLLM, LiteLLM, LocalAI"},
	{"inference", "T1", "LocalAI", `http.title:"LocalAI"`, "LocalAI frontend — /v1/models + /v1/completions no auth"},
	{"inference", "T1", "LM Studio", `port:1234 "/v1/models"`, "LM Studio API server — consumer GPU, often no auth"},
	// LLM Orchestration
	{"orchestration", "T1", "Flowise", `http.title:"Flowise"`, "LLM workflow builder — /api/v1/chatflows unauth CRUD"},
	{"orchestration", "T1", "Langflow", `http.title:"Langflow"`, "LangChain visual builder — /api/v1/flows unauth access"},
	{"orchestration", "T1", "Dify", `http.title:"Dify"`, "LLM app platform — unauth API endpoints on default install"},
	{"orchestration", "T1", "Open WebUI", `http.title:"Open WebUI"`, "ChatGPT-style frontend — model access, chat history, no auth"},
	{"orchestration", "T1", "AnythingLLM", `http.title:"AnythingLLM"`, "Document-to-LLM pipeline — workspace data unauth on default"},
	// GPU / Compute Dashboards
	{"gpu", "T1", "NVIDIA DCGM", `port:9400 "DCGM"`, "GPU metrics — /metrics dumps topology, utilization, driver versions"},
	{"gpu", "T1", "NVIDIA DCGM", `"dcgm_fi_" port:9400`, "DCGM Prometheus metrics — host enumeration via GPU model labels"},
	{"gpu", "T1", "Triton Server", `port:8002 "triton"`, "NVIDIA Triton inference — /v2/models unauth model catalog"},
	// MLOps
	{"mlops", "T1", "MLflow", `http.title:"MLflow"`, "Experiment tracking — /api/2.0/mlflow/experiments/list unauth"},
	{"mlops", "T1", "MLflow", `port:5000 "mlflow"`, "MLflow default port — /api/2.0/mlflow artifacts + models"},
	{"mlops", "T2", "Kubeflow", `http.title:"Kubeflow"`, "ML pipeline platform — often internal-only but occasionally external"},
	{"mlops", "T1", "Label Studio", `http.title:"Label Studio"`, "Data annotation — /api/projects unauth on community edition"},
	// AI Gateways
	{"gateway", "T1", "LiteLLM Proxy", `http.title:"LiteLLM" port:4000`, "Multi-provider LLM proxy — /models lists active API keys"},
	{"gateway", "T1", "OpenRouter", `port:8080 "openrouter"`, "LLM routing layer — check /api/v1/models for key exposure"},
	{"gateway", "T1", "PromptLayer", `http.title:"PromptLayer"`, "Prompt management — hardcoded webhooks flagged in prior research"},
}

// listAICategories prints all unique categories.
func listAICategories() {
	seen := map[string]bool{}
	var cats []string
	for _, d := range aiDorks {
		if !seen[d.Category] {
			seen[d.Category] = true
			cats = append(cats, d.Category)
		}
	}
	fmt.Printf("%s%s=== AI/LLM Hunt Categories ===%s\n\n", bold, cyan, reset)
	for _, c := range cats {
		var count int
		for _, d := range aiDorks {
			if d.Category == c {
				count++
			}
		}
		fmt.Printf("  %s%-16s%s %d queries\n", yellow, c, reset, count)
	}
	fmt.Printf("\nUsage: ./goharvester ai-hunt <category>  |  ./goharvester ai-hunt all\n")
}

// shodanSearchRaw hits the Shodan search API and returns raw JSON bytes.
func shodanSearchRaw(apiKey, query string) ([]byte, error) {
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

func cmdAIHunt(args []string) {
	fs := flag.NewFlagSet("ai-hunt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	category := ""
	if fs.NArg() > 0 {
		category = strings.ToLower(fs.Arg(0))
	}

	if category == "" {
		listAICategories()
		return
	}

	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: SHODAN_API_KEY not set")
		os.Exit(1)
	}

	// Select dorks for this category (or all).
	var selected []aiDork
	for _, d := range aiDorks {
		if category == "all" || d.Category == category {
			selected = append(selected, d)
		}
	}
	if len(selected) == 0 {
		fmt.Fprintf(os.Stderr, "error: unknown category %q — run 'ai-hunt' with no args to list\n", category)
		os.Exit(1)
	}

	fmt.Printf("%s[*] AI/LLM Hunt — category: %s  queries: %d%s\n",
		bold, category, len(selected), reset)
	fmt.Println(strings.Repeat("─", 70))

	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: SQLite unavailable: %v\n", err)
	}
	if db != nil {
		defer db.Close()
	}

	totalFound := 0
	for i, d := range selected {
		fmt.Printf("\n[%d/%d] %s[%s]%s %s — %s\n",
			i+1, len(selected), yellow, d.Tier, reset, d.Service, d.Query)

		raw, err := shodanSearchRaw(apiKey, d.Query)
		if err != nil {
			fmt.Printf("  error: %v\n", err)
			time.Sleep(time.Second)
			continue
		}

		var result struct {
			Total   int `json:"total"`
			Matches []struct {
				IP        string   `json:"ip_str"`
				Port      int      `json:"port"`
				Org       string   `json:"org"`
				ISP       string   `json:"isp"`
				Hostnames []string `json:"hostnames"`
				Product   string   `json:"product"`
				Version   string   `json:"version"`
			} `json:"matches"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			fmt.Printf("  parse error: %v\n", err)
			time.Sleep(time.Second)
			continue
		}

		fmt.Printf("  total=%d  returned=%d\n", result.Total, len(result.Matches))
		totalFound += len(result.Matches)

		for _, m := range result.Matches {
			hn := strings.Join(m.Hostnames, ",")
			tier := d.Tier
			color := green
			if tier == "T2" {
				color = yellow
			}

			fmt.Printf("  %s[%s]%s %-18s :%d  %-25s  %s\n",
				color, tier, reset, m.IP, m.Port, m.Org, hn)

			if db != nil {
				upsertAsset(db, AssetRow{
					IP:       m.IP,
					Port:     m.Port,
					Org:      m.Org,
					ISP:      m.ISP,
					Hostname: hn,
					Product:  m.Product,
					Version:  m.Version,
					Notes:    fmt.Sprintf("ai-hunt:%s tier:%s service:%s", d.Category, d.Tier, d.Service),
				})
			}
		}

		// Shodan free tier: 1 req/sec
		if i < len(selected)-1 {
			time.Sleep(time.Second)
		}
	}

	fmt.Printf("\n%s[+] ai-hunt complete: %d results across %d queries%s\n",
		bold, totalFound, len(selected), reset)
	if db != nil {
		fmt.Println("[+] results saved → empire.db (assets table, notes=ai-hunt:*)")
	}

	fmt.Printf("\n%sNext steps:%s\n", bold, reset)
	fmt.Println("  ./goharvester analyze            # Lead Researcher deep analysis")
	fmt.Println("  cat .claude_actions.sh           # execute generated probe commands")
	fmt.Printf("  aimap <ip> <hostname>            # deep AI service enumeration (26 enumerators)\n")
}
