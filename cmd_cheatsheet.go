// cmd_cheatsheet.go — power-dork library and pivot technique reference
package main

import "fmt"

type dork struct {
	category string
	query    string
	note     string
}

var powerDorks = []dork{
	// Shadow IT
	{category: "Shadow IT", query: `org:"Target" -product:"Akamai"`, note: "direct-origin servers bypassing CDN — often unpatched"},
	{category: "Shadow IT", query: `org:"Target" port:8443,9090,9200,9300`, note: "admin/metrics ports on non-standard services"},
	{category: "Shadow IT", query: `org:"Target" product:"Apache Tomcat"`, note: "Java app servers — frequent misconfig and default creds"},
	// Dev Leaks
	{category: "Dev Leaks", query: `org:"Target" "X-Dev-Config"`, note: "dev configuration header leaking in prod responses"},
	{category: "Dev Leaks", query: `org:"Target" http.title:"Swagger UI"`, note: "public API docs — enumerate endpoints before the pentest"},
	{category: "Dev Leaks", query: `org:"Target" "X-Powered-By" "staging"`, note: "staging env headers visible externally"},
	{category: "Dev Leaks", query: `org:"Target" ssl.cert.subject.cn:"*.dev" OR ssl.cert.subject.cn:"*.staging"`, note: "TLS certs for dev/staging subdomains — often on prod IPs"},
	// Vaults / Secrets
	{category: "Vaults/Secrets", query: `org:"Target" "HashiCorp Vault"`, note: "Vault UI or API — unauth if seal broken or dev mode"},
	{category: "Vaults/Secrets", query: `org:"Target" "kibana"`, note: "Kibana — may expose all logs without auth on older versions"},
	{category: "Vaults/Secrets", query: `org:"Target" product:"Prometheus"`, note: "/metrics dumps creds, tokens, internal topology"},
	{category: "Vaults/Secrets", query: `org:"Target" "etcd"`, note: "Kubernetes secrets store, often unauth on port 2379"},
	// Login Portals
	{category: "Login Portals", query: `org:"Target" http.title:"Login"`, note: "generic login — SSO bypass, default creds"},
	{category: "Login Portals", query: `org:"Target" http.title:"Dashboard"`, note: "dashboards that skipped auth on internal-network assumption"},
	{category: "Login Portals", query: `org:"Target" http.title:"Grafana"`, note: "default admin:admin still works on many instances"},
	{category: "Login Portals", query: `org:"Target" http.title:"Jenkins"`, note: "script console = RCE if unauth or weak auth"},
	// Favicon Pivot
	{category: "Favicon Pivot", query: `http.favicon.hash:<hash>`, note: "find all internet assets sharing the same favicon — run 'pivot' first"},
	// Actuator Hunt
	{category: "Actuator Hunt", query: `port:8081 Actuator`, note: "Spring Boot /actuator exposed — /env leaks creds, /heapdump exfils memory"},
	{category: "Actuator Hunt", query: `port:9001`, note: "management/metrics pivot — Prometheus, Portainer, or custom admin"},
	// AI/LLM Infrastructure
	{category: "AI/LLM Infra", query: `product:"Ollama" port:11434`, note: "T1 unauthenticated local LLM server — /api/tags lists models, /api/generate = RCE-adjacent"},
	{category: "AI/LLM Infra", query: `port:8000 "/v1/models"`, note: "OpenAI-compatible inference server — vLLM, LiteLLM, LocalAI"},
	{category: "AI/LLM Infra", query: `http.title:"Flowise"`, note: "T1 LLM orchestration — /api/v1/chatflows unauth CRUD on agent configs"},
	{category: "AI/LLM Infra", query: `http.title:"ChromaDB" OR port:8000 "chroma"`, note: "T1 vector DB — /api/v1/collections unauth read/write of embeddings"},
	{category: "AI/LLM Infra", query: `http.title:"Open WebUI"`, note: "T1 ChatGPT-style frontend — model access, history, often no auth"},
	{category: "AI/LLM Infra", query: `"DCGM" port:9400`, note: "NVIDIA GPU compute dashboard — /metrics exposes cluster topology"},
	// Menlo Security / Gateway
	{category: "Menlo Gateway", query: `http.headers:"X-Menlo-Security-IP"`, note: "Menlo isolation cloud header — map the gateway, find origin behind it"},
	{category: "Menlo Gateway", query: `ssl.cert.subject.cn:"*-isolation.com"`, note: "Menlo isolation domain in cert — pivot to non-Menlo org assets for origin leak"},
	{category: "Menlo Gateway", query: `ssl.cert.subject.cn:"*.menlosecurity.com"`, note: "Menlo infra cert — correlate CN with target org to fingerprint protected assets"},
}

func cmdCheatsheet() {
	fmt.Printf("%s%s=== goharvester Power-Dorks Cheatsheet ===%s\n", bold, cyan, reset)
	fmt.Printf("Replace %s\"Target\"%s with the actual org name.\n\n", yellow, reset)

	seen := []string{}
	byCat := map[string][]dork{}
	for _, d := range powerDorks {
		if _, ok := byCat[d.category]; !ok {
			seen = append(seen, d.category)
		}
		byCat[d.category] = append(byCat[d.category], d)
	}

	for _, cat := range seen {
		fmt.Printf("%s%s[%s]%s\n", bold, yellow, cat, reset)
		for _, d := range byCat[cat] {
			fmt.Printf("  %s%-60s%s  # %s\n", green, d.query, reset, d.note)
		}
		fmt.Println()
	}

	fmt.Printf("%sFavicon Pivot workflow:%s\n", bold, reset)
	fmt.Printf("  ./goharvester pivot https://target.com\n")
	fmt.Printf("  → prints the MurmurHash3 dork\n")
	fmt.Printf("  → find all shadow assets sharing that favicon\n\n")

	fmt.Printf("%sDirect pipe into hunt:%s\n", bold, reset)
	fmt.Printf("  SHODAN_API_KEY=xxx ./goharvester hunt --clean --export %q\n\n",
		`org:"Target" http.title:"Login"`)

	fmt.Printf("%sAI/LLM quick commands:%s\n", bold, reset)
	fmt.Printf("  ./goharvester ai-hunt                  # list all categories\n")
	fmt.Printf("  ./goharvester ai-hunt vector-db        # ChromaDB / Qdrant / Weaviate\n")
	fmt.Printf("  ./goharvester ai-hunt inference        # vLLM / Ollama / LiteLLM\n")
	fmt.Printf("  ./goharvester ai-hunt orchestration    # Flowise / Langflow / Dify\n")
	fmt.Printf("  ./goharvester ai-hunt gpu              # NVIDIA DCGM dashboards\n\n")

	fmt.Printf("%sEnterprise gateway commands:%s\n", bold, reset)
	fmt.Printf("  ./goharvester menlo-hunt               # Menlo Security JARM + origin-IP discovery\n\n")

	fmt.Printf("%sIngest and enrich:%s\n", bold, reset)
	fmt.Printf("  subfinder -d target.com -silent | ./goharvester import /dev/stdin --source subfinder\n")
	fmt.Printf("  ./goharvester buckets \"Tesla Motors\" --workers 50\n")
}
