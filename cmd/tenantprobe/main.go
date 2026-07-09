// Command tenantprobe is a CI red-team scanner for cross-tenant isolation in
// multi-tenant RAG/agent APIs. It seeds synthetic tenants with unique canary
// secrets, attacks the target from one tenant trying to reach another's data,
// and exits non-zero on any cross-tenant leak.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/milad93r/tenantprobe/internal/adapter"
	"github.com/milad93r/tenantprobe/internal/detector"
	"github.com/milad93r/tenantprobe/internal/probe"
)

func main() {
	target := flag.String("target", "http://127.0.0.1:8000", "base URL of the multi-tenant target API")
	nTenants := flag.Int("tenants", 2, "number of synthetic tenants to seed")
	topK := flag.Int("top-k", 3, "top_k passed to the target's chat endpoint")
	concurrency := flag.Int("concurrency", 8, "max in-flight probes")

	adapterName := flag.String("adapter", "demo", "target adapter: demo | generic")
	adapterConfig := flag.String("adapter-config", "", "path to a JSON GenericConfig file (generic adapter)")

	// Generic-adapter overrides (also settable via -adapter-config JSON).
	gResetPath := flag.String("g-reset-path", "/reset", "generic: reset endpoint path (empty to skip)")
	gSeedPath := flag.String("g-seed-path", "/seed", "generic: seed endpoint path")
	gChatPath := flag.String("g-chat-path", "/chat", "generic: chat endpoint path")
	gTenantField := flag.String("g-tenant-field", "tenant_id", "generic: request body tenant field (dotted)")
	gQueryField := flag.String("g-query-field", "query", "generic: request body query field (dotted)")
	gTopKField := flag.String("g-top-k-field", "top_k", "generic: request body top_k field (dotted, empty to omit)")
	gDocIDField := flag.String("g-doc-id-field", "doc_id", "generic: request body doc_id field (dotted)")
	gTextField := flag.String("g-text-field", "text", "generic: request body text field (dotted)")
	gAnswerPath := flag.String("g-answer-path", "answer", "generic: response answer path (dotted)")
	gCitationsPath := flag.String("g-citations-path", "citations", "generic: response citations array path (dotted)")
	gCitDocIDKey := flag.String("g-citation-doc-id-key", "doc_id", "generic: citation doc_id key (dotted)")
	gCitTenantIDKey := flag.String("g-citation-tenant-id-key", "tenant_id", "generic: citation tenant_id key (dotted)")
	gTenantHeader := flag.String("g-tenant-header", "", "generic: send tenant in this HTTP header instead of the body")

	flag.Parse()

	// Allow a positional URL to override -target for ergonomic CLI use.
	if args := flag.Args(); len(args) > 0 && args[0] != "" {
		*target = args[0]
	}

	var a adapter.Adapter
	switch *adapterName {
	case "demo":
		a = adapter.NewDemoAdapter(*target)
	case "generic":
		cfg := adapter.NewGenericConfig(*target)
		if *adapterConfig != "" {
			data, err := os.ReadFile(*adapterConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "tenantprobe: read adapter-config: %v\n", err)
				os.Exit(2)
			}
			if err := json.Unmarshal(data, &cfg); err != nil {
				fmt.Fprintf(os.Stderr, "tenantprobe: parse adapter-config: %v\n", err)
				os.Exit(2)
			}
			// A config file may omit the base URL; fall back to -target/positional.
			if cfg.BaseURL == "" {
				cfg.BaseURL = *target
			}
		} else {
			// No file: build entirely from flags (defaults already mirror the demo).
			cfg.Reset.Path = *gResetPath
			cfg.Seed.Path = *gSeedPath
			cfg.Chat.Path = *gChatPath
			cfg.TenantField = *gTenantField
			cfg.QueryField = *gQueryField
			cfg.TopKField = *gTopKField
			cfg.DocIDField = *gDocIDField
			cfg.TextField = *gTextField
			cfg.AnswerPath = *gAnswerPath
			cfg.CitationsPath = *gCitationsPath
			cfg.CitationDocIDKey = *gCitDocIDKey
			cfg.CitationTenantIDKey = *gCitTenantIDKey
			cfg.TenantHeader = *gTenantHeader
		}
		a = adapter.NewGenericAdapter(cfg)
	default:
		fmt.Fprintf(os.Stderr, "tenantprobe: unknown adapter %q (want demo|generic)\n", *adapterName)
		os.Exit(2)
	}

	res, err := probe.Run(*target, a, detector.Default(), probe.Config{
		NTenants:    *nTenants,
		TopK:        *topK,
		Concurrency: *concurrency,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tenantprobe: %v\n", err)
		os.Exit(2)
	}

	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tenantprobe: marshal result: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))

	if res.Passed {
		fmt.Printf("PASS: no cross-tenant leaks across %d probes\n", res.Probes)
		os.Exit(0)
	}
	fmt.Printf("FAIL: %d cross-tenant leak(s) detected across %d probes\n", len(res.Leaks), res.Probes)
	os.Exit(1)
}
