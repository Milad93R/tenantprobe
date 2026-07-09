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
	flag.Parse()

	// Allow a positional URL to override -target for ergonomic CLI use.
	if args := flag.Args(); len(args) > 0 && args[0] != "" {
		*target = args[0]
	}

	a := adapter.NewDemoAdapter(*target)
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
