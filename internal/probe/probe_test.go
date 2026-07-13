package probe

import (
	"testing"

	"github.com/milad93r/tenantprobe/internal/detector"
)

func TestRunDistinguishesVulnerableAndIsolatedRetrieval(t *testing.T) {
	cfg := Config{
		Concurrency: 2,
		Attacks:     []string{"internal secret"},
		Tenants: []TenantSpec{
			{
				ID:   "Acme",
				Code: "ACME-1111AAAA",
				Docs: []Doc{{ID: "acme-doc", Text: "Acme internal secret ACME-1111AAAA project kestrel"}},
			},
			{
				ID:   "Globex",
				Code: "GLOBEX-2222BBBB",
				Docs: []Doc{{ID: "globex-doc", Text: "Globex internal secret GLOBEX-2222BBBB project marlin"}},
			},
		},
	}

	vulnerable, err := Run("fake://vulnerable", &fakeAdapter{}, detector.Default(), cfg)
	if err != nil {
		t.Fatalf("vulnerable Run: %v", err)
	}
	if vulnerable.Passed || len(vulnerable.Leaks) == 0 {
		t.Fatalf("vulnerable result = %+v, want attributed leaks", vulnerable)
	}
	if vulnerable.Probes != 2 {
		t.Fatalf("vulnerable probes = %d, want 2", vulnerable.Probes)
	}

	isolated, err := Run("fake://isolated", &fakeAdapter{isolate: true}, detector.Default(), cfg)
	if err != nil {
		t.Fatalf("isolated Run: %v", err)
	}
	if !isolated.Passed || len(isolated.Leaks) != 0 {
		t.Fatalf("isolated result = %+v, want clean pass", isolated)
	}
}

func TestDedupIsStableAndKeepsDistinctBoundaries(t *testing.T) {
	in := []detector.Leak{
		{Type: "z", Attacker: "B", Victim: "A", Evidence: "first"},
		{Type: "a", Attacker: "A", Victim: "B", Evidence: "second"},
		{Type: "z", Attacker: "B", Victim: "A", Evidence: "duplicate evidence"},
		{Type: "z", Attacker: "A", Victim: "B", Evidence: "third"},
	}
	got := dedup(in)
	if len(got) != 3 {
		t.Fatalf("dedup length = %d, want 3: %+v", len(got), got)
	}
	if got[0].Type != "a" || got[1].Attacker != "A" || got[2].Attacker != "B" {
		t.Fatalf("dedup order is not stable: %+v", got)
	}
}
