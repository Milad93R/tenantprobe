package probe

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/milad93r/tenantprobe/internal/adapter"
)

type pcniStoredFact struct {
	tenant string
	value  string
}

// pcniFakeAdapter is a deterministic black-box target. When isolate is false,
// every principal can resolve every seeded subject; when true, only the owning
// principal can. Its fallback always chooses the first option, modelling a
// stable model prior that must not be mistaken for causal data flow.
type pcniFakeAdapter struct {
	isolate    bool
	breakOwner string
	facts      map[string]pcniStoredFact
}

var (
	pcniDocRE   = regexp.MustCompile(`subject ([a-z0-9-]+) has marker ([a-z]+)`)
	pcniQueryRE = regexp.MustCompile(`subject ([a-z0-9-]+).*marker ([a-z]+) or ([a-z]+)`)
)

func (f *pcniFakeAdapter) Reset() error {
	f.facts = map[string]pcniStoredFact{}
	return nil
}

func (f *pcniFakeAdapter) Seed(tenant, _ string, text string) error {
	m := pcniDocRE.FindStringSubmatch(strings.ToLower(text))
	if len(m) != 3 {
		return fmt.Errorf("unexpected seeded document %q", text)
	}
	f.facts[m[1]] = pcniStoredFact{tenant: tenant, value: m[2]}
	return nil
}

func (f *pcniFakeAdapter) Chat(tenant, query string, _ int) (string, []adapter.Citation, error) {
	m := pcniQueryRE.FindStringSubmatch(strings.ToLower(query))
	if len(m) != 4 {
		return "unknown", nil, nil
	}
	fact, ok := f.facts[m[1]]
	if ok && tenant == f.breakOwner && fact.tenant == tenant {
		return "unknown", nil, nil
	}
	if ok && (!f.isolate || fact.tenant == tenant) {
		return fact.value, nil, nil
	}
	return m[2], nil, nil // stable prior: never follows the victim-only flip
}

func TestRunCounterfactualDetectsCrossTenantInfluence(t *testing.T) {
	res, err := RunCounterfactual("fake", &pcniFakeAdapter{isolate: false}, CounterfactualConfig{
		TenantIDs: []string{"Acme", "Globex"}, Bits: 12, Alpha: 0.05,
	})
	if err != nil {
		t.Fatalf("RunCounterfactual: %v", err)
	}
	if res.Passed || len(res.Leaks) != 2 {
		t.Fatalf("vulnerable target: passed=%v leaks=%+v", res.Passed, res.Leaks)
	}
	for _, pair := range res.Counterfactual.Pairs {
		if pair.Concordant != pair.Calibrated || !pair.Significant {
			t.Errorf("expected perfect significant tracking, got %+v", pair)
		}
	}
}

func TestRunCounterfactualRejectsStablePriorOnIsolatedTarget(t *testing.T) {
	res, err := RunCounterfactual("fake", &pcniFakeAdapter{isolate: true}, CounterfactualConfig{
		TenantIDs: []string{"Acme", "Globex"}, Bits: 12, Alpha: 0.05,
	})
	if err != nil {
		t.Fatalf("RunCounterfactual: %v", err)
	}
	if !res.Passed || len(res.Leaks) != 0 {
		t.Fatalf("isolated target: passed=%v leaks=%+v", res.Passed, res.Leaks)
	}
	for _, pair := range res.Counterfactual.Pairs {
		if pair.Concordant != 0 || pair.Significant {
			t.Errorf("stable prior looked like a leak: %+v", pair)
		}
	}
}

func TestRunCounterfactualFailsInconclusiveCalibration(t *testing.T) {
	_, err := RunCounterfactual("fake", &pcniFakeAdapter{isolate: true, breakOwner: "Acme"}, CounterfactualConfig{
		TenantIDs: []string{"Acme", "Globex"}, Bits: 12, Alpha: 0.05,
	})
	if err == nil || !strings.Contains(err.Error(), "inconclusive") {
		t.Fatalf("want explicit inconclusive calibration error, got %v", err)
	}
}

func TestExtractFactAnswer(t *testing.T) {
	pair := factPair{"amber", "cobalt"}
	tests := []struct {
		answer string
		want   int
	}{
		{"Amber.", 0},
		{"cobalt, according to the registry", 1},
		{"The marker is amber.", 0},
		{"Amber, not cobalt.", 0},
		{"It could be amber or cobalt.", -1},
		{"I do not know.", -1},
	}
	for _, tc := range tests {
		if got := extractFactAnswer(tc.answer, pair); got != tc.want {
			t.Errorf("extractFactAnswer(%q)=%d, want %d", tc.answer, got, tc.want)
		}
	}
}

func TestBinomialUpperTailAndHolm(t *testing.T) {
	if got := binomialUpperTail(3, 3); mathAbs(got-0.125) > 1e-12 {
		t.Fatalf("tail(3,3)=%.12f, want .125", got)
	}
	if got := binomialUpperTail(3, 2); mathAbs(got-0.5) > 1e-12 {
		t.Fatalf("tail(3,2)=%.12f, want .5", got)
	}
	pairs := []CounterfactualPair{{RawP: 0.01}, {RawP: 0.03}, {RawP: 0.2}}
	applyHolm(pairs, 0.05)
	if mathAbs(pairs[0].AdjustedP-0.03) > 1e-12 || !pairs[0].Significant {
		t.Errorf("first Holm result=%+v, want adjusted .03 significant", pairs[0])
	}
	if pairs[1].Significant || pairs[2].Significant {
		t.Errorf("unexpected Holm significance: %+v", pairs)
	}
}

func mathAbs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
