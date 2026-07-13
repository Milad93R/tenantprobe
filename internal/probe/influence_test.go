package probe

import (
	"strings"
	"testing"

	"github.com/milad93r/tenantprobe/internal/adapter"
	"github.com/milad93r/tenantprobe/internal/canary"
)

// fakeAdapter is an in-memory multi-tenant RAG target used to exercise the
// content-influence sweep without a live HTTP server. isolate toggles tenant
// scoping; summarize toggles paraphrase (drops the verbatim canary code but
// keeps the doc's distinctive vocabulary), modelling a SILENT leak.
type fakeAdapter struct {
	store     []storedDoc
	isolate   bool // true => correctly tenant-scoped retrieval
	summarize bool // true => paraphrase retrieved chunks (no verbatim canary)
}

type storedDoc struct{ tenant, docID, text string }

func (f *fakeAdapter) Reset() error { f.store = nil; return nil }

func (f *fakeAdapter) Seed(tenant, docID, text string) error {
	f.store = append(f.store, storedDoc{tenant, docID, text})
	return nil
}

func (f *fakeAdapter) Chat(tenant, query string, topK int) (string, []adapter.Citation, error) {
	qset := map[string]bool{}
	for _, t := range strings.Fields(strings.ToLower(query)) {
		qset[t] = true
	}
	var hits []storedDoc
	for _, d := range f.store {
		if f.isolate && d.tenant != tenant {
			continue // tenant-scoped: never retrieve another tenant's doc
		}
		// crude overlap match
		for _, w := range strings.Fields(strings.ToLower(d.text)) {
			if qset[w] {
				hits = append(hits, d)
				break
			}
		}
	}
	if len(hits) == 0 {
		return "I don't have information on that.", nil, nil
	}
	if f.summarize {
		// paraphrase: keep words, drop 8-hex codes, no citations
		var kept []string
		for _, h := range hits {
			for _, w := range strings.Fields(h.text) {
				stripped := strings.Trim(w, ".:,")
				if len(stripped) == 8 && isHex(stripped) {
					continue
				}
				kept = append(kept, w)
			}
		}
		return "Records cover: " + strings.Join(kept, " "), nil, nil
	}
	var parts []string
	var cites []adapter.Citation
	for _, h := range hits {
		parts = append(parts, h.text)
		cites = append(cites, adapter.Citation{DocID: h.docID, TenantID: h.tenant})
	}
	return strings.Join(parts, " "), cites, nil
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return s != ""
}

// seedTenants seeds a fake adapter with the given tenants and returns the
// docsByTenant map the sweep needs.
func seedTenants(f *fakeAdapter, tenants []canary.Tenant) map[string][]string {
	_ = f.Reset()
	docs := map[string][]string{}
	for _, t := range tenants {
		_ = f.Seed(t.ID, t.ID+"-canary", t.Doc)
		docs[t.ID] = append(docs[t.ID], t.Doc)
	}
	return docs
}

func TestContentInfluence_FiresWhenSummaryPreservesVictimVocabulary(t *testing.T) {
	tenants := canary.MakeTenants(2)
	// Vulnerable (isolate=false) + summarize: the verbatim canary is gone but the
	// victim's distinctive topic vocabulary bleeds into the other tenant's answer.
	f := &fakeAdapter{isolate: false, summarize: true}
	docs := seedTenants(f, tenants)

	leaks, probes, err := contentInfluence(f, tenants, docs, 3)
	if err != nil {
		t.Fatalf("contentInfluence: %v", err)
	}
	if probes == 0 {
		t.Fatalf("expected probes > 0")
	}
	if len(leaks) == 0 {
		t.Fatalf("expected content_influence leak when a summary preserves victim vocabulary, got none")
	}
	for _, l := range leaks {
		if l.Type != "content_influence" {
			t.Errorf("unexpected leak type %q", l.Type)
		}
		if l.Attacker == l.Victim {
			t.Errorf("leak attributes a tenant to itself: %+v", l)
		}
	}
}

func TestContentInfluence_QuietWhenIsolated(t *testing.T) {
	tenants := canary.MakeTenants(2)
	// Correctly isolated (isolate=true) + summarize: no cross-tenant content, so
	// the sweep must NOT produce a false positive.
	f := &fakeAdapter{isolate: true, summarize: true}
	docs := seedTenants(f, tenants)

	leaks, _, err := contentInfluence(f, tenants, docs, 3)
	if err != nil {
		t.Fatalf("contentInfluence: %v", err)
	}
	if len(leaks) != 0 {
		t.Fatalf("expected no leaks on a correctly isolated target, got %d: %+v", len(leaks), leaks)
	}
}

func TestContentInfluence_DoesNotFlagOwnData(t *testing.T) {
	tenants := canary.MakeTenants(2)
	// Even in a fully-open target (verbatim), a tenant seeing ONLY its own data
	// must never be flagged; and a victim token appearing in the attacker's own
	// docs is excluded. Here we just assert self-attribution never happens.
	f := &fakeAdapter{isolate: false, summarize: false}
	docs := seedTenants(f, tenants)
	leaks, _, err := contentInfluence(f, tenants, docs, 3)
	if err != nil {
		t.Fatalf("contentInfluence: %v", err)
	}
	for _, l := range leaks {
		if l.Attacker == l.Victim {
			t.Fatalf("self-attribution leak: %+v", l)
		}
	}
}

func TestInfluenceQueryHoldsOutEvidenceTokens(t *testing.T) {
	docs := []string{"Acme renewal codename kestrel pricing northstar"}
	query := influenceQuery("Acme", docs)
	queryTokens := contentTokens(query)
	heldOut := diffTokens(docTokens(docs), queryTokens)
	if len(heldOut) < influenceMinNovelTokens {
		t.Fatalf("query %q leaves only %v; want at least %d held-out tokens", query, heldOut, influenceMinNovelTokens)
	}
}
