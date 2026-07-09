package scenario

import (
	"os"
	"strings"
	"testing"
)

// TestLoadBasic loads the shipped basic.yaml and asserts the core invariants:
// two tenants parsed, {{canary}} substitution happened, and both default
// detectors are enabled.
func TestLoadBasic(t *testing.T) {
	sc, err := Load("../../testdata/scenarios/basic.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := len(sc.Tenants); got != 2 {
		t.Fatalf("tenants = %d, want 2", got)
	}

	// Canary substitution: no placeholder remains, and each tenant's generated
	// code appears in its document text.
	specs := sc.TenantSpecs()
	if len(specs) != 2 {
		t.Fatalf("TenantSpecs = %d, want 2", len(specs))
	}
	seenCodes := map[string]bool{}
	for _, ts := range specs {
		if ts.Code == "" {
			t.Errorf("tenant %s: empty canary code (substitution did not run)", ts.ID)
		}
		if seenCodes[ts.Code] {
			t.Errorf("tenant %s: canary code %q is not unique", ts.ID, ts.Code)
		}
		seenCodes[ts.Code] = true
		if len(ts.Docs) != 1 {
			t.Fatalf("tenant %s: docs = %d, want 1", ts.ID, len(ts.Docs))
		}
		doc := ts.Docs[0]
		if strings.Contains(doc.Text, canaryPlaceholder) {
			t.Errorf("tenant %s: %q still contains %s", ts.ID, doc.Text, canaryPlaceholder)
		}
		if !strings.Contains(doc.Text, ts.Code) {
			t.Errorf("tenant %s: code %q not embedded in doc %q", ts.ID, ts.Code, doc.Text)
		}
	}

	// Assertions default to the core detector set.
	want := map[string]bool{"canary_in_answer": true, "cross_tenant_citation": true}
	got := sc.EnabledAssertions()
	if len(got) != len(want) {
		t.Fatalf("assertions = %v, want %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected assertion %q", name)
		}
	}
	dets, err := sc.Detectors()
	if err != nil {
		t.Fatalf("Detectors: %v", err)
	}
	if len(dets) != 2 {
		t.Fatalf("Detectors() = %d, want 2", len(dets))
	}

	// Adapter defaults / matches file: demo.
	if sc.Adapter.Name != "demo" {
		t.Errorf("adapter = %q, want demo", sc.Adapter.Name)
	}
	a, err := sc.BuildAdapter()
	if err != nil {
		t.Fatalf("BuildAdapter: %v", err)
	}
	if a == nil {
		t.Fatal("BuildAdapter returned nil adapter")
	}
}

// TestValidationErrors checks that malformed scenarios fail with a clear,
// field-scoped message rather than silently.
func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "too few tenants",
			yaml:    "tenants:\n  - id: only\n    docs:\n      - doc_id: d\n        text: hi\n",
			wantSub: "at least two tenants",
		},
		{
			name:    "unknown adapter",
			yaml:    "adapter:\n  name: bogus\ntenants:\n  - id: a\n    docs: [{doc_id: d, text: t}]\n  - id: b\n    docs: [{doc_id: d, text: t}]\n",
			wantSub: "unknown adapter",
		},
		{
			name:    "unknown assertion",
			yaml:    "tenants:\n  - id: a\n    docs: [{doc_id: d, text: t}]\n  - id: b\n    docs: [{doc_id: d, text: t}]\nassertions: [nope]\n",
			wantSub: "unknown detector",
		},
		{
			name:    "duplicate tenant id",
			yaml:    "tenants:\n  - id: a\n    docs: [{doc_id: d, text: t}]\n  - id: a\n    docs: [{doc_id: d, text: t}]\n",
			wantSub: "duplicate tenant",
		},
		{
			name:    "tenant with no docs",
			yaml:    "tenants:\n  - id: a\n    docs: []\n  - id: b\n    docs: [{doc_id: d, text: t}]\n",
			wantSub: "no documents",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/s.yaml"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return path
}
