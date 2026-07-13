package adapter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/milad93r/tenantprobe/internal/adapter"
)

func TestGenericAdapterUsesDistinctTenantPrincipals(t *testing.T) {
	t.Setenv("TOKEN_A", "Bearer token-a")
	t.Setenv("TOKEN_B", "Bearer token-b")

	wantAuth := map[string]string{
		"org-a": "Bearer token-a",
		"org-b": "Bearer token-b",
	}
	var mu sync.Mutex
	seeded := map[string]string{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		org := body["org"].(map[string]any)["id"].(string)
		if got := r.Header.Get("Authorization"); got != wantAuth[org] {
			t.Errorf("%s auth = %q, want %q", org, got, wantAuth[org])
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/documents":
			mu.Lock()
			seeded[org] = body["content"].(string)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case "/query":
			mu.Lock()
			answer := seeded[org]
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"answer":  answer,
					"sources": []map[string]any{{"id": "doc-1", "owner": org}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := adapter.NewGenericConfig(srv.URL)
	cfg.Seed = adapter.Endpoint{Method: http.MethodPost, Path: "/documents"}
	cfg.Chat = adapter.Endpoint{Method: http.MethodPost, Path: "/query"}
	cfg.TenantField = "org.id"
	cfg.QueryField = "input.question"
	cfg.TextField = "content"
	cfg.AnswerPath = "data.answer"
	cfg.CitationsPath = "data.sources"
	cfg.CitationDocIDKey = "id"
	cfg.CitationTenantIDKey = "owner"
	cfg.Principals = map[string]adapter.PrincipalConfig{
		"Tenant-A": {TenantValue: "org-a", HeadersFromEnv: map[string]string{"Authorization": "TOKEN_A"}},
		"Tenant-B": {TenantValue: "org-b", HeadersFromEnv: map[string]string{"Authorization": "TOKEN_B"}},
	}

	a, err := adapter.NewGenericAdapter(cfg)
	if err != nil {
		t.Fatalf("NewGenericAdapter: %v", err)
	}
	if err := a.Seed("Tenant-A", "doc-a", "alpha-private-fact"); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if err := a.Seed("Tenant-B", "doc-b", "bravo-private-fact"); err != nil {
		t.Fatalf("seed B: %v", err)
	}

	answer, citations, err := a.Chat("Tenant-B", "what is mine?", 3)
	if err != nil {
		t.Fatalf("chat B: %v", err)
	}
	if answer != "bravo-private-fact" {
		t.Fatalf("answer = %q, want tenant B document", answer)
	}
	if len(citations) != 1 || citations[0].TenantID != "Tenant-B" || citations[0].DocID != "doc-1" {
		t.Fatalf("citations = %+v", citations)
	}
}

func TestGenericAdapterPreseededAndFailClosedAuth(t *testing.T) {
	cfg := adapter.NewGenericConfig("https://example.invalid")
	cfg.Preseeded = true
	cfg.Principals = map[string]adapter.PrincipalConfig{
		"Tenant-A": {HeadersFromEnv: map[string]string{"Authorization": "MISSING_TOKEN"}},
	}
	a, err := adapter.NewGenericAdapter(cfg)
	if err != nil {
		t.Fatalf("NewGenericAdapter: %v", err)
	}

	// Preseeded mode deliberately performs no network call during Seed.
	if err := a.Seed("Tenant-A", "known-doc", "known literal fact"); err != nil {
		t.Fatalf("preseeded Seed: %v", err)
	}
	if _, _, err := a.Chat("Tenant-A", "query", 3); err == nil {
		t.Fatal("expected missing credential environment variable to fail closed")
	}
	if _, _, err := a.Chat("Tenant-B", "query", 3); err == nil {
		t.Fatal("expected unknown tenant principal to fail closed")
	}
}

func TestGenericAdapterRequiresExplicitLifecycle(t *testing.T) {
	cfg := adapter.NewGenericConfig("https://example.invalid")
	if _, err := adapter.NewGenericAdapter(cfg); err == nil {
		t.Fatal("expected missing seed lifecycle configuration to fail")
	}

	cfg.Preseeded = true
	cfg.Seed = adapter.Endpoint{Path: "/documents"}
	if _, err := adapter.NewGenericAdapter(cfg); err == nil {
		t.Fatal("expected preseeded plus seed endpoint to be rejected")
	}
}
