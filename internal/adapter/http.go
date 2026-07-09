package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Endpoint describes one HTTP operation (method + path) on the target.
type Endpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// GenericConfig fully describes how to talk to an arbitrary multi-tenant RAG
// API: which endpoints to hit, how to name the request-body fields, and how to
// extract the answer + citations from the response. Every extraction/injection
// site is a dotted JSON path (e.g. "data.answer", "result.docs") walked by a
// tiny stdlib map walker, so no client-specific code is ever required.
//
// The zero value is not useful; build one with defaults via NewGenericConfig
// (or DemoGenericConfig for a demo-equivalent mapping) and override fields.
type GenericConfig struct {
	BaseURL string `json:"base_url"`

	// Endpoints. Reset may be zero (empty path) to skip resetting.
	Reset Endpoint `json:"reset"`
	Seed  Endpoint `json:"seed"`
	Chat  Endpoint `json:"chat"`

	// Request-body JSON field names (dotted paths). These are the keys the
	// probe writes into the outgoing JSON body.
	TenantField string `json:"tenant_field"` // e.g. "tenant_id"
	QueryField  string `json:"query_field"`  // e.g. "query"
	TopKField   string `json:"top_k_field"`  // e.g. "top_k"
	DocIDField  string `json:"doc_id_field"` // e.g. "doc_id"
	TextField   string `json:"text_field"`   // e.g. "text"

	// Response extraction JSON paths (dotted).
	AnswerPath    string `json:"answer_path"`    // e.g. "answer"
	CitationsPath string `json:"citations_path"` // e.g. "citations"
	// Within a single citation object, keys for the referenced doc/tenant.
	CitationDocIDKey    string `json:"citation_doc_id_key"`    // e.g. "doc_id"
	CitationTenantIDKey string `json:"citation_tenant_id_key"` // e.g. "tenant_id"

	// Static headers sent on every request (e.g. Authorization).
	Headers map[string]string `json:"headers"`

	// TenantHeader, when non-empty, injects the tenant id into this HTTP
	// header instead of the JSON body (the TenantField body key is then
	// omitted). Useful for APIs that scope tenancy via a header/token.
	TenantHeader string `json:"tenant_header"`
}

// NewGenericConfig returns a GenericConfig pre-filled with conventional
// defaults; callers override the fields their target differs on.
func NewGenericConfig(baseURL string) GenericConfig {
	return GenericConfig{
		BaseURL:             baseURL,
		Reset:               Endpoint{Method: http.MethodPost, Path: "/reset"},
		Seed:                Endpoint{Method: http.MethodPost, Path: "/seed"},
		Chat:                Endpoint{Method: http.MethodPost, Path: "/chat"},
		TenantField:         "tenant_id",
		QueryField:          "query",
		TopKField:           "top_k",
		DocIDField:          "doc_id",
		TextField:           "text",
		AnswerPath:          "answer",
		CitationsPath:       "citations",
		CitationDocIDKey:    "doc_id",
		CitationTenantIDKey: "tenant_id",
	}
}

// DemoGenericConfig is NewGenericConfig — the defaults already mirror the demo
// contract, kept as a named helper for clarity in tests and CLI wiring.
func DemoGenericConfig(baseURL string) GenericConfig {
	return NewGenericConfig(baseURL)
}

// GenericAdapter is a fully configurable HTTP adapter usable against any
// multi-tenant RAG/agent API without bespoke Go code.
type GenericAdapter struct {
	cfg    GenericConfig
	Client *http.Client
}

// NewGenericAdapter builds a GenericAdapter from cfg, trimming the base URL and
// applying a sane default timeout.
func NewGenericAdapter(cfg GenericConfig) *GenericAdapter {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &GenericAdapter{
		cfg:    cfg,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

// do issues one request to ep with the given JSON body and optional per-request
// tenant (for header injection), decoding the response into out when non-nil.
func (g *GenericAdapter) do(ep Endpoint, body map[string]any, tenant string, out *map[string]any) error {
	if ep.Path == "" {
		return nil // skippable endpoint (e.g. reset)
	}
	method := ep.Method
	if method == "" {
		method = http.MethodPost
	}

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", ep.Path, err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, g.cfg.BaseURL+ep.Path, reader)
	if err != nil {
		return fmt.Errorf("new request %s: %w", ep.Path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range g.cfg.Headers {
		req.Header.Set(k, v)
	}
	if g.cfg.TenantHeader != "" && tenant != "" {
		req.Header.Set(g.cfg.TenantHeader, tenant)
	}

	resp, err := g.Client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, ep.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: status %d: %s", method, ep.Path, resp.StatusCode, snippet)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	m := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return fmt.Errorf("decode %s: %w", ep.Path, err)
	}
	*out = m
	return nil
}

// useHeaderTenant reports whether the tenant id travels in a header rather than
// the request body.
func (g *GenericAdapter) useHeaderTenant() bool {
	return g.cfg.TenantHeader != ""
}

// Reset clears target state, or is a no-op when no reset endpoint is configured.
func (g *GenericAdapter) Reset() error {
	return g.do(g.cfg.Reset, map[string]any{}, "", nil)
}

// Seed stores a document for a tenant.
func (g *GenericAdapter) Seed(tenantID, docID, text string) error {
	body := map[string]any{}
	if !g.useHeaderTenant() {
		setPath(body, g.cfg.TenantField, tenantID)
	}
	setPath(body, g.cfg.DocIDField, docID)
	setPath(body, g.cfg.TextField, text)
	return g.do(g.cfg.Seed, body, tenantID, nil)
}

// Chat asks a query as a tenant and extracts the answer + citations via the
// configured JSON paths.
func (g *GenericAdapter) Chat(tenantID, query string, topK int) (string, []Citation, error) {
	body := map[string]any{}
	if !g.useHeaderTenant() {
		setPath(body, g.cfg.TenantField, tenantID)
	}
	setPath(body, g.cfg.QueryField, query)
	if g.cfg.TopKField != "" {
		setPath(body, g.cfg.TopKField, topK)
	}

	var out map[string]any
	if err := g.do(g.cfg.Chat, body, tenantID, &out); err != nil {
		return "", nil, err
	}

	answer := toString(getPath(out, g.cfg.AnswerPath))

	var citations []Citation
	if raw := getPath(out, g.cfg.CitationsPath); raw != nil {
		if arr, ok := raw.([]any); ok {
			for _, item := range arr {
				cm, ok := item.(map[string]any)
				if !ok {
					continue
				}
				citations = append(citations, Citation{
					DocID:    toString(getPath(cm, g.cfg.CitationDocIDKey)),
					TenantID: toString(getPath(cm, g.cfg.CitationTenantIDKey)),
				})
			}
		}
	}
	return answer, citations, nil
}

// --- tiny stdlib dotted-path helpers ---

// getPath walks m along a dotted path (e.g. "data.answer") and returns the
// value found, or nil if any segment is missing. An empty path returns m.
func getPath(m map[string]any, path string) any {
	if path == "" {
		return m
	}
	var cur any = m
	for _, seg := range strings.Split(path, ".") {
		node, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = node[seg]
		if !ok {
			return nil
		}
	}
	return cur
}

// setPath writes val into m at a dotted path, creating intermediate maps as
// needed. A path with no dots sets a single top-level key.
func setPath(m map[string]any, path string, val any) {
	if path == "" {
		return
	}
	segs := strings.Split(path, ".")
	cur := m
	for _, seg := range segs[:len(segs)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = val
}

// toString coerces a decoded JSON scalar to a string; non-scalars become "".
func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
