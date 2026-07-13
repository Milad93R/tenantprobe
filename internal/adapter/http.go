package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Endpoint describes one HTTP operation (method + path) on the target.
type Endpoint struct {
	Method string `json:"method" yaml:"method"`
	Path   string `json:"path" yaml:"path"`
}

// PrincipalConfig describes how TenantProbe authenticates as one logical
// tenant. Map keys in GenericConfig.Principals must match scenario tenant IDs.
// TenantValue optionally maps that logical ID to the value expected by the
// target API. HeadersFromEnv keeps credentials out of scenario files.
type PrincipalConfig struct {
	TenantValue    string            `json:"tenantValue,omitempty" yaml:"tenant_value,omitempty"`
	Headers        map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	HeadersFromEnv map[string]string `json:"headersFromEnv,omitempty" yaml:"headers_from_env,omitempty"`
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
	BaseURL string `json:"baseUrl" yaml:"base_url"`

	// Endpoints. Reset may be zero (empty path) to skip resetting.
	Reset Endpoint `json:"reset" yaml:"reset"`
	Seed  Endpoint `json:"seed" yaml:"seed"`
	Chat  Endpoint `json:"chat" yaml:"chat"`

	// Preseeded declares that scenario documents already exist in the target.
	// In this mode Seed is intentionally a no-op and Seed.Path must be empty.
	// It is useful for systems that expose no test-only ingestion endpoint.
	Preseeded bool `json:"preseeded,omitempty" yaml:"preseeded,omitempty"`

	// Request-body JSON field names (dotted paths). These are the keys the
	// probe writes into the outgoing JSON body.
	TenantField string `json:"tenantField" yaml:"tenant_field"` // e.g. "tenant_id"
	QueryField  string `json:"queryField" yaml:"query_field"`   // e.g. "query"
	TopKField   string `json:"topKField" yaml:"top_k_field"`    // e.g. "top_k"
	DocIDField  string `json:"docIdField" yaml:"doc_id_field"`  // e.g. "doc_id"
	TextField   string `json:"textField" yaml:"text_field"`     // e.g. "text"

	// Response extraction JSON paths (dotted).
	AnswerPath    string `json:"answerPath" yaml:"answer_path"`       // e.g. "answer"
	CitationsPath string `json:"citationsPath" yaml:"citations_path"` // e.g. "citations"
	// Within a single citation object, keys for the referenced doc/tenant.
	CitationDocIDKey    string `json:"citationDocIdKey" yaml:"citation_doc_id_key"`       // e.g. "doc_id"
	CitationTenantIDKey string `json:"citationTenantIdKey" yaml:"citation_tenant_id_key"` // e.g. "tenant_id"

	// Static headers sent on every request (e.g. Authorization).
	Headers        map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	HeadersFromEnv map[string]string `json:"headersFromEnv,omitempty" yaml:"headers_from_env,omitempty"`

	// TenantHeader, when non-empty, injects the tenant id into this HTTP
	// header instead of the JSON body (the TenantField body key is then
	// omitted). Useful for APIs that scope tenancy via a header/token.
	TenantHeader string `json:"tenantHeader,omitempty" yaml:"tenant_header,omitempty"`

	// Principals supplies distinct credentials for each tenant. When non-empty,
	// Chat and Seed reject unknown tenant IDs instead of silently reusing one
	// shared credential across the entire scan.
	Principals map[string]PrincipalConfig `json:"principals,omitempty" yaml:"principals,omitempty"`
}

// NewGenericConfig returns a GenericConfig pre-filled with conventional
// defaults; callers override the fields their target differs on.
func NewGenericConfig(baseURL string) GenericConfig {
	return GenericConfig{
		BaseURL: baseURL,
		// Reset and Seed are deliberately opt-in. Guessing destructive lifecycle
		// endpoints is unsafe, and most production APIs do not expose them.
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
	cfg := NewGenericConfig(baseURL)
	cfg.Reset = Endpoint{Method: http.MethodPost, Path: "/reset"}
	cfg.Seed = Endpoint{Method: http.MethodPost, Path: "/seed"}
	return cfg
}

// GenericAdapter is a fully configurable HTTP adapter usable against any
// multi-tenant RAG/agent API without bespoke Go code.
type GenericAdapter struct {
	cfg    GenericConfig
	Client *http.Client
}

// NewGenericAdapter builds a GenericAdapter from cfg, trimming the base URL and
// applying a sane default timeout.
func NewGenericAdapter(cfg GenericConfig) (*GenericAdapter, error) {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("generic adapter: base URL is required")
	}
	if cfg.Chat.Path == "" {
		return nil, fmt.Errorf("generic adapter: chat endpoint path is required")
	}
	if cfg.Preseeded && cfg.Seed.Path != "" {
		return nil, fmt.Errorf("generic adapter: preseeded mode and a seed endpoint are mutually exclusive")
	}
	if !cfg.Preseeded && cfg.Seed.Path == "" {
		return nil, fmt.Errorf("generic adapter: configure a seed endpoint or set preseeded=true with a matching scenario")
	}
	return &GenericAdapter{
		cfg:    cfg,
		Client: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// SupportsCounterfactualWorlds is true only when the target exposes both a
// reset endpoint and real temporary ingestion. A no-op reset or preseeded mode
// cannot construct the paired worlds required by a causal isolation audit.
func (g *GenericAdapter) SupportsCounterfactualWorlds() bool {
	return !g.cfg.Preseeded && g.cfg.Reset.Path != "" && g.cfg.Seed.Path != ""
}

// principal resolves the target-facing tenant value and request headers for a
// logical scenario tenant. Environment-backed headers fail closed when their
// variable is missing so a scan cannot accidentally run unauthenticated.
func (g *GenericAdapter) principal(tenant string) (string, map[string]string, error) {
	wireTenant := tenant
	headers := make(map[string]string, len(g.cfg.Headers)+len(g.cfg.HeadersFromEnv)+2)
	for k, v := range g.cfg.Headers {
		headers[k] = v
	}
	for header, envName := range g.cfg.HeadersFromEnv {
		value, ok := os.LookupEnv(envName)
		if !ok || value == "" {
			return "", nil, fmt.Errorf("generic adapter: environment variable %s for header %s is not set", envName, header)
		}
		headers[header] = value
	}

	if len(g.cfg.Principals) == 0 || tenant == "" {
		return wireTenant, headers, nil
	}
	p, ok := g.cfg.Principals[tenant]
	if !ok {
		return "", nil, fmt.Errorf("generic adapter: no principal configured for tenant %q", tenant)
	}
	if p.TenantValue != "" {
		wireTenant = p.TenantValue
	}
	for k, v := range p.Headers {
		headers[k] = v
	}
	for header, envName := range p.HeadersFromEnv {
		value, ok := os.LookupEnv(envName)
		if !ok || value == "" {
			return "", nil, fmt.Errorf("generic adapter: environment variable %s for tenant %s header %s is not set", envName, tenant, header)
		}
		headers[header] = value
	}
	return wireTenant, headers, nil
}

// logicalTenant maps a target-facing tenant value found in a citation back to
// the scenario's logical tenant ID. Detectors compare logical identities, while
// real APIs commonly return an internal organization UUID.
func (g *GenericAdapter) logicalTenant(wireTenant string) string {
	for logical, principal := range g.cfg.Principals {
		candidate := principal.TenantValue
		if candidate == "" {
			candidate = logical
		}
		if candidate == wireTenant {
			return logical
		}
	}
	return wireTenant
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
	wireTenant, headers, err := g.principal(tenant)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if g.cfg.TenantHeader != "" && wireTenant != "" {
		req.Header.Set(g.cfg.TenantHeader, wireTenant)
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
	if g.cfg.Preseeded {
		return nil
	}
	wireTenant, _, err := g.principal(tenantID)
	if err != nil {
		return err
	}
	body := map[string]any{}
	if !g.useHeaderTenant() {
		setPath(body, g.cfg.TenantField, wireTenant)
	}
	setPath(body, g.cfg.DocIDField, docID)
	setPath(body, g.cfg.TextField, text)
	return g.do(g.cfg.Seed, body, tenantID, nil)
}

// Chat asks a query as a tenant and extracts the answer + citations via the
// configured JSON paths.
func (g *GenericAdapter) Chat(tenantID, query string, topK int) (string, []Citation, error) {
	wireTenant, _, err := g.principal(tenantID)
	if err != nil {
		return "", nil, err
	}
	body := map[string]any{}
	if !g.useHeaderTenant() {
		setPath(body, g.cfg.TenantField, wireTenant)
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
					TenantID: g.logicalTenant(toString(getPath(cm, g.cfg.CitationTenantIDKey))),
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
