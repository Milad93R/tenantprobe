// Package scenario loads a declarative YAML scan definition — tenants, their
// canary documents, attack queries, and which detectors (assertions) to enable —
// and turns it into the concrete adapter, tenants, attacks and detectors the
// probe orchestrator consumes.
//
// A scenario file lets a user pin a reproducible cross-tenant isolation test in
// version control and run it in CI without any Go code or flags:
//
//	tenantprobe -scenario scan.yaml
//
// The one placeholder understood inside document text is {{canary}}: it is
// replaced, per tenant, with a freshly generated high-entropy code that the
// canary_in_answer detector watches for. Documents may also embed an explicit
// literal secret instead of {{canary}}.
package scenario

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/milad93r/tenantprobe/internal/adapter"
	"github.com/milad93r/tenantprobe/internal/canary"
	"github.com/milad93r/tenantprobe/internal/detector"
	"github.com/milad93r/tenantprobe/internal/probe"
)

// canaryPlaceholder is substituted, per tenant, with a unique generated code.
const canaryPlaceholder = "{{canary}}"

// DocSpec is one document belonging to a tenant.
type DocSpec struct {
	DocID string `yaml:"doc_id"`
	Text  string `yaml:"text"`
}

// TenantSpec is a tenant with its seeded documents.
type TenantSpec struct {
	ID   string    `yaml:"id"`
	Docs []DocSpec `yaml:"docs"`
}

// AdapterSpec selects and configures the transport. Only the block matching Name
// is consulted.
type AdapterSpec struct {
	Name    string                 `yaml:"name"`    // demo | generic | openai
	Generic *adapter.GenericConfig `yaml:"generic"` // when name == generic
	OpenAI  *adapter.OpenAIConfig  `yaml:"openai"`  // when name == openai
}

// Scenario is the parsed top-level file.
type Scenario struct {
	// Target base URL. Adapter configs inherit it when they omit base_url.
	Target string `yaml:"target"`
	// Adapter selection/configuration. Defaults to the demo adapter.
	Adapter AdapterSpec `yaml:"adapter"`
	// Tenants and their canary documents. At least two are required.
	Tenants []TenantSpec `yaml:"tenants"`
	// Attacks override the built-in query battery when non-empty.
	Attacks []string `yaml:"attacks"`
	// Assertions names the detectors to enable. Defaults to the core set.
	Assertions []string `yaml:"assertions"`
	// Patterns are extra user-supplied regexes fed to the PII/secret detector
	// (they emit secret_leak). Only consulted when a regex assertion is enabled.
	Patterns []string `yaml:"patterns"`

	// codes records the generated canary code per tenant id after Load.
	codes map[string]string
}

// Load reads, parses and validates a scenario file, performing {{canary}}
// substitution. Errors name the file and offending field for quick diagnosis.
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scenario: read %s: %w", path, err)
	}

	var s Scenario
	// Strict decoding surfaces typos/unknown keys instead of silently ignoring them.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scenario: parse %s: %w", path, err)
	}

	if err := s.normalize(path); err != nil {
		return nil, err
	}
	return &s, nil
}

// normalize applies defaults, validates, and performs canary substitution.
func normalizeErr(path, field, msg string) error {
	return fmt.Errorf("scenario %s: field %q: %s", path, field, msg)
}

func (s *Scenario) normalize(path string) error {
	if s.Adapter.Name == "" {
		s.Adapter.Name = "demo"
	}
	switch s.Adapter.Name {
	case "demo", "generic", "openai":
	default:
		return normalizeErr(path, "adapter.name", fmt.Sprintf("unknown adapter %q (want demo|generic|openai)", s.Adapter.Name))
	}

	if len(s.Tenants) < 2 {
		return normalizeErr(path, "tenants", "at least two tenants are required for a cross-tenant scan")
	}

	// Validate tenants and substitute canaries.
	s.codes = make(map[string]string, len(s.Tenants))
	seenTenant := make(map[string]bool, len(s.Tenants))
	for ti := range s.Tenants {
		t := &s.Tenants[ti]
		if strings.TrimSpace(t.ID) == "" {
			return normalizeErr(path, fmt.Sprintf("tenants[%d].id", ti), "must be non-empty")
		}
		if seenTenant[t.ID] {
			return normalizeErr(path, fmt.Sprintf("tenants[%d].id", ti), fmt.Sprintf("duplicate tenant id %q", t.ID))
		}
		seenTenant[t.ID] = true
		if len(t.Docs) == 0 {
			return normalizeErr(path, fmt.Sprintf("tenants[%d].docs", ti), fmt.Sprintf("tenant %q has no documents to seed", t.ID))
		}

		// One canary code per tenant, generated lazily on first {{canary}} use.
		code := makeCode(t.ID)
		usedCanary := false
		for di := range t.Docs {
			d := &t.Docs[di]
			if strings.TrimSpace(d.DocID) == "" {
				return normalizeErr(path, fmt.Sprintf("tenants[%d].docs[%d].doc_id", ti, di), "must be non-empty")
			}
			if strings.TrimSpace(d.Text) == "" {
				return normalizeErr(path, fmt.Sprintf("tenants[%d].docs[%d].text", ti, di), "must be non-empty")
			}
			if strings.Contains(d.Text, canaryPlaceholder) {
				d.Text = strings.ReplaceAll(d.Text, canaryPlaceholder, code)
				usedCanary = true
			}
		}
		if usedCanary {
			s.codes[t.ID] = code
		}
	}

	// Assertions default to the core detector set.
	if len(s.Assertions) == 0 {
		s.Assertions = []string{"canary_in_answer", "cross_tenant_citation"}
	}
	// Validate each named assertion resolves to a real detector.
	for i, name := range s.Assertions {
		if _, err := detector.ByName(name); err != nil {
			return normalizeErr(path, fmt.Sprintf("assertions[%d]", i), err.Error())
		}
	}

	return nil
}

// makeCode returns a unique canary code for a tenant, matching the auto-mode
// format (TENANTID-<8HEX>) so the canary detector behaves identically.
func makeCode(tenantID string) string {
	bare := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "_", "").Replace(tenantID))
	return fmt.Sprintf("%s-%s", bare, canary.RandCode())
}

// Code returns the generated canary code for a tenant (empty if the tenant used
// no {{canary}} placeholder).
func (s *Scenario) Code(tenantID string) string { return s.codes[tenantID] }

// TenantSpecs returns the tenants as probe.TenantSpec, with canary codes wired
// through so the canary detector can flag leaks.
func (s *Scenario) TenantSpecs() []probe.TenantSpec {
	out := make([]probe.TenantSpec, 0, len(s.Tenants))
	for _, t := range s.Tenants {
		docs := make([]probe.Doc, 0, len(t.Docs))
		for _, d := range t.Docs {
			docs = append(docs, probe.Doc{ID: d.DocID, Text: d.Text})
		}
		out = append(out, probe.TenantSpec{ID: t.ID, Code: s.codes[t.ID], Docs: docs})
	}
	return out
}

// AttackList returns the scenario attacks (may be empty, meaning "use built-ins").
func (s *Scenario) AttackList() []string { return s.Attacks }

// Detectors builds the detector set named by assertions, deduplicating aliases
// and threading any user-supplied patterns into the PII/secret regex detector. It
// assumes normalize already validated the names.
func (s *Scenario) Detectors() ([]detector.Detector, error) {
	return detector.Select(s.Assertions, s.Patterns)
}

// EnabledAssertions returns the resolved assertion names (post-default).
func (s *Scenario) EnabledAssertions() []string { return s.Assertions }

// BuildAdapter constructs the transport adapter described by the scenario,
// inheriting Target where an adapter block omits its base URL.
func (s *Scenario) BuildAdapter() (adapter.Adapter, error) {
	switch s.Adapter.Name {
	case "demo":
		return adapter.NewDemoAdapter(s.Target), nil

	case "generic":
		cfg := adapter.NewGenericConfig(s.Target)
		if s.Adapter.Generic != nil {
			// Overlay explicit fields from the file; keep defaults otherwise.
			g := *s.Adapter.Generic
			if g.BaseURL != "" {
				cfg.BaseURL = g.BaseURL
			}
			mergeGeneric(&cfg, g)
		}
		return adapter.NewGenericAdapter(cfg), nil

	case "openai":
		cfg := adapter.NewOpenAIConfig(s.Target)
		if s.Adapter.OpenAI != nil {
			o := *s.Adapter.OpenAI
			if o.BaseURL != "" {
				cfg.BaseURL = o.BaseURL
			}
			if o.Model != "" {
				cfg.Model = o.Model
			}
			if o.APIKey != "" {
				cfg.APIKey = o.APIKey
			}
			if o.SystemTemplate != "" {
				cfg.SystemTemplate = o.SystemTemplate
			}
			if o.Headers != nil {
				cfg.Headers = o.Headers
			}
		}
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		}
		return adapter.NewOpenAIAdapter(cfg)

	default:
		return nil, fmt.Errorf("scenario: unknown adapter %q", s.Adapter.Name)
	}
}

// mergeGeneric overlays non-zero fields of src onto dst, leaving demo-compatible
// defaults where the scenario is silent.
func mergeGeneric(dst *adapter.GenericConfig, src adapter.GenericConfig) {
	if src.Reset.Path != "" || src.Reset.Method != "" {
		dst.Reset = src.Reset
	}
	if src.Seed.Path != "" || src.Seed.Method != "" {
		dst.Seed = src.Seed
	}
	if src.Chat.Path != "" || src.Chat.Method != "" {
		dst.Chat = src.Chat
	}
	if src.TenantField != "" {
		dst.TenantField = src.TenantField
	}
	if src.QueryField != "" {
		dst.QueryField = src.QueryField
	}
	if src.TopKField != "" {
		dst.TopKField = src.TopKField
	}
	if src.DocIDField != "" {
		dst.DocIDField = src.DocIDField
	}
	if src.TextField != "" {
		dst.TextField = src.TextField
	}
	if src.AnswerPath != "" {
		dst.AnswerPath = src.AnswerPath
	}
	if src.CitationsPath != "" {
		dst.CitationsPath = src.CitationsPath
	}
	if src.CitationDocIDKey != "" {
		dst.CitationDocIDKey = src.CitationDocIDKey
	}
	if src.CitationTenantIDKey != "" {
		dst.CitationTenantIDKey = src.CitationTenantIDKey
	}
	if src.TenantHeader != "" {
		dst.TenantHeader = src.TenantHeader
	}
	if src.Headers != nil {
		dst.Headers = src.Headers
	}
}
