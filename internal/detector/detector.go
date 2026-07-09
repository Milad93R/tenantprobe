// Package detector inspects a single attacker->victim probe result for
// cross-tenant leakage. Detectors are read-only and independent, so the
// orchestrator can run many probes concurrently and merge their findings.
package detector

import (
	"fmt"
	"sort"
	"strings"

	"github.com/milad93r/tenantprobe/internal/adapter"
	"github.com/milad93r/tenantprobe/internal/canary"
)

// Leak is a single cross-tenant isolation failure.
type Leak struct {
	Type     string `json:"type"`
	Attacker string `json:"attacker"`
	Victim   string `json:"victim"`
	Attack   string `json:"attack"`
	Evidence string `json:"evidence"`
}

// Probe is the read-only view a detector inspects: who attacked whom, with what
// query, and what the target returned.
//
// AttackerDocs and VictimDocs carry the *seeded* document text for each side so a
// content detector (e.g. the PII/secret regex) can attribute a matched string to
// a tenant and stay strictly cross-tenant: a match fires only when it traces to
// the victim's seeded data and not the attacker's own. They may be empty (the
// canary/citation detectors ignore them).
type Probe struct {
	Attacker     canary.Tenant
	Victim       canary.Tenant
	Attack       string
	Answer       string
	Citations    []adapter.Citation
	AttackerDocs []string
	VictimDocs   []string
}

// Detector examines one probe and returns any leaks it found.
type Detector interface {
	Name() string
	Detect(p Probe) []Leak
}

// Default returns the core detector set for cross-tenant isolation testing.
func Default() []Detector {
	return []Detector{CanaryInAnswer{}, CrossTenantCitation{}}
}

// registry maps a detector's Name() to a constructor. It is the single source of
// truth for which assertions a scenario file (or -detectors flag) may enable by
// name. The regex detector registers under its built-in-pattern names; extra
// user-supplied patterns are layered on separately via NewRegexDetector.
var registry = map[string]func() Detector{
	"canary_in_answer":       func() Detector { return CanaryInAnswer{} },
	"canary_in_answer_fuzzy": func() Detector { return NewCanaryFuzzy(DefaultFuzzyMinLen) },
	"cross_tenant_citation":  func() Detector { return CrossTenantCitation{} },
	"pii_leak":               func() Detector { return NewRegexDetector(nil) },
	"secret_leak":            func() Detector { return NewRegexDetector(nil) },
}

// Available returns the sorted list of assertion names a scenario may request.
func Available() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ByName builds the detector registered under name, or reports that it is
// unknown along with the set of names that are available.
func ByName(name string) (Detector, error) {
	if ctor, ok := registry[name]; ok {
		return ctor(), nil
	}
	return nil, fmt.Errorf("unknown detector %q (available: %s)", name, strings.Join(Available(), ", "))
}

// Select builds the detectors named in names, deduplicating by Detector.Name() so
// aliases (e.g. pii_leak / secret_leak, which resolve to the same regex detector)
// do not run twice. userPatterns are appended to the PII/secret regex detector
// when it is selected. Returns an error naming the first unknown detector.
func Select(names []string, userPatterns []string) ([]Detector, error) {
	dets := make([]Detector, 0, len(names))
	seen := make(map[string]bool)
	for _, name := range names {
		d, err := ByName(name)
		if err != nil {
			return nil, err
		}
		// The regex detector may carry user patterns; rebuild it with them.
		if d.Name() == regexDetectorName {
			d = NewRegexDetector(userPatterns)
		}
		if seen[d.Name()] {
			continue
		}
		seen[d.Name()] = true
		dets = append(dets, d)
	}
	return dets, nil
}
