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
type Probe struct {
	Attacker  canary.Tenant
	Victim    canary.Tenant
	Attack    string
	Answer    string
	Citations []adapter.Citation
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
// truth for which assertions a scenario file may enable by name.
var registry = map[string]func() Detector{
	"canary_in_answer":      func() Detector { return CanaryInAnswer{} },
	"cross_tenant_citation": func() Detector { return CrossTenantCitation{} },
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
