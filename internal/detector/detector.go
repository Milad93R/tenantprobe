// Package detector inspects a single attacker->victim probe result for
// cross-tenant leakage. Detectors are read-only and independent, so the
// orchestrator can run many probes concurrently and merge their findings.
package detector

import (
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
