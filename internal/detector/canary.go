package detector

import "strings"

// CanaryInAnswer flags when the victim tenant's canary code appears in the answer
// returned to the attacker — a direct cross-tenant secret leak.
type CanaryInAnswer struct{}

// Name implements Detector.
func (CanaryInAnswer) Name() string { return "canary_in_answer" }

// Detect implements Detector.
func (CanaryInAnswer) Detect(p Probe) []Leak {
	if p.Victim.Code != "" && strings.Contains(p.Answer, p.Victim.Code) {
		return []Leak{{
			Type:     "canary_in_answer",
			Attacker: p.Attacker.ID,
			Victim:   p.Victim.ID,
			Attack:   p.Attack,
			Evidence: p.Victim.Code,
		}}
	}
	return nil
}
