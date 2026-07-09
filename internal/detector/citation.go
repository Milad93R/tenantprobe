package detector

// CrossTenantCitation flags any citation whose owning tenant differs from the
// attacker — the target retrieved another tenant's document.
type CrossTenantCitation struct{}

// Name implements Detector.
func (CrossTenantCitation) Name() string { return "cross_tenant_citation" }

// Detect implements Detector.
func (CrossTenantCitation) Detect(p Probe) []Leak {
	var leaks []Leak
	for _, cit := range p.Citations {
		if cit.TenantID != "" && cit.TenantID != p.Attacker.ID {
			leaks = append(leaks, Leak{
				Type:     "cross_tenant_citation",
				Attacker: p.Attacker.ID,
				Victim:   cit.TenantID,
				Attack:   p.Attack,
				Evidence: cit.DocID,
			})
		}
	}
	return leaks
}
