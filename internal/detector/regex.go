package detector

import (
	"regexp"
	"strings"
)

// regexDetectorName is the canonical Name() of the PII/secret regex detector.
// The scenario/CLI aliases "pii_leak" and "secret_leak" both resolve to it; they
// are the *leak types* it emits, not distinct detectors.
const regexDetectorName = "pii_secret_regex"

// pattern pairs a compiled regex with the leak type it emits and whether a match
// must additionally pass a Luhn check (credit-card shapes).
type pattern struct {
	name string // for reference/debugging
	typ  string // "pii_leak" | "secret_leak"
	re   *regexp.Regexp
	luhn bool
}

// builtinPatterns are the always-on PII/secret shapes. They are intentionally
// conservative: TenantProbe only cares that *another tenant's* seeded value
// surfaced, so the cross-tenant attribution in Detect — not pattern breadth — is
// what keeps this in-lane and low-noise.
var builtinPatterns = []pattern{
	{
		name: "email",
		typ:  "pii_leak",
		re:   regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
	},
	{
		name: "credit_card",
		typ:  "pii_leak",
		re:   regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`),
		luhn: true,
	},
	{
		// AWS-style access key id.
		name: "aws_access_key",
		typ:  "secret_leak",
		re:   regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		// Common bearer/API-token shapes: sk-..., ghp_..., xoxb-..., long hex/base62.
		name: "api_token",
		typ:  "secret_leak",
		re:   regexp.MustCompile(`\b(?:sk|pk|rk)-[A-Za-z0-9]{16,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	},
}

// RegexDetector flags PII/secret-shaped strings in an answer, but only when the
// matched text traces to another tenant's seeded document — never the attacker's
// own. This keeps it strictly a cross-tenant isolation check, not a generic PII
// scanner.
type RegexDetector struct {
	patterns []pattern
}

// NewRegexDetector builds the detector with the built-in PII/secret patterns plus
// any user-supplied patterns (from a scenario). User patterns emit "secret_leak"
// and are skipped if they fail to compile.
func NewRegexDetector(userPatterns []string) RegexDetector {
	pats := make([]pattern, 0, len(builtinPatterns)+len(userPatterns))
	pats = append(pats, builtinPatterns...)
	for _, up := range userPatterns {
		up = strings.TrimSpace(up)
		if up == "" {
			continue
		}
		re, err := regexp.Compile(up)
		if err != nil {
			continue // ignore invalid user patterns rather than fail the whole scan
		}
		pats = append(pats, pattern{name: "user", typ: "secret_leak", re: re})
	}
	return RegexDetector{patterns: pats}
}

// Name implements Detector.
func (RegexDetector) Name() string { return regexDetectorName }

// Detect implements Detector. For every PII/secret match in the answer it fires
// only if the matched string appears in one of the victim's seeded documents
// (cross-tenant provenance) AND does not appear in any of the attacker's own
// documents (which would make it the attacker's legitimate data, not a leak).
func (d RegexDetector) Detect(p Probe) []Leak {
	if p.Answer == "" || len(p.VictimDocs) == 0 {
		return nil
	}
	var leaks []Leak
	seen := make(map[string]bool)
	for _, pat := range d.patterns {
		for _, m := range pat.re.FindAllString(p.Answer, -1) {
			if pat.luhn && !luhnValid(m) {
				continue
			}
			if !containsAny(p.VictimDocs, m) {
				continue // not the victim's data — outside our lane
			}
			if containsAny(p.AttackerDocs, m) {
				continue // also the attacker's own value: not a cross-tenant leak
			}
			key := pat.typ + "\x00" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			leaks = append(leaks, Leak{
				Type:     pat.typ,
				Attacker: p.Attacker.ID,
				Victim:   p.Victim.ID,
				Attack:   p.Attack,
				Evidence: m,
			})
		}
	}
	return leaks
}

// containsAny reports whether needle appears in any of the docs.
func containsAny(docs []string, needle string) bool {
	for _, doc := range docs {
		if strings.Contains(doc, needle) {
			return true
		}
	}
	return false
}

// luhnValid reports whether the digits in s pass the Luhn checksum (used to keep
// only plausible credit-card numbers, cutting noise from arbitrary digit runs).
func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
