package probe

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/milad93r/tenantprobe/internal/adapter"
	"github.com/milad93r/tenantprobe/internal/canary"
	"github.com/milad93r/tenantprobe/internal/detector"
)

// influenceMinNovelTokens is how many distinct VICTIM-ONLY content tokens must
// appear in the attacker's answer before we flag content influence. This is a
// deterministic provenance heuristic, not statistical membership inference or
// an embedding/LLM semantic judge.
const influenceMinNovelTokens = 2

// tokenRe extracts lowercase alphanumeric word tokens for content comparison.
var tokenRe = regexp.MustCompile(`[a-z0-9]+`)

// stopwords are generic tokens that carry no tenant-specific signal; excluding
// them stops boilerplate ("the confidential internal secret") from being scored
// as leaked victim content.
var stopwords = map[string]bool{
	"the": true, "a": true, "an": true, "of": true, "to": true, "and": true,
	"is": true, "in": true, "on": true, "for": true, "do": true, "not": true,
	"i": true, "have": true, "information": true, "that": true, "this": true,
	"confidential": true, "internal": true, "secret": true, "leak": true,
	"tenant": true, "document": true, "documents": true, "no": true, "any": true,
	"it": true, "as": true, "with": true, "your": true, "you": true,
}

// contentInfluence runs the victim-content provenance sweep.
//
// Rationale: string-matching detectors only catch a victim canary that appears
// *verbatim* (or fuzzily) in the answer. A retrieval-isolation bug can leak
// without exposing the literal high-entropy canary — for example, when a RAG
// answer summarizes the retrieved chunk but preserves its distinctive terms.
//
// The sweep asks a victim-topic query as each other configured tenant. If an
// attacker's answer contains distinctive tokens owned by the victim, absent
// from the query itself, and absent from the attacker's own seeded documents,
// the response has crossed the tenant boundary.
//
// It reuses the adapter/detector abstractions and returns Leaks of type
// "content_influence" so the orchestrator can merge and dedup them alongside
// the string-matching findings.
func contentInfluence(a adapter.Adapter, tenants []canary.Tenant, docsByTenant map[string][]string, topK int) ([]detector.Leak, int, error) {
	var leaks []detector.Leak
	probes := 0

	for _, victim := range tenants {
		vDocs := docsByTenant[victim.ID]
		if len(vDocs) == 0 {
			continue
		}
		// A victim-topic query built from the victim's own content. If isolation
		// holds, only the victim retrieves it; anyone else must fall back to a
		// "no information" answer regardless of how well the query matches.
		query := influenceQuery(victim.ID, vDocs)

		// Also treat the query's own tokens as boilerplate: a target that merely
		// parrots the question back must not be scored as leaking.
		queryTokens := contentTokens(query)

		for _, attacker := range tenants {
			if attacker.ID == victim.ID {
				continue
			}
			ans, _, err := a.Chat(attacker.ID, query, topK)
			if err != nil {
				return nil, probes, fmt.Errorf("content-influence attacker chat: %w", err)
			}
			probes++

			ansTokens := contentTokens(ans)
			// Attacker's own seeded vocabulary is legitimately theirs; exclude it
			// so we never flag a tenant for seeing its own data.
			ownTokens := docTokens(docsByTenant[attacker.ID])

			// victimContent = tokens the VICTIM owns (in its seeded docs) that the
			// attacker does NOT own. Ground-truth seeded-document ownership decides
			// attribution.
			victimContent := diffTokens(docTokens(vDocs), ownTokens)

			var novel []string
			for _, tok := range victimContent {
				// Fire on victim-owned tokens that surfaced in the attacker's
				// answer and are not mere query echo. Boilerplate is excluded
				// structurally: victimContent holds only tokens the victim owns and
				// the attacker does not; queryTokens strips question echo.
				if ansTokens[tok] && !queryTokens[tok] {
					novel = append(novel, tok)
				}
			}
			if len(novel) >= influenceMinNovelTokens {
				leaks = append(leaks, detector.Leak{
					Type:     "content_influence",
					Attacker: attacker.ID,
					Victim:   victim.ID,
					Attack:   query,
					Evidence: fmt.Sprintf("attacker answer carries %d victim-only content token(s): %s", len(novel), strings.Join(novel, ", ")),
				})
			}
		}
	}
	return leaks, probes, nil
}

// influenceQuery builds a victim-topic query. It uses the victim's most
// distinctive seeded tokens so that a correctly isolated target retrieves the
// victim's doc ONLY for the victim, and everyone else gets the fallback answer.
func influenceQuery(victimID string, docs []string) string {
	toks := distinctiveTokens(docs)
	// Keep at least influenceMinNovelTokens out of the query whenever possible.
	// Those held-out terms are the evidence; putting every source term into the
	// question would make a later echo indistinguishable from a leak.
	if len(toks) == 0 {
		return fmt.Sprintf("What confidential information belongs to %s?", victimID)
	}
	n := len(toks) - influenceMinNovelTokens
	if n < 1 {
		n = 1
	}
	if n > 2 {
		n = 2
	}
	return fmt.Sprintf("What confidential information mentions %s?", strings.Join(toks[:n], " "))
}

// distinctiveTokens returns up to a handful of the victim's non-boilerplate
// content tokens, which make the strongest retrieval signal for the victim doc.
func distinctiveTokens(docs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range docs {
		for _, t := range tokenRe.FindAllString(strings.ToLower(d), -1) {
			if stopwords[t] || seen[t] || len(t) < 4 {
				continue
			}
			seen[t] = true
			out = append(out, t)
			if len(out) >= 8 {
				return out
			}
		}
	}
	return out
}

// contentTokens returns the set of non-stopword tokens in s.
func contentTokens(s string) map[string]bool {
	set := map[string]bool{}
	for _, t := range tokenRe.FindAllString(strings.ToLower(s), -1) {
		if !stopwords[t] {
			set[t] = true
		}
	}
	return set
}

// docTokens returns the set of non-stopword tokens across all docs.
func docTokens(docs []string) map[string]bool {
	set := map[string]bool{}
	for _, d := range docs {
		for t := range contentTokens(d) {
			set[t] = true
		}
	}
	return set
}

// diffTokens returns the members of have that are absent from without in stable
// lexical order so evidence remains reproducible across runs.
func diffTokens(have, without map[string]bool) []string {
	var out []string
	for t := range have {
		if !without[t] {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}
