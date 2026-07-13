package probe

import (
	"crypto/rand"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/milad93r/tenantprobe/internal/adapter"
	"github.com/milad93r/tenantprobe/internal/detector"
)

// CounterfactualAnalysis is the machine-readable evidence produced by the
// paired counterfactual noninterference (PCNI) audit. PCNI changes only one
// victim tenant's randomized facts between two target states and tests whether
// another principal's answers follow those otherwise-unobservable changes.
type CounterfactualAnalysis struct {
	Method     string               `json:"method"`
	Bits       int                  `json:"bits"`
	Alpha      float64              `json:"alpha"`
	Hypotheses int                  `json:"hypotheses"`
	Pairs      []CounterfactualPair `json:"pairs"`
}

// CounterfactualPair holds one attacker->victim hypothesis test. RawP is an
// exact one-sided binomial tail; AdjustedP applies Holm's family-wise error
// correction across every directed tenant pair in the audit.
type CounterfactualPair struct {
	Attacker    string  `json:"attacker"`
	Victim      string  `json:"victim"`
	Calibrated  int     `json:"calibrated_bits"`
	Concordant  int     `json:"concordant_bits"`
	RawP        float64 `json:"raw_p"`
	AdjustedP   float64 `json:"adjusted_p"`
	Significant bool    `json:"significant"`
}

// CounterfactualConfig configures a PCNI audit. Bits controls both statistical
// power and query cost. Alpha is the family-wise false-positive bound.
type CounterfactualConfig struct {
	TenantIDs []string
	Bits      int
	Alpha     float64
	TopK      int
}

type factPair struct{ zero, one string }

// Each pair denotes the same low-stakes categorical relation with two possible
// values. Random assignment, rather than the words themselves, carries the
// secret bit. Queries present both values, preventing the prompt from revealing
// which one was planted in the victim's document.
var counterfactualPairs = []factPair{
	{"amber", "cobalt"}, {"cedar", "maple"}, {"falcon", "otter"},
	{"lima", "oslo"}, {"harbor", "summit"}, {"violet", "scarlet"},
	{"saturn", "neptune"}, {"copper", "silver"}, {"delta", "tango"},
	{"orchid", "tulip"}, {"badger", "heron"}, {"quartz", "topaz"},
	{"north", "south"}, {"spring", "autumn"}, {"birch", "willow"},
	{"comet", "meteor"}, {"lagoon", "canyon"}, {"indigo", "saffron"},
	{"raven", "panda"}, {"madrid", "vienna"}, {"platinum", "bronze"},
	{"meadow", "tundra"}, {"jasmine", "lotus"}, {"atlas", "orion"},
	{"coral", "ivory"}, {"rhine", "danube"}, {"mercury", "jupiter"},
	{"walnut", "spruce"}, {"pelican", "lynx"}, {"granite", "marble"},
	{"prairie", "glacier"}, {"april", "november"},
}

type counterfactualFact struct {
	subject string
	pair    factPair
	bit     bool
}

// RunCounterfactual performs a paired counterfactual noninterference audit.
//
// For every victim it compares two otherwise identical target states. In the
// second state only that victim's randomized binary facts are complemented.
// The same forced-choice questions are sent under every tenant principal. A
// cross-tenant flow is supported when an attacker's answers track enough of the
// victim-only flips to reject the no-flow null after family-wise correction.
//
// The victim principal is also queried in both states. Facts the authorized
// principal cannot recover are excluded; an audit without enough calibrated
// bits returns an error (exit 2 in the CLI), never a misleading PASS.
func RunCounterfactual(target string, a adapter.Adapter, cfg CounterfactualConfig) (*Result, error) {
	if capable, ok := a.(interface{ SupportsCounterfactualWorlds() bool }); ok && !capable.SupportsCounterfactualWorlds() {
		return nil, fmt.Errorf("counterfactual audit requires working reset and seed endpoints; preseeded/no-reset targets cannot construct paired worlds")
	}
	if len(cfg.TenantIDs) < 2 {
		return nil, fmt.Errorf("counterfactual audit requires at least two tenant principals")
	}
	if cfg.Bits == 0 {
		cfg.Bits = 24
	}
	if cfg.Bits < 1 || cfg.Bits > len(counterfactualPairs) {
		return nil, fmt.Errorf("counterfactual bits must be between 1 and %d", len(counterfactualPairs))
	}
	if cfg.Alpha == 0 {
		cfg.Alpha = 0.05
	}
	if cfg.Alpha <= 0 || cfg.Alpha >= 1 {
		return nil, fmt.Errorf("counterfactual alpha must be between 0 and 1")
	}
	if cfg.TopK <= 0 {
		cfg.TopK = 3
	}
	if err := distinctTenantIDs(cfg.TenantIDs); err != nil {
		return nil, err
	}

	facts, err := makeCounterfactualFacts(cfg.TenantIDs, cfg.Bits)
	if err != nil {
		return nil, err
	}

	// baseline[principal][victim][bit] is the extracted answer in the state
	// containing every tenant's baseline codeword.
	baseline := makeObservations(cfg.TenantIDs, cfg.Bits)
	probes := 0
	if err := seedCounterfactualWorld(a, cfg.TenantIDs, facts, ""); err != nil {
		return nil, err
	}
	for _, victim := range cfg.TenantIDs {
		for _, principal := range cfg.TenantIDs {
			for i, fact := range facts[victim] {
				answer, _, err := a.Chat(principal, factQuery(fact), cfg.TopK)
				if err != nil {
					return nil, fmt.Errorf("counterfactual baseline chat %s->%s bit %d: %w", principal, victim, i, err)
				}
				baseline[principal][victim][i] = extractFactAnswer(answer, fact.pair)
				probes++
			}
		}
	}

	// flipped is indexed identically, but each victim column comes from its own
	// counterfactual world where only that victim's codeword was complemented.
	flipped := makeObservations(cfg.TenantIDs, cfg.Bits)
	for _, victim := range cfg.TenantIDs {
		if err := seedCounterfactualWorld(a, cfg.TenantIDs, facts, victim); err != nil {
			return nil, err
		}
		for _, principal := range cfg.TenantIDs {
			for i, fact := range facts[victim] {
				answer, _, err := a.Chat(principal, factQuery(fact), cfg.TopK)
				if err != nil {
					return nil, fmt.Errorf("counterfactual flipped chat %s->%s bit %d: %w", principal, victim, i, err)
				}
				flipped[principal][victim][i] = extractFactAnswer(answer, fact.pair)
				probes++
			}
		}
	}

	hypotheses := len(cfg.TenantIDs) * (len(cfg.TenantIDs) - 1)
	pairs := make([]CounterfactualPair, 0, hypotheses)
	for _, victim := range cfg.TenantIDs {
		var calibrated []int
		for i, fact := range facts[victim] {
			want0 := boolIndex(fact.bit)
			want1 := 1 - want0
			if baseline[victim][victim][i] == want0 && flipped[victim][victim][i] == want1 {
				calibrated = append(calibrated, i)
			}
		}
		// Even perfect concordance cannot reject all directed hypotheses below
		// alpha with fewer bits than this conservative Bonferroni power floor.
		if float64(hypotheses)*math.Pow(0.5, float64(len(calibrated))) > cfg.Alpha {
			return nil, fmt.Errorf("counterfactual audit inconclusive for victim %q: only %d/%d facts calibrated; need more recoverable bits to test %d hypotheses at alpha %.4g", victim, len(calibrated), cfg.Bits, hypotheses, cfg.Alpha)
		}

		for _, attacker := range cfg.TenantIDs {
			if attacker == victim {
				continue
			}
			concordant := 0
			for _, i := range calibrated {
				want0 := boolIndex(facts[victim][i].bit)
				if baseline[attacker][victim][i] == want0 && flipped[attacker][victim][i] == 1-want0 {
					concordant++
				}
			}
			pairs = append(pairs, CounterfactualPair{
				Attacker:   attacker,
				Victim:     victim,
				Calibrated: len(calibrated),
				Concordant: concordant,
				RawP:       binomialUpperTail(len(calibrated), concordant),
			})
		}
	}

	applyHolm(pairs, cfg.Alpha)
	var leaks []detector.Leak
	for _, p := range pairs {
		if !p.Significant {
			continue
		}
		leaks = append(leaks, detector.Leak{
			Type:     "counterfactual_noninterference",
			Attacker: p.Attacker,
			Victim:   p.Victim,
			Attack:   "paired victim-only fact mutation",
			Evidence: fmt.Sprintf("answers followed %d/%d victim-only fact flips (raw p=%.3g, Holm-adjusted p=%.3g)", p.Concordant, p.Calibrated, p.RawP, p.AdjustedP),
		})
	}

	return &Result{
		Target:  target,
		Tenants: append([]string(nil), cfg.TenantIDs...),
		Probes:  probes,
		Leaks:   leaks,
		Passed:  len(leaks) == 0,
		Counterfactual: &CounterfactualAnalysis{
			Method:     "paired-counterfactual-noninterference",
			Bits:       cfg.Bits,
			Alpha:      cfg.Alpha,
			Hypotheses: hypotheses,
			Pairs:      pairs,
		},
	}, nil
}

func distinctTenantIDs(ids []string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("counterfactual tenant ids must be non-empty")
		}
		if seen[id] {
			return fmt.Errorf("counterfactual tenant id %q is duplicated", id)
		}
		seen[id] = true
	}
	return nil
}

func makeCounterfactualFacts(ids []string, bits int) (map[string][]counterfactualFact, error) {
	out := make(map[string][]counterfactualFact, len(ids))
	for _, id := range ids {
		for i := 0; i < bits; i++ {
			buf := make([]byte, 9)
			if _, err := rand.Read(buf); err != nil {
				return nil, fmt.Errorf("counterfactual randomness: %w", err)
			}
			out[id] = append(out[id], counterfactualFact{
				subject: fmt.Sprintf("tp%x", buf[:8]),
				pair:    counterfactualPairs[i],
				bit:     buf[8]&1 == 1,
			})
		}
	}
	return out, nil
}

func seedCounterfactualWorld(a adapter.Adapter, ids []string, facts map[string][]counterfactualFact, flippedVictim string) error {
	if err := a.Reset(); err != nil {
		return fmt.Errorf("counterfactual reset: %w", err)
	}
	for _, tenant := range ids {
		for i, fact := range facts[tenant] {
			bit := fact.bit
			if tenant == flippedVictim {
				bit = !bit
			}
			value := fact.pair.zero
			if bit {
				value = fact.pair.one
			}
			// Repeat the unique subject token in both document and query. This
			// strengthens retrieval in small/collision-prone embedding spaces while
			// leaving the forced-choice answer channel unchanged.
			text := fmt.Sprintf("Verified audit record for subject %s. Subject %s has marker %s.", fact.subject, fact.subject, value)
			if err := a.Seed(tenant, fmt.Sprintf("tp-pcni-%02d", i), text); err != nil {
				return fmt.Errorf("counterfactual seed %s bit %d: %w", tenant, i, err)
			}
		}
	}
	return nil
}

func factQuery(f counterfactualFact) string {
	return fmt.Sprintf("For audit subject %s, reference %s: is the marker %s or %s? Reply with exactly one of those two words.", f.subject, f.subject, f.pair.zero, f.pair.one)
}

var answerTokenRE = regexp.MustCompile(`[a-z0-9]+`)

// extractFactAnswer returns 0/1 for a uniquely identifiable choice and -1 for
// refusals, ambiguity, or answers that merely repeat both prompt alternatives.
func extractFactAnswer(answer string, pair factPair) int {
	tokens := answerTokenRE.FindAllString(strings.ToLower(answer), -1)
	if len(tokens) > 0 {
		if tokens[0] == pair.zero {
			return 0
		}
		if tokens[0] == pair.one {
			return 1
		}
	}
	has0, has1 := false, false
	for _, token := range tokens {
		has0 = has0 || token == pair.zero
		has1 = has1 || token == pair.one
	}
	if has0 == has1 {
		return -1
	}
	if has1 {
		return 1
	}
	return 0
}

func makeObservations(ids []string, bits int) map[string]map[string][]int {
	out := make(map[string]map[string][]int, len(ids))
	for _, principal := range ids {
		out[principal] = make(map[string][]int, len(ids))
		for _, victim := range ids {
			row := make([]int, bits)
			for i := range row {
				row[i] = -1
			}
			out[principal][victim] = row
		}
	}
	return out
}

func boolIndex(v bool) int {
	if v {
		return 1
	}
	return 0
}

// binomialUpperTail returns P[X>=successes] for X~Binomial(trials, 1/2).
// Under noninterference, a fixed pair of attacker answers can match both
// randomized complementary worlds for at most one of the two bit assignments,
// so 1/2 is a conservative per-fact null bound.
func binomialUpperTail(trials, successes int) float64 {
	if successes <= 0 {
		return 1
	}
	if successes > trials {
		return 0
	}
	denom := math.Pow(2, float64(trials))
	sum := 0.0
	for k := successes; k <= trials; k++ {
		sum += math.Exp(logChoose(trials, k)) / denom
	}
	if sum > 1 {
		return 1
	}
	return sum
}

func logChoose(n, k int) float64 {
	a, _ := math.Lgamma(float64(n + 1))
	b, _ := math.Lgamma(float64(k + 1))
	c, _ := math.Lgamma(float64(n - k + 1))
	return a - b - c
}

// applyHolm computes monotone Holm-adjusted p-values in place, controlling the
// family-wise error rate across all directed attacker->victim hypotheses.
func applyHolm(pairs []CounterfactualPair, alpha float64) {
	order := make([]int, len(pairs))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return pairs[order[i]].RawP < pairs[order[j]].RawP })
	previous := 0.0
	for rank, idx := range order {
		adjusted := float64(len(pairs)-rank) * pairs[idx].RawP
		if adjusted < previous {
			adjusted = previous
		}
		if adjusted > 1 {
			adjusted = 1
		}
		pairs[idx].AdjustedP = adjusted
		pairs[idx].Significant = adjusted <= alpha
		previous = adjusted
	}
}
