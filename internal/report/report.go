// Package report renders a probe.Result in one of three CI-friendly formats:
// a human console summary, indented JSON, or JUnit XML. Format selection and
// output destination are decoupled from the scan so the orchestrator stays
// oblivious to presentation. No third-party dependencies: JSON via
// encoding/json, JUnit via encoding/xml.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/milad93r/tenantprobe/internal/probe"
)

// Format is one of the supported output formats.
type Format string

const (
	Console Format = "console"
	JSON    Format = "json"
	JUnit   Format = "junit"
)

// ParseFormat validates a -report flag value.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case Console, JSON, JUnit:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown report format %q (want console|json|junit)", s)
	}
}

// Render writes res to w in the requested format.
func Render(w io.Writer, res *probe.Result, f Format) error {
	switch f {
	case Console:
		return renderConsole(w, res)
	case JSON:
		return renderJSON(w, res)
	case JUnit:
		return renderJUnit(w, res)
	default:
		return fmt.Errorf("unknown report format %q", f)
	}
}

// renderJSON writes the indented Result JSON with stable field names.
func renderJSON(w io.Writer, res *probe.Result) error {
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}

// renderConsole writes a plain human summary: target, tenant/probe counts, one
// line per leak (attacker->victim [type] evidence), and a final PASS/FAIL line.
func renderConsole(w io.Writer, res *probe.Result) error {
	if _, err := fmt.Fprintf(w, "TenantProbe scan\n"); err != nil {
		return err
	}
	fmt.Fprintf(w, "  target:  %s\n", res.Target)
	fmt.Fprintf(w, "  tenants: %d\n", len(res.Tenants))
	fmt.Fprintf(w, "  probes:  %d\n", res.Probes)
	if len(res.Leaks) == 0 {
		fmt.Fprintf(w, "  leaks:   0\n")
		fmt.Fprintf(w, "PASS: no cross-tenant leaks across %d probes\n", res.Probes)
		return nil
	}
	fmt.Fprintf(w, "  leaks:   %d\n", len(res.Leaks))
	for _, l := range res.Leaks {
		fmt.Fprintf(w, "  - %s -> %s [%s] %s\n", l.Attacker, l.Victim, l.Type, truncate(l.Evidence, 120))
	}
	_, err := fmt.Fprintf(w, "FAIL: %d cross-tenant leak(s) detected across %d probes\n", len(res.Leaks), res.Probes)
	return err
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
