package report

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/milad93r/tenantprobe/internal/probe"
)

type htmlReport struct {
	Generated       string
	Target          string
	Passed          bool
	Verdict         string
	VerdictClass    string
	VerdictSummary  string
	TenantCount     int
	Probes          int
	FindingCount    int
	AffectedEdges   int
	Tenants         []string
	MatrixTitle     string
	MatrixHelp      string
	Matrix          []htmlMatrixRow
	Findings        []htmlFinding
	Remediations    []htmlRemediation
	Counterfactual  *htmlCounterfactual
	EncodedScanJSON string
}

type htmlMatrixRow struct {
	Attacker string
	Cells    []htmlMatrixCell
}

type htmlMatrixCell struct {
	Victim   string
	Class    string
	Label    string
	Detail   string
	Diagonal bool
}

type htmlFinding struct {
	Number      int
	Type        string
	TypeLabel   string
	Attacker    string
	Victim      string
	Attack      string
	Evidence    string
	Remediation string
}

type htmlRemediation struct {
	Title string
	Text  string
}

type htmlCounterfactual struct {
	Method     string
	Bits       int
	Alpha      string
	Hypotheses int
	Pairs      []htmlCounterfactualPair
}

type htmlCounterfactualPair struct {
	Attacker   string
	Victim     string
	Flips      string
	RawP       string
	AdjustedP  string
	Verdict    string
	Class      string
	Percentage float64
}

// renderHTML produces one portable report containing all CSS, JavaScript, and
// machine-readable scan data. It has no network dependencies and can be opened
// directly from disk or uploaded as a CI artifact.
func renderHTML(w io.Writer, res *probe.Result) error {
	view, err := buildHTMLReport(res)
	if err != nil {
		return err
	}
	if err := htmlReportTemplate.Execute(w, view); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	return nil
}

func buildHTMLReport(res *probe.Result) (htmlReport, error) {
	if res == nil {
		return htmlReport{}, fmt.Errorf("render html: nil result")
	}
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return htmlReport{}, fmt.Errorf("marshal embedded scan data: %w", err)
	}

	view := htmlReport{
		Generated:       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Target:          res.Target,
		Passed:          res.Passed,
		TenantCount:     len(res.Tenants),
		Probes:          res.Probes,
		FindingCount:    len(res.Leaks),
		Tenants:         append([]string(nil), res.Tenants...),
		EncodedScanJSON: base64.StdEncoding.EncodeToString(raw),
	}
	if res.Passed {
		view.Verdict = "PASS"
		view.VerdictClass = "pass"
		if res.Counterfactual != nil {
			view.VerdictSummary = "No statistically significant cross-tenant influence was observed in the tested paths."
		} else {
			view.VerdictSummary = "No cross-tenant leakage was observed in the tested paths."
		}
	} else {
		view.Verdict = "FAIL"
		view.VerdictClass = "fail"
		view.VerdictSummary = fmt.Sprintf("%d cross-tenant isolation finding(s) require attention.", len(res.Leaks))
	}

	view.Findings = make([]htmlFinding, 0, len(res.Leaks))
	remediations := map[string]htmlRemediation{}
	edges := map[string]bool{}
	for i, leak := range res.Leaks {
		remediation := remediationFor(leak.Type)
		view.Findings = append(view.Findings, htmlFinding{
			Number:      i + 1,
			Type:        leak.Type,
			TypeLabel:   humanizeIdentifier(leak.Type),
			Attacker:    leak.Attacker,
			Victim:      leak.Victim,
			Attack:      leak.Attack,
			Evidence:    leak.Evidence,
			Remediation: remediation.Text,
		})
		remediations[remediation.Title] = remediation
		edges[leak.Attacker+"\x00"+leak.Victim] = true
	}
	view.AffectedEdges = len(edges)
	for _, remediation := range remediations {
		view.Remediations = append(view.Remediations, remediation)
	}
	sort.Slice(view.Remediations, func(i, j int) bool {
		return view.Remediations[i].Title < view.Remediations[j].Title
	})

	view.Matrix = buildHTMLMatrix(res)
	if res.Counterfactual == nil {
		view.MatrixTitle = "Observed leak matrix"
		view.MatrixHelp = "Rows are authenticated attackers; columns are victim tenants. Cells show the number of unique findings on each directed boundary."
		return view, nil
	}

	cf := res.Counterfactual
	view.MatrixTitle = "Counterfactual influence matrix"
	view.MatrixHelp = "Rows are authenticated attackers; columns are victim tenants. Cells show how many calibrated victim-only fact flips the attacker followed."
	view.Counterfactual = &htmlCounterfactual{
		Method:     cf.Method,
		Bits:       cf.Bits,
		Alpha:      formatPValue(cf.Alpha),
		Hypotheses: cf.Hypotheses,
	}
	for _, pair := range cf.Pairs {
		percentage := 0.0
		if pair.Calibrated > 0 {
			percentage = 100 * float64(pair.Concordant) / float64(pair.Calibrated)
		}
		verdict, class := "No significant flow", "pass"
		if pair.Significant {
			verdict, class = "Significant flow", "fail"
		}
		view.Counterfactual.Pairs = append(view.Counterfactual.Pairs, htmlCounterfactualPair{
			Attacker:   pair.Attacker,
			Victim:     pair.Victim,
			Flips:      fmt.Sprintf("%d / %d", pair.Concordant, pair.Calibrated),
			RawP:       formatPValue(pair.RawP),
			AdjustedP:  formatPValue(pair.AdjustedP),
			Verdict:    verdict,
			Class:      class,
			Percentage: percentage,
		})
	}
	return view, nil
}

func buildHTMLMatrix(res *probe.Result) []htmlMatrixRow {
	leakCounts := map[string]int{}
	for _, leak := range res.Leaks {
		leakCounts[leak.Attacker+"\x00"+leak.Victim]++
	}
	pairs := map[string]probe.CounterfactualPair{}
	if res.Counterfactual != nil {
		for _, pair := range res.Counterfactual.Pairs {
			pairs[pair.Attacker+"\x00"+pair.Victim] = pair
		}
	}

	rows := make([]htmlMatrixRow, 0, len(res.Tenants))
	for _, attacker := range res.Tenants {
		row := htmlMatrixRow{Attacker: attacker}
		for _, victim := range res.Tenants {
			cell := htmlMatrixCell{Victim: victim}
			if attacker == victim {
				cell.Diagonal = true
				cell.Class = "na"
				cell.Label = "—"
				cell.Detail = "same tenant"
				row.Cells = append(row.Cells, cell)
				continue
			}
			key := attacker + "\x00" + victim
			if res.Counterfactual != nil {
				pair, ok := pairs[key]
				if !ok {
					cell.Class, cell.Label, cell.Detail = "na", "N/A", "not tested"
				} else {
					cell.Class = "safe"
					if pair.Significant {
						cell.Class = "danger"
					}
					cell.Label = fmt.Sprintf("%d/%d", pair.Concordant, pair.Calibrated)
					cell.Detail = "adj p " + formatPValue(pair.AdjustedP)
				}
			} else {
				count := leakCounts[key]
				if count == 0 {
					cell.Class, cell.Label, cell.Detail = "safe", "0", "no finding"
				} else {
					cell.Class, cell.Label = "danger", fmt.Sprintf("%d", count)
					cell.Detail = "finding"
					if count != 1 {
						cell.Detail = "findings"
					}
				}
			}
			row.Cells = append(row.Cells, cell)
		}
		rows = append(rows, row)
	}
	return rows
}

func humanizeIdentifier(value string) string {
	parts := strings.Fields(strings.ReplaceAll(value, "_", " "))
	for i := range parts {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, " ")
}

func formatPValue(value float64) string {
	if value == 0 {
		return "0"
	}
	if value < 0.001 {
		return fmt.Sprintf("%.2e", value)
	}
	return fmt.Sprintf("%.4g", value)
}

func remediationFor(leakType string) htmlRemediation {
	switch leakType {
	case "cross_tenant_citation":
		return htmlRemediation{
			Title: "Constrain retrieval and citations",
			Text:  "Apply the authenticated tenant predicate before ranking or graph expansion, and reject every citation whose owner differs from the active principal.",
		}
	case "counterfactual_noninterference":
		return htmlRemediation{
			Title: "Close the observed influence channel",
			Text:  "Trace the affected directed boundary through retrieval filters, caches, conversation memory, tool state, and response assembly. Derive tenant scope from server-validated credentials at every hop.",
		}
	case "pii_leak", "secret_leak":
		return htmlRemediation{
			Title: "Enforce authorization before generation",
			Text:  "Treat PII and secret filtering as defense in depth. Prevent unauthorized records from entering model context by enforcing tenant ownership during retrieval and tool execution.",
		}
	case "content_influence":
		return htmlRemediation{
			Title: "Preserve and validate provenance",
			Text:  "Carry tenant ownership through retrieval and response assembly, then block output derived from sources outside the authenticated tenant scope.",
		}
	default:
		return htmlRemediation{
			Title: "Enforce tenant scope end to end",
			Text:  "Derive tenant identity from authenticated server-side context and enforce it before retrieval, caching, memory access, tool calls, and citation assembly.",
		}
	}
}

var htmlReportTemplate = template.Must(template.New("tenantprobe-report").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>TenantProbe · {{.Verdict}} · Security report</title>
  <style>
    :root {
      --page: #f6f8fa;
      --surface: #ffffff;
      --surface-muted: #f6f8fa;
      --border: #d0d7de;
      --border-strong: #afb8c1;
      --text: #1f2328;
      --muted: #59636e;
      --blue: #0969da;
      --blue-soft: #ddf4ff;
      --green: #1a7f37;
      --green-soft: #dafbe1;
      --red: #cf222e;
      --red-soft: #ffebe9;
      --amber: #9a6700;
      --amber-soft: #fff8c5;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--page); color: var(--text); font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
    .shell { width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 56px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; min-height: 44px; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 600; }
    .mark { display: grid; place-items: center; width: 30px; height: 30px; border-radius: 5px; background: #24292f; color: #fff; font: 700 11px/1 var(--mono); }
    .subbrand { color: var(--muted); font-weight: 400; }
    .actions { display: flex; gap: 8px; }
    .button { border: 1px solid var(--border-strong); background: var(--surface); color: var(--text); border-radius: 6px; padding: 7px 11px; font: inherit; font-size: 12px; font-weight: 600; cursor: pointer; }
    .button:hover { background: var(--surface-muted); border-color: #8c959f; }
    .hero { border: 1px solid var(--border); border-left-width: 5px; border-radius: 6px; background: var(--surface); padding: 22px 24px; }
    .hero.pass { border-left-color: var(--green); }
    .hero.fail { border-left-color: var(--red); }
    .eyebrow { color: var(--muted); font-size: 12px; font-weight: 600; }
    .verdict-line { display: flex; align-items: center; gap: 10px; margin: 6px 0 4px; }
    .verdict { font-size: 32px; line-height: 1.15; font-weight: 650; letter-spacing: -.5px; }
    .status-dot { width: 10px; height: 10px; border-radius: 50%; }
    .pass .status-dot { background: var(--green); }
    .fail .status-dot { background: var(--red); }
    .summary { color: var(--muted); font-size: 14px; }
    .target { margin-top: 16px; color: var(--muted); font: 12px/1.5 var(--mono); word-break: break-all; }
    .target:before { content: "Target: "; color: var(--text); font-weight: 600; }
    .metrics { display: grid; grid-template-columns: repeat(4, 1fr); margin: 16px 0 22px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface); }
    .metric { padding: 15px 18px; border-right: 1px solid var(--border); }
    .metric:last-child { border-right: 0; }
    .metric-value { font-size: 22px; line-height: 1.2; font-weight: 600; }
    .metric-label { margin-top: 3px; color: var(--muted); font-size: 12px; }
    .metric.danger .metric-value { color: var(--red); }
    .metric.safe .metric-value { color: var(--green); }
    .panel { margin-top: 16px; padding: 20px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface); }
    .panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 16px; }
    .panel h2 { margin: 0; font-size: 16px; line-height: 1.4; font-weight: 600; }
    .panel-copy { max-width: 760px; margin: 4px 0 0; color: var(--muted); font-size: 13px; }
    .tag { display: inline-flex; align-items: center; padding: 3px 7px; border: 1px solid var(--border); border-radius: 12px; color: var(--muted); background: var(--surface-muted); font-size: 11px; font-weight: 600; white-space: nowrap; }
    .tag.pass { color: var(--green); border-color: #4ac26b; background: var(--green-soft); }
    .tag.fail { color: var(--red); border-color: #ff8182; background: var(--red-soft); }
    .matrix-wrap { overflow: auto; }
    .matrix { width: 100%; min-width: 600px; border-collapse: collapse; }
    .matrix th { padding: 8px 10px; border-bottom: 1px solid var(--border); color: var(--muted); font-size: 11px; font-weight: 600; text-align: center; }
    .matrix th:first-child { text-align: left; }
    .matrix td { border-bottom: 1px solid var(--border); }
    .matrix tr:last-child td, .matrix tr:last-child th { border-bottom: 0; }
    .matrix-cell { min-width: 110px; height: 58px; padding: 8px 10px; text-align: center; }
    .matrix-cell strong { display: block; font-size: 14px; font-weight: 600; }
    .matrix-cell small { display: block; margin-top: 2px; color: var(--muted); font-size: 10px; }
    .matrix-cell.safe { background: var(--green-soft); }
    .matrix-cell.safe strong { color: var(--green); }
    .matrix-cell.danger { background: var(--red-soft); }
    .matrix-cell.danger strong { color: var(--red); }
    .matrix-cell.na { background: var(--surface-muted); color: var(--muted); }
    .row-label { max-width: 170px; color: var(--text) !important; text-align: left !important; overflow: hidden; text-overflow: ellipsis; }
    .finding-list { display: grid; gap: 12px; }
    .finding { padding: 16px; border: 1px solid var(--border); border-left: 3px solid var(--red); border-radius: 4px; background: var(--surface); }
    .finding-top { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
    .finding-number { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 50%; background: var(--red-soft); color: var(--red); font-size: 11px; font-weight: 600; }
    .finding-title { font-size: 14px; font-weight: 600; }
    .edge { margin-left: auto; color: var(--text); font: 12px/1.4 var(--mono); }
    .edge span { padding: 0 4px; color: var(--red); }
    .finding-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
    .evidence-box { min-width: 0; padding: 10px 12px; border: 1px solid var(--border); border-radius: 4px; background: var(--surface-muted); }
    .label { display: block; margin-bottom: 4px; color: var(--muted); font-size: 10px; font-weight: 600; text-transform: uppercase; }
    .evidence-box code { color: var(--text); font: 12px/1.5 var(--mono); white-space: pre-wrap; word-break: break-word; }
    .remediation { margin: 12px 0 0; color: var(--muted); font-size: 13px; }
    .remediation strong { color: var(--text); }
    .clean-state { padding: 24px; border: 1px solid #4ac26b; border-radius: 4px; background: var(--green-soft); text-align: center; }
    .clean-icon { color: var(--green); font-size: 22px; }
    .pcni-meta { display: grid; grid-template-columns: repeat(4, 1fr); margin-bottom: 14px; border: 1px solid var(--border); border-radius: 4px; }
    .pcni-meta div { padding: 10px 12px; border-right: 1px solid var(--border); }
    .pcni-meta div:last-child { border-right: 0; }
    .pcni-table { width: 100%; border-collapse: collapse; }
    .pcni-table th, .pcni-table td { padding: 10px 8px; border-bottom: 1px solid var(--border); text-align: left; }
    .pcni-table th { color: var(--muted); font-size: 10px; font-weight: 600; text-transform: uppercase; }
    .bar { display: block; width: 100px; height: 5px; margin-top: 5px; border: 0; border-radius: 0; background: var(--border); overflow: hidden; }
    .bar::-webkit-progress-bar { background: var(--border); }
    .bar::-webkit-progress-value { background: var(--blue); }
    .bar::-moz-progress-bar { background: var(--blue); }
    .pair-pass { color: var(--green); }
    .pair-fail { color: var(--red); }
    .recommendations { display: grid; gap: 10px; }
    .recommendation { padding: 12px 14px; border: 1px solid var(--border); border-left: 3px solid var(--amber); border-radius: 4px; background: var(--amber-soft); }
    .recommendation h3 { margin: 0 0 4px; font-size: 13px; font-weight: 600; }
    .recommendation p { margin: 0; color: var(--muted); font-size: 13px; }
    .notice { margin-top: 16px; padding: 12px 14px; border: 1px solid var(--border); border-radius: 4px; background: var(--surface-muted); color: var(--muted); font-size: 12px; }
    .notice strong { color: var(--text); }
    .footer { display: flex; justify-content: space-between; margin-top: 18px; color: var(--muted); font-size: 11px; }
    .footer strong { color: var(--text); }
    @media (max-width: 760px) {
      .shell { width: min(100% - 20px, 1120px); padding-top: 14px; }
      .topbar { align-items: flex-start; }
      .subbrand { display: none; }
      .actions .button:first-child { display: none; }
      .metrics { grid-template-columns: repeat(2, 1fr); }
      .metric:nth-child(2) { border-right: 0; }
      .metric:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
      .finding-grid { grid-template-columns: 1fr; }
      .pcni-meta { grid-template-columns: repeat(2, 1fr); }
      .pcni-meta div:nth-child(2) { border-right: 0; }
      .pcni-meta div:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
      .edge { width: 100%; margin-left: 0; }
      .panel { padding: 15px; }
    }
    @media print {
      body { background: #fff; }
      .shell { width: 100%; padding: 0; }
      .actions { display: none; }
      .panel, .hero, .metrics { break-inside: avoid; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand"><span class="mark">TP</span><span>TenantProbe</span><span class="subbrand">Tenant isolation test report</span></div>
      <div class="actions"><button class="button" onclick="downloadJSON()">Download JSON</button><button class="button" onclick="window.print()">Print / PDF</button></div>
    </header>

    <section class="hero {{.VerdictClass}}">
      <div class="eyebrow">Scan result</div>
      <div class="verdict-line"><span class="status-dot" aria-hidden="true"></span><div class="verdict">{{.Verdict}}</div></div>
      <div class="summary">{{.VerdictSummary}}</div>
      <div class="target">{{.Target}}</div>
    </section>

    <section class="metrics" aria-label="Scan summary">
      <div class="metric"><div class="metric-value">{{.TenantCount}}</div><div class="metric-label">Tenants</div></div>
      <div class="metric"><div class="metric-value">{{.Probes}}</div><div class="metric-label">Probes</div></div>
      <div class="metric {{if .Passed}}safe{{else}}danger{{end}}"><div class="metric-value">{{.FindingCount}}</div><div class="metric-label">Findings</div></div>
      <div class="metric {{if .Passed}}safe{{else}}danger{{end}}"><div class="metric-value">{{.AffectedEdges}}</div><div class="metric-label">Affected boundaries</div></div>
    </section>

    <section class="panel">
      <div class="panel-head"><div><h2>{{.MatrixTitle}}</h2><p class="panel-copy">{{.MatrixHelp}}</p></div><span class="tag {{.VerdictClass}}">{{.Verdict}}</span></div>
      <div class="matrix-wrap">
        <table class="matrix">
          <thead><tr><th scope="col">Attacker ↓ / Victim →</th>{{range .Tenants}}<th scope="col">{{.}}</th>{{end}}</tr></thead>
          <tbody>{{range .Matrix}}<tr><th scope="row" class="row-label">{{.Attacker}}</th>{{range .Cells}}<td class="matrix-cell {{.Class}}" title="{{.Victim}}: {{.Detail}}"><strong>{{.Label}}</strong><small>{{.Detail}}</small></td>{{end}}</tr>{{end}}</tbody>
        </table>
      </div>
    </section>

    {{with .Counterfactual}}
    <section class="panel">
      <div class="panel-head"><div><h2>Paired counterfactual noninterference</h2><p class="panel-copy">Victim-only randomized fact mutations tested under unchanged attacker credentials and queries.</p></div><span class="tag">Experimental</span></div>
      <div class="pcni-meta"><div><span class="label">Method</span>{{.Method}}</div><div><span class="label">Bits / victim</span>{{.Bits}}</div><div><span class="label">Family-wise α</span>{{.Alpha}}</div><div><span class="label">Hypotheses</span>{{.Hypotheses}}</div></div>
      <div class="matrix-wrap"><table class="pcni-table"><thead><tr><th>Directed boundary</th><th>Followed flips</th><th>Raw p</th><th>Holm-adjusted p</th><th>Verdict</th></tr></thead><tbody>
	        {{range .Pairs}}<tr><td><strong>{{.Attacker}}</strong> → <strong>{{.Victim}}</strong></td><td>{{.Flips}}<progress class="bar" max="100" value="{{printf "%.2f" .Percentage}}">{{printf "%.2f" .Percentage}}%</progress></td><td>{{.RawP}}</td><td>{{.AdjustedP}}</td><td class="pair-{{.Class}}">{{.Verdict}}</td></tr>{{end}}
      </tbody></table></div>
    </section>
    {{end}}

    <section class="panel">
      <div class="panel-head"><div><h2>Findings</h2><p class="panel-copy">Evidence is grouped by unique detector and directed tenant boundary.</p></div><span class="tag {{.VerdictClass}}">{{.FindingCount}} total</span></div>
      {{if .Findings}}<div class="finding-list">{{range .Findings}}
        <article class="finding">
          <div class="finding-top"><span class="finding-number">{{.Number}}</span><span class="finding-title">{{.TypeLabel}}</span><code class="tag">{{.Type}}</code><div class="edge">{{.Attacker}} <span>→</span> {{.Victim}}</div></div>
          <div class="finding-grid"><div class="evidence-box"><span class="label">Attack</span><code>{{.Attack}}</code></div><div class="evidence-box"><span class="label">Evidence</span><code>{{.Evidence}}</code></div></div>
          <p class="remediation"><strong>Suggested fix:</strong> {{.Remediation}}</p>
        </article>{{end}}</div>
      {{else}}<div class="clean-state"><div class="clean-icon">✓</div><strong>No findings on the tested boundaries</strong><p class="panel-copy">No configured detector reported a boundary violation in this scan.</p></div>{{end}}
    </section>

    {{if .Remediations}}<section class="panel"><div class="panel-head"><div><h2>Recommended fixes</h2><p class="panel-copy">Apply authorization before data enters retrieval or model context.</p></div></div><div class="recommendations">{{range .Remediations}}<div class="recommendation"><h3>{{.Title}}</h3><p>{{.Text}}</p></div>{{end}}</div></section>{{end}}

    <div class="notice"><strong>Scope note:</strong> A PASS is evidence for the principals, states, queries, and channels exercised by this scan—not a proof of universal isolation. Re-run after changes to retrieval, caching, memory, tools, or authorization.</div>
    <footer class="footer"><span>Generated {{.Generated}}</span><span><strong>TenantProbe</strong> · HTML report</span></footer>
  </main>
  <script>
    const encoded = {{.EncodedScanJSON}};
    function downloadJSON(){
      const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
      const blob=new Blob([bytes],{type:"application/json"});
      const link=document.createElement("a");
      link.href=URL.createObjectURL(blob);link.download="tenantprobe-report.json";link.click();
      setTimeout(()=>URL.revokeObjectURL(link.href),500);
    }
  </script>
</body>
</html>
`))
