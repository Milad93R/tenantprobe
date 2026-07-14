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
  <meta name="color-scheme" content="dark">
  <title>TenantProbe · {{.Verdict}} · Security report</title>
  <style>
    :root{--bg:#07111f;--panel:#0d1a2c;--panel2:#101f33;--line:#21334b;--text:#edf4ff;--muted:#94a7c2;--cyan:#52d9ff;--cyan2:#1688aa;--green:#53e0a1;--green-bg:#0c342b;--red:#ff6b7a;--red-bg:#411c2a;--amber:#ffc76a;--radius:18px;--shadow:0 18px 55px rgba(0,0,0,.25)}
    *{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 85% -5%,rgba(36,146,187,.22),transparent 30%),radial-gradient(circle at 10% 20%,rgba(38,95,160,.15),transparent 28%),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.18;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:38px 38px}
    a{color:inherit}.shell{width:min(1180px,calc(100% - 32px));margin:0 auto;padding:30px 0 70px;position:relative}.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}.brand{display:flex;align-items:center;gap:12px;font-weight:760;letter-spacing:.2px}.mark{display:grid;place-items:center;width:38px;height:38px;border:1px solid rgba(82,217,255,.45);border-radius:11px;background:linear-gradient(145deg,rgba(82,217,255,.2),rgba(82,217,255,.04));box-shadow:inset 0 0 20px rgba(82,217,255,.08);color:var(--cyan);font-size:20px}.subbrand{color:var(--muted);font-weight:520}.actions{display:flex;gap:9px}.button{border:1px solid var(--line);background:rgba(16,31,51,.8);color:var(--text);border-radius:10px;padding:9px 13px;font:inherit;font-weight:650;cursor:pointer}.button:hover{border-color:var(--cyan2);background:#13273d}
    .hero{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:24px;background:linear-gradient(130deg,rgba(16,31,51,.98),rgba(9,25,42,.94));padding:34px;box-shadow:var(--shadow)}.hero:after{content:"";position:absolute;width:320px;height:320px;border-radius:50%;right:-150px;top:-185px;background:{{if .Passed}}rgba(83,224,161,.13){{else}}rgba(255,107,122,.14){{end}};filter:blur(3px)}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:1.7px;color:var(--cyan);font-weight:800}.verdict-line{display:flex;align-items:center;gap:15px;margin:10px 0 6px}.verdict{font-size:44px;line-height:1;font-weight:850;letter-spacing:-1.4px}.status-dot{width:14px;height:14px;border-radius:50%;box-shadow:0 0 0 7px rgba(255,255,255,.035)}.pass .status-dot{background:var(--green);box-shadow:0 0 24px rgba(83,224,161,.7)}.fail .status-dot{background:var(--red);box-shadow:0 0 24px rgba(255,107,122,.65)}.summary{max-width:690px;color:#c7d4e6;font-size:16px}.target{display:flex;gap:9px;align-items:center;margin-top:22px;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.target:before{content:"TARGET";font:800 10px/1 ui-sans-serif,system-ui;letter-spacing:1.2px;color:#6f849f;border:1px solid var(--line);padding:5px 7px;border-radius:6px}
    .metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin:18px 0 30px}.metric,.panel{border:1px solid var(--line);background:linear-gradient(150deg,rgba(15,31,51,.95),rgba(11,24,41,.92));border-radius:var(--radius);box-shadow:0 12px 35px rgba(0,0,0,.16)}.metric{padding:18px 20px}.metric-value{font-size:28px;font-weight:820;letter-spacing:-.7px}.metric-label{font-size:11px;text-transform:uppercase;letter-spacing:1.1px;color:var(--muted);font-weight:750}.metric.danger .metric-value{color:var(--red)}.metric.safe .metric-value{color:var(--green)}
    .panel{padding:24px;margin-top:18px}.panel-head{display:flex;align-items:start;justify-content:space-between;gap:20px;margin-bottom:20px}.panel h2{font-size:19px;margin:0;letter-spacing:-.25px}.panel-copy{color:var(--muted);margin:5px 0 0;max-width:760px}.tag{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:5px 9px;color:var(--muted);font-size:11px;font-weight:750;white-space:nowrap}.tag.pass{color:var(--green);border-color:rgba(83,224,161,.3);background:rgba(83,224,161,.07)}.tag.fail{color:var(--red);border-color:rgba(255,107,122,.3);background:rgba(255,107,122,.07)}
    .matrix-wrap{overflow:auto;padding-bottom:4px}.matrix{width:100%;border-collapse:separate;border-spacing:7px;min-width:600px}.matrix th{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);padding:5px 8px}.matrix th:first-child{text-align:left}.matrix-cell{min-width:105px;height:74px;text-align:center;border:1px solid var(--line);border-radius:12px;background:#0a1728;padding:8px}.matrix-cell strong{display:block;font-size:17px}.matrix-cell small{display:block;color:var(--muted);font-size:10px;margin-top:2px}.matrix-cell.safe{border-color:rgba(83,224,161,.24);background:rgba(83,224,161,.07)}.matrix-cell.safe strong{color:var(--green)}.matrix-cell.danger{border-color:rgba(255,107,122,.42);background:rgba(255,107,122,.1);box-shadow:inset 0 0 24px rgba(255,107,122,.04)}.matrix-cell.danger strong{color:var(--red)}.matrix-cell.na{opacity:.46;background:rgba(255,255,255,.02)}.row-label{text-align:left!important;color:#cdd9e9!important;text-transform:none!important;letter-spacing:0!important;max-width:160px;overflow:hidden;text-overflow:ellipsis}
    .finding-list{display:grid;gap:12px}.finding{border:1px solid rgba(255,107,122,.25);background:linear-gradient(120deg,rgba(65,28,42,.47),rgba(13,26,44,.7));border-radius:14px;padding:18px}.finding-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.finding-number{display:grid;place-items:center;width:25px;height:25px;border-radius:7px;background:var(--red-bg);color:var(--red);font-size:11px;font-weight:850}.finding-title{font-weight:780;font-size:15px}.edge{margin-left:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#d8e6f8}.edge span{color:var(--red);padding:0 5px}.finding-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}.evidence-box{background:rgba(4,13,24,.55);border:1px solid var(--line);border-radius:10px;padding:11px 13px;min-width:0}.label{display:block;color:#7890ad;font-size:10px;font-weight:800;letter-spacing:1px;text-transform:uppercase;margin-bottom:5px}.evidence-box code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#dbe8f8;white-space:pre-wrap;word-break:break-word}.remediation{margin:13px 0 0;color:#b8c9dc}.remediation strong{color:var(--amber)}.clean-state{padding:30px;text-align:center;border:1px dashed rgba(83,224,161,.25);border-radius:14px;background:rgba(83,224,161,.04)}.clean-icon{font-size:27px;color:var(--green)}
	    .pcni-meta{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}.pcni-meta div{border:1px solid var(--line);background:rgba(4,13,24,.35);padding:12px;border-radius:10px}.pcni-table{width:100%;border-collapse:collapse}.pcni-table th,.pcni-table td{text-align:left;padding:11px 9px;border-bottom:1px solid var(--line)}.pcni-table th{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.8px}.bar{display:block;width:110px;height:6px;border:0;border-radius:99px;background:#203149;overflow:hidden;margin-top:5px}.bar::-webkit-progress-bar{background:#203149}.bar::-webkit-progress-value{background:var(--cyan)}.bar::-moz-progress-bar{background:var(--cyan)}.pair-pass{color:var(--green)}.pair-fail{color:var(--red)}
    .recommendations{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.recommendation{border-left:3px solid var(--amber);background:rgba(255,199,106,.045);border-radius:3px 12px 12px 3px;padding:14px 16px}.recommendation h3{font-size:14px;margin:0 0 5px}.recommendation p{color:var(--muted);margin:0}.notice{margin-top:18px;padding:14px 16px;border:1px solid var(--line);border-radius:12px;color:var(--muted);background:rgba(4,13,24,.32)}.notice strong{color:#cbd8e8}.footer{display:flex;justify-content:space-between;color:#6f849f;margin-top:24px;font-size:12px}.footer strong{color:#9cb0c9}
    @media(max-width:760px){.shell{width:min(100% - 20px,1180px);padding-top:16px}.topbar{align-items:flex-start}.subbrand{display:none}.hero{padding:24px}.verdict{font-size:36px}.metrics{grid-template-columns:repeat(2,1fr)}.finding-grid,.recommendations{grid-template-columns:1fr}.pcni-meta{grid-template-columns:repeat(2,1fr)}.panel{padding:18px}.edge{margin-left:0;width:100%}.actions .button:first-child{display:none}}
    @media print{body{background:#fff;color:#101827}.shell{width:100%;padding:0}.actions{display:none}.hero,.metric,.panel{box-shadow:none;background:#fff;border-color:#cfd7e3}.summary,.panel-copy,.recommendation p,.notice,.target,.metric-label,.matrix-cell small{color:#475569}.verdict,.panel h2,.metric-value{color:#101827}.matrix-cell{background:#fff}.footer{color:#64748b}.finding{background:#fff}.evidence-box{background:#f8fafc}.evidence-box code{color:#1e293b}}
  </style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand"><span class="mark">⌁</span><span>TenantProbe</span><span class="subbrand">Cross-tenant isolation report</span></div>
      <div class="actions"><button class="button" onclick="downloadJSON()">Download JSON</button><button class="button" onclick="window.print()">Print / PDF</button></div>
    </header>

    <section class="hero {{.VerdictClass}}">
      <div class="eyebrow">Security boundary verdict</div>
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
          <p class="remediation"><strong>Recommended:</strong> {{.Remediation}}</p>
        </article>{{end}}</div>
      {{else}}<div class="clean-state"><div class="clean-icon">✓</div><strong>No findings on the tested boundaries</strong><p class="panel-copy">Keep this report as CI evidence and expand scenarios as the system adds caches, memory, and tools.</p></div>{{end}}
    </section>

    {{if .Remediations}}<section class="panel"><div class="panel-head"><div><h2>Remediation priorities</h2><p class="panel-copy">Address authorization at the earliest data boundary; output filters are defense in depth.</p></div></div><div class="recommendations">{{range .Remediations}}<div class="recommendation"><h3>{{.Title}}</h3><p>{{.Text}}</p></div>{{end}}</div></section>{{end}}

    <div class="notice"><strong>Scope note:</strong> A PASS is evidence for the principals, states, queries, and channels exercised by this scan—not a proof of universal isolation. Re-run after changes to retrieval, caching, memory, tools, or authorization.</div>
    <footer class="footer"><span>Generated {{.Generated}}</span><span><strong>TenantProbe</strong> · self-contained report</span></footer>
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
