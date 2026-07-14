package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/milad93r/tenantprobe/internal/detector"
	"github.com/milad93r/tenantprobe/internal/probe"
)

func TestRenderHTMLVulnerableScan(t *testing.T) {
	res := sampleResult()
	res.Target = `https://rag.example.test/<script>alert("target")</script>`
	res.Leaks[0].Evidence = `<script>alert("evidence")</script>`

	var buf bytes.Buffer
	if err := Render(&buf, res, HTML); err != nil {
		t.Fatalf("Render(HTML): %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!doctype html>",
		"TenantProbe",
		"Observed leak matrix",
		"Canary In Answer",
		"tenant-a",
		"tenant-b",
		"Download JSON",
		"Print / PDF",
		"FAIL",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
	if strings.Contains(out, `<script>alert("evidence")</script>`) || strings.Contains(out, `<script>alert("target")</script>`) {
		t.Fatal("untrusted result content was emitted as executable HTML")
	}
	if strings.Contains(out, "ZgotmplZ") {
		t.Fatal("html/template rejected a dynamic value")
	}

	// The self-contained download payload must decode to the original Result.
	re := regexp.MustCompile(`const encoded = "([A-Za-z0-9+/=]+)";`)
	match := re.FindStringSubmatch(out)
	if len(match) != 2 {
		start := strings.Index(out, "const encoded")
		if start < 0 {
			t.Fatalf("embedded scan payload not found")
		}
		end := start + 180
		if end > len(out) {
			end = len(out)
		}
		t.Fatalf("embedded scan payload not found: %q", out[start:end])
	}
	raw, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil {
		t.Fatalf("decode embedded scan payload: %v", err)
	}
	var decoded probe.Result
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("embedded scan payload is not valid JSON: %v", err)
	}
	if decoded.Target != res.Target || len(decoded.Leaks) != len(res.Leaks) {
		t.Fatalf("embedded scan payload differs from source result")
	}
}

func TestRenderHTMLCleanScan(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, cleanResult(), HTML); err != nil {
		t.Fatalf("Render clean HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"PASS", "No findings on the tested boundaries", "no finding"} {
		if !strings.Contains(out, want) {
			t.Errorf("clean HTML output missing %q", want)
		}
	}
	if strings.Contains(out, "Remediation priorities") {
		t.Error("clean report should not show finding-specific remediation priorities")
	}
}

func TestRenderHTMLCounterfactualMatrix(t *testing.T) {
	res := &probe.Result{
		Target:  "https://rag.example.test",
		Tenants: []string{"acme", "globex"},
		Probes:  192,
		Passed:  false,
		Leaks: []detector.Leak{{
			Type: "counterfactual_noninterference", Attacker: "acme", Victim: "globex",
			Attack: "paired victim-only fact mutation", Evidence: "answers followed 24/24 victim-only fact flips",
		}},
		Counterfactual: &probe.CounterfactualAnalysis{
			Method: "paired-counterfactual-noninterference", Bits: 24, Alpha: 0.05, Hypotheses: 2,
			Pairs: []probe.CounterfactualPair{
				{Attacker: "acme", Victim: "globex", Calibrated: 24, Concordant: 24, RawP: 5.960464477539063e-08, AdjustedP: 1.1920928955078125e-07, Significant: true},
				{Attacker: "globex", Victim: "acme", Calibrated: 24, Concordant: 0, RawP: 1, AdjustedP: 1, Significant: false},
			},
		},
	}

	var buf bytes.Buffer
	if err := Render(&buf, res, HTML); err != nil {
		t.Fatalf("Render counterfactual HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Counterfactual influence matrix",
		"Paired counterfactual noninterference",
		"paired-counterfactual-noninterference",
		"24/24",
		"Holm-adjusted p",
		"Significant flow",
		"No significant flow",
		"Close the observed influence channel",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("counterfactual HTML output missing %q", want)
		}
	}
}

func TestRenderHTMLRejectsNilResult(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, nil, HTML); err == nil {
		t.Fatal("Render nil HTML result should fail")
	}
}
