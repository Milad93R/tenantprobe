package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/milad93r/tenantprobe/internal/detector"
	"github.com/milad93r/tenantprobe/internal/probe"
)

func sampleResult() *probe.Result {
	return &probe.Result{
		Target:  "http://127.0.0.1:8077",
		Tenants: []string{"tenant-a", "tenant-b"},
		Probes:  10,
		Leaks: []detector.Leak{
			{Type: "canary_in_answer", Attacker: "tenant-a", Victim: "tenant-b", Attack: "internal secret", Evidence: "CANARY-abc123"},
			{Type: "cross_tenant_citation", Attacker: "tenant-b", Victim: "tenant-a", Attack: "confidential", Evidence: "cited doc tenant-a/x"},
		},
		Passed: false,
	}
}

func cleanResult() *probe.Result {
	return &probe.Result{
		Target:  "http://127.0.0.1:8077",
		Tenants: []string{"tenant-a", "tenant-b"},
		Probes:  10,
		Leaks:   nil,
		Passed:  true,
	}
}

func TestRenderJUnitParsesBack(t *testing.T) {
	res := sampleResult()
	var buf bytes.Buffer
	if err := Render(&buf, res, JUnit); err != nil {
		t.Fatalf("render junit: %v", err)
	}

	// Must parse back via encoding/xml into a struct.
	var parsed junitTestsuites
	if err := xml.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("junit output not well-formed / unmarshalable: %v\n%s", err, buf.String())
	}

	if parsed.Failures != len(res.Leaks) {
		t.Errorf("top-level failures = %d, want %d", parsed.Failures, len(res.Leaks))
	}
	if len(parsed.Testsuites) != 1 {
		t.Fatalf("want 1 testsuite, got %d", len(parsed.Testsuites))
	}
	suite := parsed.Testsuites[0]
	if suite.Failures != len(res.Leaks) {
		t.Errorf("suite failures = %d, want %d", suite.Failures, len(res.Leaks))
	}
	if len(suite.Testcases) == 0 {
		t.Fatalf("want testcases > 0, got 0")
	}
	if len(suite.Testcases) != len(res.Leaks) {
		t.Errorf("testcases = %d, want %d", len(suite.Testcases), len(res.Leaks))
	}
	// Each leak testcase must carry a <failure> with evidence.
	failures := 0
	for _, tc := range suite.Testcases {
		if tc.Failure != nil {
			failures++
			if !strings.Contains(tc.Failure.Body, "evidence:") {
				t.Errorf("failure body missing evidence: %q", tc.Failure.Body)
			}
		}
	}
	if failures != len(res.Leaks) {
		t.Errorf("failure elements = %d, want %d", failures, len(res.Leaks))
	}
}

func TestRenderJUnitCleanScan(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, cleanResult(), JUnit); err != nil {
		t.Fatalf("render junit: %v", err)
	}
	var parsed junitTestsuites
	if err := xml.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("clean junit not well-formed: %v", err)
	}
	if parsed.Failures != 0 {
		t.Errorf("clean failures = %d, want 0", parsed.Failures)
	}
	if parsed.Tests == 0 {
		t.Errorf("clean scan should still emit tests > 0, got 0")
	}
	if len(parsed.Testsuites) != 1 || len(parsed.Testsuites[0].Testcases) == 0 {
		t.Errorf("clean scan should emit a synthetic passing testcase")
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sampleResult(), JSON); err != nil {
		t.Fatalf("render json: %v", err)
	}
	var back probe.Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("json not parseable: %v", err)
	}
	if back.Passed {
		t.Errorf("passed = true, want false")
	}
	if len(back.Leaks) != 2 {
		t.Errorf("leaks = %d, want 2", len(back.Leaks))
	}
}

func TestRenderConsole(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sampleResult(), Console); err != nil {
		t.Fatalf("render console: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"FAIL", "tenant-a", "tenant-b", "canary_in_answer", "probes:"} {
		if !strings.Contains(out, want) {
			t.Errorf("console output missing %q\n%s", want, out)
		}
	}

	buf.Reset()
	if err := Render(&buf, cleanResult(), Console); err != nil {
		t.Fatalf("render console clean: %v", err)
	}
	if !strings.Contains(buf.String(), "PASS") {
		t.Errorf("clean console missing PASS: %s", buf.String())
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"console", "json", "junit"} {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("ParseFormat(%q) err: %v", s, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Errorf("ParseFormat(xml) should error")
	}
}
