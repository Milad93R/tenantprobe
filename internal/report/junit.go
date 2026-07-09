package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/milad93r/tenantprobe/internal/probe"
)

// JUnit XML model. CI systems (GitHub, GitLab, Jenkins) parse this schema and
// render each <testcase> as a test, with any child <failure> marking it failed.
// We emit one testcase per (attacker, victim, detector) leak plus a synthetic
// passing testcase when the scan is clean, so the suite is never empty.

type junitTestsuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Name       string           `xml:"name,attr"`
	Testsuites []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Testcases []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// renderJUnit writes a valid JUnit XML document. Each leak becomes a failing
// testcase carrying its evidence; a clean scan emits a single passing testcase
// so tests > 0 always holds.
func renderJUnit(w io.Writer, res *probe.Result) error {
	suite := junitTestsuite{
		Name:     "tenantprobe",
		Failures: len(res.Leaks),
	}

	for _, l := range res.Leaks {
		tc := junitTestcase{
			Name:      fmt.Sprintf("%s->%s [%s]", l.Attacker, l.Victim, l.Type),
			Classname: "cross-tenant-isolation",
			Failure: &junitFailure{
				Message: fmt.Sprintf("cross-tenant leak %s: %s reached %s", l.Type, l.Attacker, l.Victim),
				Type:    l.Type,
				Body:    fmt.Sprintf("attack: %s\nevidence: %s", l.Attack, l.Evidence),
			},
		}
		suite.Testcases = append(suite.Testcases, tc)
	}

	// Never emit an empty suite: a clean scan is one passing testcase.
	if len(suite.Testcases) == 0 {
		suite.Testcases = append(suite.Testcases, junitTestcase{
			Name:      "cross-tenant-isolation",
			Classname: "cross-tenant-isolation",
		})
	}
	suite.Tests = len(suite.Testcases)

	root := junitTestsuites{
		Name:       "tenantprobe",
		Tests:      suite.Tests,
		Failures:   suite.Failures,
		Testsuites: []junitTestsuite{suite},
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return fmt.Errorf("encode junit: %w", err)
	}
	_, err := io.WriteString(w, "\n")
	return err
}
