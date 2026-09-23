// Package semgrep converts Semgrep's JSON output format into
// observation.Observation values, modeled against Semgrep's published JSON
// output docs (https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif).
// It passes Semgrep's own severity through verbatim (D-04); see
// docs/severity-handling.md.
package semgrep

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/fireline-security/fireline-adapters/observation"
)

// Report mirrors the top level of `semgrep scan --json`'s output.
type Report struct {
	Results []Result `json:"results"`
}

// Result is one finding within a Report.
type Result struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   Position `json:"start"`
	End     Position `json:"end"`
	Extra   Extra    `json:"extra"`
}

// Position is a location within a file.
type Position struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

// Extra holds a Result's descriptive fields.
type Extra struct {
	Message  string   `json:"message"`
	Severity string   `json:"severity"` // documented as ERROR or WARNING
	Metadata Metadata `json:"metadata"`
}

// Metadata is a Result's rule metadata. Only CWE is modeled; Semgrep's real
// metadata also includes OWASP references, confidence/likelihood/impact,
// and links back to the rule's source.
type Metadata struct {
	CWE []string `json:"cwe"`
}

// Convert maps one Result to an Observation.
func Convert(r Result) (observation.Observation, error) {
	if r.CheckID == "" {
		return observation.Observation{}, fmt.Errorf("semgrep: result has no check_id")
	}
	if r.Path == "" {
		return observation.Observation{}, fmt.Errorf("semgrep: result %q has no path", r.CheckID)
	}
	if r.Extra.Severity == "" {
		return observation.Observation{}, fmt.Errorf("semgrep: result %q has no severity", r.CheckID)
	}

	raw, err := json.Marshal(r)
	if err != nil {
		return observation.Observation{}, fmt.Errorf("semgrep: marshal raw_payload: %w", err)
	}

	identity := map[string]string{
		"file":       r.Path,
		"start_line": strconv.Itoa(r.Start.Line),
		"end_line":   strconv.Itoa(r.End.Line),
	}

	return observation.New(
		observation.Source{Tool: "semgrep", RuleID: r.CheckID},
		identity,
		r.Extra.Severity,
		raw,
	), nil
}

// ConvertReport maps every Result in a full Report.
func ConvertReport(report Report) ([]observation.Observation, error) {
	out := make([]observation.Observation, 0, len(report.Results))
	for i, r := range report.Results {
		obs, err := Convert(r)
		if err != nil {
			return nil, fmt.Errorf("semgrep: result %d: %w", i, err)
		}
		out = append(out, obs)
	}
	return out, nil
}
