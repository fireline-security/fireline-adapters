// Package gitleaks converts Gitleaks' JSON report format into
// observation.Observation values. Gitleaks reports no severity, so this
// adapter hardcodes severity_raw to "HIGH" (see docs/severity-handling.md
// for why).
package gitleaks

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/fireline-security/fireline-adapters/observation"
)

// Finding mirrors one element of `gitleaks detect --report-format json`'s
// report array. Field names and casing match Gitleaks' own JSON exactly.
// Only the fields this adapter uses are modeled.
type Finding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}

// defaultSeverity is what every Gitleaks finding is reported as, since
// Gitleaks itself has no severity concept. See the package doc comment.
const defaultSeverity = "HIGH"

// Convert maps one Gitleaks Finding to an Observation. It does not redact
// Match or Secret from raw_payload; redaction is a consumer's choice, not
// this adapter's.
func Convert(f Finding) (observation.Observation, error) {
	if f.RuleID == "" {
		return observation.Observation{}, fmt.Errorf("gitleaks: finding has no RuleID")
	}
	if f.File == "" {
		return observation.Observation{}, fmt.Errorf("gitleaks: finding has no File")
	}

	raw, err := json.Marshal(f) // #nosec G117 -- f.Secret is Gitleaks' own finding data, not a credential of this adapter's; see the doc comment above for why it isn't redacted
	if err != nil {
		return observation.Observation{}, fmt.Errorf("gitleaks: marshal raw_payload: %w", err)
	}

	// A working-tree scan (as opposed to a git-history scan) leaves Commit
	// and Fingerprint empty; file+line+rule is still a fine identity for
	// that case, so they're included only when Gitleaks actually set them.
	identity := map[string]string{
		"file": f.File,
		"line": strconv.Itoa(f.StartLine),
	}
	if f.Commit != "" {
		identity["commit"] = f.Commit
	}
	if f.Fingerprint != "" {
		identity["gitleaks_fingerprint"] = f.Fingerprint
	}

	return observation.New(
		observation.Source{Tool: "gitleaks", RuleID: f.RuleID},
		identity,
		defaultSeverity,
		raw,
	), nil
}

// ConvertReport maps every Finding in a full Gitleaks report.
func ConvertReport(findings []Finding) ([]observation.Observation, error) {
	out := make([]observation.Observation, 0, len(findings))
	for i, f := range findings {
		obs, err := Convert(f)
		if err != nil {
			return nil, fmt.Errorf("gitleaks: finding %d: %w", i, err)
		}
		out = append(out, obs)
	}
	return out, nil
}
