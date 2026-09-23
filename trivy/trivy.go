// Package trivy converts Trivy's JSON report format into
// observation.Observation values, passing its severity through verbatim
// (D-04). See docs/severity-handling.md.
package trivy

import (
	"encoding/json"
	"fmt"

	"github.com/fireline-security/fireline-adapters/observation"
)

// Report mirrors the top level of `trivy <target> --format json`'s output.
// Only the fields this adapter uses are modeled; Trivy's real schema has
// many more, and varies by target type (image, filesystem, repo, ...).
type Report struct {
	ArtifactName string   `json:"ArtifactName"`
	Results      []Result `json:"Results"`
}

// Result is one scanned target within a Report, e.g. one OS package set
// or one language-specific dependency file.
type Result struct {
	Target          string          `json:"Target"`
	Type            string          `json:"Type"` // e.g. "alpine", "gomod", "npm"
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// Vulnerability is one finding within a Result.
type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	Severity         string `json:"Severity"`
	PrimaryURL       string `json:"PrimaryURL"`
}

// Convert maps one Vulnerability, found within a Result named target with
// ecosystem resultType (Result.Type, e.g. "alpine", "gomod"), to an
// Observation.
func Convert(target, ecosystem string, v Vulnerability) (observation.Observation, error) {
	if v.VulnerabilityID == "" {
		return observation.Observation{}, fmt.Errorf("trivy: vulnerability has no VulnerabilityID")
	}
	if v.PkgName == "" {
		return observation.Observation{}, fmt.Errorf("trivy: vulnerability has no PkgName")
	}

	severity := v.Severity
	if severity == "" {
		severity = "UNKNOWN" // Trivy's own fallback when a source doesn't report one
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return observation.Observation{}, fmt.Errorf("trivy: marshal raw_payload: %w", err)
	}

	identity := map[string]string{
		"target":            target,
		"package":           v.PkgName,
		"installed_version": v.InstalledVersion,
	}
	if ecosystem != "" {
		identity["ecosystem"] = ecosystem
	}

	return observation.New(
		observation.Source{Tool: "trivy", RuleID: v.VulnerabilityID},
		identity,
		severity,
		raw,
	), nil
}

// ConvertReport maps every Vulnerability across every Result in a Report.
func ConvertReport(report Report) ([]observation.Observation, error) {
	var out []observation.Observation
	for _, result := range report.Results {
		for i, v := range result.Vulnerabilities {
			obs, err := Convert(result.Target, result.Type, v)
			if err != nil {
				return nil, fmt.Errorf("trivy: target %q, vulnerability %d: %w", result.Target, i, err)
			}
			out = append(out, obs)
		}
	}
	return out, nil
}
