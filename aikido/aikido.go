// Package aikido converts issues from Aikido Security's "Export all issues"
// API (GET /public/v1/issues/export) into observation.Observation values.
//
// Aikido reports its own severity per issue and this adapter passes
// SeverityRaw through verbatim (D-04); see docs/severity-handling.md.
// See docs/aikido/issue-mapping.md for the identityComponents trade-off
// and why this package doesn't call Aikido's API itself.
package aikido

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/fireline-security/fireline-adapters/observation"
)

// Issue "type" values, as documented by Aikido's export-issues API. Not
// exhaustive of every field this adapter reads, but useful for callers that
// want to filter or branch on category.
const (
	TypeOpenSource        = "open_source"
	TypeLeakedSecret      = "leaked_secret"
	TypeCloud             = "cloud"
	TypeIaC               = "iac"
	TypeSAST              = "sast"
	TypeMobile            = "mobile"
	TypeSurfaceMonitoring = "surface_monitoring"
	TypeMalware           = "malware"
	TypeEOL               = "eol"
	TypeSCMSecurity       = "scm_security"
	TypeAIPentest         = "ai_pentest"
	TypeLicense           = "license"
)

// Issue mirrors one element of the array returned by Aikido's "Export all
// issues" endpoint. Only the fields this adapter uses are modeled; Aikido's
// real schema has more (status, SLA fields, exploitability, CWE classes,
// and category-specific fields for mobile/malware/license issues among
// others).
type Issue struct {
	ID                 int64  `json:"id"`
	Type               string `json:"type"`
	Severity           string `json:"severity"`
	Rule               string `json:"rule"`
	RuleID             string `json:"rule_id"`
	CVEID              string `json:"cve_id"`
	AffectedPackage    string `json:"affected_package"`
	InstalledVersion   string `json:"installed_version"`
	AffectedFile       string `json:"affected_file"`
	StartLine          *int   `json:"start_line"`
	CodeRepoName       string `json:"code_repo_name"`
	CodeRepoBranchName string `json:"code_repo_branch_name"`
	CloudName          string `json:"cloud_name"`
	ContainerRepoName  string `json:"container_repo_name"`
	DomainName         string `json:"domain_name"`
	VirtualMachineName string `json:"virtual_machine_name"`
	FirstDetectedAt    int64  `json:"first_detected_at"`
}

// Convert maps one Issue to an Observation.
func Convert(issue Issue) (observation.Observation, error) {
	if issue.Type == "" {
		return observation.Observation{}, fmt.Errorf("aikido: issue %d has no type", issue.ID)
	}
	if issue.Severity == "" {
		return observation.Observation{}, fmt.Errorf("aikido: issue %d has no severity", issue.ID)
	}
	ruleID := ruleIdentifier(issue)
	if ruleID == "" {
		return observation.Observation{}, fmt.Errorf("aikido: issue %d has no rule_id, cve_id, or rule to identify it by", issue.ID)
	}

	raw, err := json.Marshal(issue)
	if err != nil {
		return observation.Observation{}, fmt.Errorf("aikido: marshal raw_payload: %w", err)
	}

	obs := observation.New(
		observation.Source{Tool: "aikido", RuleID: ruleID},
		identityComponents(issue),
		issue.Severity,
		raw,
	)
	if issue.FirstDetectedAt > 0 {
		obs.ObservedAt = time.Unix(issue.FirstDetectedAt, 0).UTC().Format(time.RFC3339)
	}
	return obs, nil
}

// ConvertExport maps every Issue in a full "Export all issues" response.
func ConvertExport(issues []Issue) ([]observation.Observation, error) {
	out := make([]observation.Observation, 0, len(issues))
	for i, issue := range issues {
		obs, err := Convert(issue)
		if err != nil {
			return nil, fmt.Errorf("aikido: index %d: %w", i, err)
		}
		out = append(out, obs)
	}
	return out, nil
}

// ruleIdentifier picks source.rule_id from whichever of Aikido's own
// identifiers is present: RuleID is documented optional, so this falls back
// to CVEID, then the human-readable Rule name, before giving up. The wire
// contract requires a non-empty rule_id.
func ruleIdentifier(issue Issue) string {
	switch {
	case issue.RuleID != "":
		return issue.RuleID
	case issue.CVEID != "":
		return issue.CVEID
	case issue.Rule != "":
		return issue.Rule
	default:
		return ""
	}
}

// identityComponents includes whichever of Issue's category-specific fields
// Aikido populated for this particular issue. See the package doc comment
// for why this is a general default rather than a per-Type mapping.
func identityComponents(issue Issue) map[string]string {
	m := make(map[string]string)
	add := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}

	add("type", issue.Type)
	add("affected_package", issue.AffectedPackage)
	add("installed_version", issue.InstalledVersion)
	add("affected_file", issue.AffectedFile)
	add("cve_id", issue.CVEID)
	add("code_repo_name", issue.CodeRepoName)
	add("code_repo_branch_name", issue.CodeRepoBranchName)
	add("cloud_name", issue.CloudName)
	add("container_repo_name", issue.ContainerRepoName)
	add("domain_name", issue.DomainName)
	add("virtual_machine_name", issue.VirtualMachineName)
	if issue.StartLine != nil {
		m["start_line"] = strconv.Itoa(*issue.StartLine)
	}
	return m
}
