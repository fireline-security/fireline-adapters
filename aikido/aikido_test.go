package aikido_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/fireline-security/fireline-adapters/aikido"
)

func loadSampleIssues(t *testing.T) []aikido.Issue {
	t.Helper()
	data, err := os.ReadFile("testdata/sample-issues.json")
	if err != nil {
		t.Fatalf("read sample issues: %v", err)
	}
	var issues []aikido.Issue
	if err := json.Unmarshal(data, &issues); err != nil {
		t.Fatalf("unmarshal sample issues: %v", err)
	}
	return issues
}

func TestConvertExport(t *testing.T) {
	issues := loadSampleIssues(t)

	observations, err := aikido.ConvertExport(issues)
	if err != nil {
		t.Fatalf("ConvertExport: %v", err)
	}
	if len(observations) != 3 {
		t.Fatalf("got %d observations, want 3", len(observations))
	}
	for i, obs := range observations {
		if err := obs.Validate(); err != nil {
			t.Errorf("observation %d failed Validate: %v", i, err)
		}
	}

	openSource := observations[0]
	if openSource.Source.Tool != "aikido" {
		t.Errorf("Source.Tool = %q, want %q", openSource.Source.Tool, "aikido")
	}
	if openSource.SeverityRaw != "critical" {
		t.Errorf("SeverityRaw = %q, want %q", openSource.SeverityRaw, "critical")
	}
	if openSource.IdentityComponents["affected_package"] != "minimist" {
		t.Errorf("identity_components[affected_package] = %q, want %q", openSource.IdentityComponents["affected_package"], "minimist")
	}
	if openSource.ObservedAt == "" {
		t.Error("expected ObservedAt to be set from first_detected_at")
	}

	leakedSecret := observations[1]
	if leakedSecret.IdentityComponents["start_line"] != "12" {
		t.Errorf("identity_components[start_line] = %q, want %q", leakedSecret.IdentityComponents["start_line"], "12")
	}
	if _, ok := leakedSecret.IdentityComponents["affected_package"]; ok {
		t.Error("expected no affected_package identity component for a secrets finding")
	}

	cloud := observations[2]
	if cloud.IdentityComponents["cloud_name"] != "prod-aws" {
		t.Errorf("identity_components[cloud_name] = %q, want %q", cloud.IdentityComponents["cloud_name"], "prod-aws")
	}
	if _, ok := cloud.IdentityComponents["affected_file"]; ok {
		t.Error("expected no affected_file identity component for a cloud finding")
	}
}

func TestConvert_MissingType(t *testing.T) {
	_, err := aikido.Convert(aikido.Issue{Severity: "high", RuleID: "x"})
	if err == nil {
		t.Fatal("expected an error for an issue with no type")
	}
}

func TestConvert_MissingSeverity(t *testing.T) {
	_, err := aikido.Convert(aikido.Issue{Type: aikido.TypeCloud, RuleID: "x"})
	if err == nil {
		t.Fatal("expected an error for an issue with no severity")
	}
}

func TestConvert_NoRuleIdentifier(t *testing.T) {
	_, err := aikido.Convert(aikido.Issue{Type: aikido.TypeCloud, Severity: "high"})
	if err == nil {
		t.Fatal("expected an error for an issue with no rule_id, cve_id, or rule")
	}
}

func TestConvertExport_ErrorAfterAnEarlierSuccess(t *testing.T) {
	_, err := aikido.ConvertExport([]aikido.Issue{
		{Type: aikido.TypeCloud, Severity: "high", RuleID: "good"},
		{Severity: "high", RuleID: "bad"}, // missing Type
	})
	if err == nil {
		t.Fatal("expected an error propagated from the second (invalid) issue, got nil")
	}
}

func TestConvert_FallsBackToCVEIDThenRule(t *testing.T) {
	obs, err := aikido.Convert(aikido.Issue{
		Type: aikido.TypeOpenSource, Severity: "high", CVEID: "CVE-2024-1", AffectedPackage: "pkg",
	})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if obs.Source.RuleID != "CVE-2024-1" {
		t.Errorf("Source.RuleID = %q, want %q", obs.Source.RuleID, "CVE-2024-1")
	}

	obs, err = aikido.Convert(aikido.Issue{
		Type: aikido.TypeSAST, Severity: "low", Rule: "Hardcoded credentials", AffectedFile: "x.go",
	})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if obs.Source.RuleID != "Hardcoded credentials" {
		t.Errorf("Source.RuleID = %q, want %q", obs.Source.RuleID, "Hardcoded credentials")
	}
}
