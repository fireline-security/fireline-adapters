package gitleaks_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/fireline-security/fireline-adapters/gitleaks"
)

func loadSampleReport(t *testing.T) []gitleaks.Finding {
	t.Helper()
	data, err := os.ReadFile("testdata/sample-report.json")
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}
	var findings []gitleaks.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("unmarshal sample report: %v", err)
	}
	return findings
}

func TestConvertReport(t *testing.T) {
	findings := loadSampleReport(t)

	observations, err := gitleaks.ConvertReport(findings)
	if err != nil {
		t.Fatalf("ConvertReport: %v", err)
	}
	if len(observations) != 2 {
		t.Fatalf("got %d observations, want 2", len(observations))
	}

	first := observations[0]
	if err := first.Validate(); err != nil {
		t.Errorf("first observation failed Validate: %v", err)
	}
	if first.Source.Tool != "gitleaks" {
		t.Errorf("Source.Tool = %q, want %q", first.Source.Tool, "gitleaks")
	}
	if first.Source.RuleID != "aws-access-token" {
		t.Errorf("Source.RuleID = %q, want %q", first.Source.RuleID, "aws-access-token")
	}
	if first.SeverityRaw != "HIGH" {
		t.Errorf("SeverityRaw = %q, want %q", first.SeverityRaw, "HIGH")
	}
	if first.IdentityComponents["commit"] != "a1b2c3d4e5f6" {
		t.Errorf("identity_components[commit] = %q, want %q", first.IdentityComponents["commit"], "a1b2c3d4e5f6")
	}
	if first.IdentityComponents["gitleaks_fingerprint"] == "" {
		t.Error("expected identity_components[gitleaks_fingerprint] to be set")
	}

	second := observations[1]
	if err := second.Validate(); err != nil {
		t.Errorf("second observation failed Validate: %v", err)
	}
	if _, ok := second.IdentityComponents["commit"]; ok {
		t.Errorf("expected no commit identity component for a working-tree finding, got %q", second.IdentityComponents["commit"])
	}
}

func TestConvert_MissingRuleID(t *testing.T) {
	_, err := gitleaks.Convert(gitleaks.Finding{File: "x"})
	if err == nil {
		t.Fatal("expected an error for a finding with no RuleID")
	}
}

func TestConvert_MissingFile(t *testing.T) {
	_, err := gitleaks.Convert(gitleaks.Finding{RuleID: "x"})
	if err == nil {
		t.Fatal("expected an error for a finding with no File")
	}
}

func TestConvertReport_ErrorAfterAnEarlierSuccess(t *testing.T) {
	_, err := gitleaks.ConvertReport([]gitleaks.Finding{
		{RuleID: "good", File: "a.go"},
		{File: "b.go"}, // missing RuleID
	})
	if err == nil {
		t.Fatal("expected an error propagated from the second (invalid) finding, got nil")
	}
}
