package trivy_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/fireline-security/fireline-adapters/trivy"
)

func loadSampleReport(t *testing.T) trivy.Report {
	t.Helper()
	data, err := os.ReadFile("testdata/sample-report.json")
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}
	var report trivy.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal sample report: %v", err)
	}
	return report
}

func TestConvertReport(t *testing.T) {
	report := loadSampleReport(t)

	observations, err := trivy.ConvertReport(report)
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
	if first.Source.Tool != "trivy" {
		t.Errorf("Source.Tool = %q, want %q", first.Source.Tool, "trivy")
	}
	if first.SeverityRaw != "HIGH" {
		t.Errorf("SeverityRaw = %q, want %q", first.SeverityRaw, "HIGH")
	}
	if first.IdentityComponents["ecosystem"] != "alpine" {
		t.Errorf("identity_components[ecosystem] = %q, want %q", first.IdentityComponents["ecosystem"], "alpine")
	}
	if first.IdentityComponents["package"] != "openssl" {
		t.Errorf("identity_components[package] = %q, want %q", first.IdentityComponents["package"], "openssl")
	}

	second := observations[1]
	if err := second.Validate(); err != nil {
		t.Errorf("second observation failed Validate: %v", err)
	}
	if second.Source.RuleID != "GHSA-2c9j-2mgh-g8h5" {
		t.Errorf("Source.RuleID = %q, want %q", second.Source.RuleID, "GHSA-2c9j-2mgh-g8h5")
	}
	if second.SeverityRaw != "MEDIUM" {
		t.Errorf("SeverityRaw = %q, want %q", second.SeverityRaw, "MEDIUM")
	}
}

func TestConvert_MissingVulnerabilityID(t *testing.T) {
	_, err := trivy.Convert("target", "alpine", trivy.Vulnerability{PkgName: "x"})
	if err == nil {
		t.Fatal("expected an error for a vulnerability with no VulnerabilityID")
	}
}

func TestConvert_MissingPkgName(t *testing.T) {
	_, err := trivy.Convert("target", "alpine", trivy.Vulnerability{VulnerabilityID: "CVE-x"})
	if err == nil {
		t.Fatal("expected an error for a vulnerability with no PkgName")
	}
}

func TestConvertReport_ErrorAfterAnEarlierSuccess(t *testing.T) {
	_, err := trivy.ConvertReport(trivy.Report{
		Results: []trivy.Result{
			{
				Target: "t", Type: "alpine",
				Vulnerabilities: []trivy.Vulnerability{
					{VulnerabilityID: "CVE-1", PkgName: "good"},
					{PkgName: "bad"}, // missing VulnerabilityID
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected an error propagated from the second (invalid) vulnerability, got nil")
	}
}

func TestConvert_DefaultsSeverityToUnknown(t *testing.T) {
	obs, err := trivy.Convert("target", "alpine", trivy.Vulnerability{VulnerabilityID: "CVE-x", PkgName: "pkg"})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if obs.SeverityRaw != "UNKNOWN" {
		t.Errorf("SeverityRaw = %q, want %q", obs.SeverityRaw, "UNKNOWN")
	}
}
