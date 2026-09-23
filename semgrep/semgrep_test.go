package semgrep_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/fireline-security/fireline-adapters/semgrep"
)

func loadSampleReport(t *testing.T) semgrep.Report {
	t.Helper()
	data, err := os.ReadFile("testdata/sample-report.json")
	if err != nil {
		t.Fatalf("read sample report: %v", err)
	}
	var report semgrep.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal sample report: %v", err)
	}
	return report
}

func TestConvertReport(t *testing.T) {
	report := loadSampleReport(t)

	observations, err := semgrep.ConvertReport(report)
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
	if first.Source.Tool != "semgrep" {
		t.Errorf("Source.Tool = %q, want %q", first.Source.Tool, "semgrep")
	}
	if first.Source.RuleID != "python.django.security.injection.sql.sql-injection-using-db-cursor-execute" {
		t.Errorf("unexpected Source.RuleID: %q", first.Source.RuleID)
	}
	if first.SeverityRaw != "ERROR" {
		t.Errorf("SeverityRaw = %q, want %q", first.SeverityRaw, "ERROR")
	}
	if first.IdentityComponents["file"] != "billing/queries.py" {
		t.Errorf("identity_components[file] = %q, want %q", first.IdentityComponents["file"], "billing/queries.py")
	}
	if first.IdentityComponents["start_line"] != "42" {
		t.Errorf("identity_components[start_line] = %q, want %q", first.IdentityComponents["start_line"], "42")
	}

	second := observations[1]
	if err := second.Validate(); err != nil {
		t.Errorf("second observation failed Validate: %v", err)
	}
	if second.SeverityRaw != "WARNING" {
		t.Errorf("SeverityRaw = %q, want %q", second.SeverityRaw, "WARNING")
	}
}

func TestConvert_MissingCheckID(t *testing.T) {
	_, err := semgrep.Convert(semgrep.Result{Path: "x.py", Extra: semgrep.Extra{Severity: "ERROR"}})
	if err == nil {
		t.Fatal("expected an error for a result with no check_id")
	}
}

func TestConvert_MissingPath(t *testing.T) {
	_, err := semgrep.Convert(semgrep.Result{CheckID: "x", Extra: semgrep.Extra{Severity: "ERROR"}})
	if err == nil {
		t.Fatal("expected an error for a result with no path")
	}
}

func TestConvert_MissingSeverity(t *testing.T) {
	_, err := semgrep.Convert(semgrep.Result{CheckID: "x", Path: "x.py"})
	if err == nil {
		t.Fatal("expected an error for a result with no severity")
	}
}

func TestConvertReport_ErrorAfterAnEarlierSuccess(t *testing.T) {
	_, err := semgrep.ConvertReport(semgrep.Report{
		Results: []semgrep.Result{
			{CheckID: "good", Path: "a.py", Extra: semgrep.Extra{Severity: "ERROR"}},
			{Path: "b.py", Extra: semgrep.Extra{Severity: "ERROR"}}, // missing CheckID
		},
	})
	if err == nil {
		t.Fatal("expected an error propagated from the second (invalid) result, got nil")
	}
}
