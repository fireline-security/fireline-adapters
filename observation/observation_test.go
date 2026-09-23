package observation_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/fireline-security/fireline-adapters/observation"
)

func validArgs() (observation.Source, map[string]string, string, json.RawMessage) {
	return observation.Source{Tool: "trivy", RuleID: "CVE-2024-12345"},
		map[string]string{"package": "openssl"},
		"HIGH",
		json.RawMessage(`{"id":"CVE-2024-12345"}`)
}

func TestNew_SetsSchemaVersion(t *testing.T) {
	source, components, severity, payload := validArgs()
	obs := observation.New(source, components, severity, payload)

	if obs.SchemaVersion != observation.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", obs.SchemaVersion, observation.SchemaVersion)
	}
	if err := obs.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestValidate_Invalid(t *testing.T) {
	source, components, severity, payload := validArgs()

	tests := []struct {
		name    string
		mutate  func(o *observation.Observation)
		wantErr error
	}{
		{"wrong schema version", func(o *observation.Observation) { o.SchemaVersion = "v2" }, observation.ErrWrongSchemaVersion},
		{"empty tool", func(o *observation.Observation) { o.Source.Tool = "" }, observation.ErrEmptySourceTool},
		{"empty rule id", func(o *observation.Observation) { o.Source.RuleID = "" }, observation.ErrEmptyRuleID},
		{"no identity components", func(o *observation.Observation) { o.IdentityComponents = nil }, observation.ErrNoIdentity},
		{"empty severity", func(o *observation.Observation) { o.SeverityRaw = "" }, observation.ErrEmptySeverityRaw},
		{"empty raw payload", func(o *observation.Observation) { o.RawPayload = nil }, observation.ErrEmptyRawPayload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := observation.New(source, components, severity, payload)
			tt.mutate(&obs)
			if err := obs.Validate(); !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestObservation_JSONRoundTrip(t *testing.T) {
	source, components, severity, payload := validArgs()
	obs := observation.New(source, components, severity, payload)

	data, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got observation.Observation
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("round-tripped observation failed validation: %v", err)
	}
	if got.Source != obs.Source {
		t.Errorf("Source = %+v, want %+v", got.Source, obs.Source)
	}
}
