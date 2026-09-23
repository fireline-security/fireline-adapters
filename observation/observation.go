package observation

import (
	"encoding/json"
	"errors"
)

// SchemaVersion is the contract version this package mirrors.
const SchemaVersion = "v1"

// Observation is one claim from one tool run about a potential security
// concern ("Smoke"). It carries no id, fingerprint, or ingestion time;
// those are Fireline core's to assign on receipt, never an adapter's to
// claim.
type Observation struct {
	SchemaVersion      string            `json:"schema_version"`
	Source             Source            `json:"source"`
	IdentityComponents map[string]string `json:"identity_components"`
	SeverityRaw        string            `json:"severity_raw"`
	RawPayload         json.RawMessage   `json:"raw_payload"`
	ObservedAt         string            `json:"observed_at,omitempty"` // RFC 3339, optional
}

// Source names the tool and rule that produced an Observation.
type Source struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
	RuleID      string `json:"rule_id"`
}

// Errors returned by Validate.
var (
	ErrWrongSchemaVersion = errors.New("observation: schema_version must be " + SchemaVersion)
	ErrEmptySourceTool    = errors.New("observation: source.tool must not be empty")
	ErrEmptyRuleID        = errors.New("observation: source.rule_id must not be empty")
	ErrNoIdentity         = errors.New("observation: at least one identity component is required")
	ErrEmptySeverityRaw   = errors.New("observation: severity_raw must not be empty")
	ErrEmptyRawPayload    = errors.New("observation: raw_payload must not be empty")
)

// New builds an Observation with SchemaVersion already set, so callers can't
// forget it.
func New(source Source, identityComponents map[string]string, severityRaw string, rawPayload json.RawMessage) Observation {
	return Observation{
		SchemaVersion:      SchemaVersion,
		Source:             source,
		IdentityComponents: identityComponents,
		SeverityRaw:        severityRaw,
		RawPayload:         rawPayload,
	}
}

// Validate checks the structural rules fireline-spec's
// observation.schema.json also encodes. See the package doc comment for why
// this isn't real JSON-Schema validation.
func (o Observation) Validate() error {
	if o.SchemaVersion != SchemaVersion {
		return ErrWrongSchemaVersion
	}
	if o.Source.Tool == "" {
		return ErrEmptySourceTool
	}
	if o.Source.RuleID == "" {
		return ErrEmptyRuleID
	}
	if len(o.IdentityComponents) == 0 {
		return ErrNoIdentity
	}
	if o.SeverityRaw == "" {
		return ErrEmptySeverityRaw
	}
	if len(o.RawPayload) == 0 {
		return ErrEmptyRawPayload
	}
	return nil
}
