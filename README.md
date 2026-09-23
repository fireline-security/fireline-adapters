# fireline-adapters

Scanner adapters stay outside Fireline core (D-11): each importer talks to
core through a versioned JSON contract, defined canonically in
[fireline-spec](https://github.com/fireline-security/fireline-spec), so
untrusted, format-specific parsing is isolated and contributors can write an
adapter in whatever language suits the source tool, without core needing a
plugin ABI.

This repo holds `observation` (a typed, dependency-free Go mirror of
fireline-spec's Observation contract) plus four prototype adapters
(`gitleaks`, `trivy`, `aikido`, and `semgrep`) that convert a real tool's
report into Observation JSON. They're intentionally small and read-only:
each is a `Convert`/`ConvertReport` (or `ConvertExport`) function plus a
CLI that reads a report file (or stdin) and prints a JSON array of
Observations to stdout. See "What the adapters do (and don't) prove" below
before treating them as more than that.

## Using `observation`

```go
import "github.com/fireline-security/fireline-adapters/observation"

obs := observation.New(
	observation.Source{Tool: "trivy", RuleID: "CVE-2024-12345"},
	map[string]string{"package": "openssl", "version": "3.0.1"},
	"HIGH",
	rawFinding, // json.RawMessage: the original tool-output fragment
)
if err := obs.Validate(); err != nil {
	// ...
}
data, err := json.Marshal(obs)
```

## The four adapters

**`gitleaks`** converts a `gitleaks detect --report-format json` report.
**`trivy`** converts a `trivy <target> --format json` report. **`aikido`**
converts a response from Aikido Security's "Export all issues" API,
modeled against
[Aikido's real, published API reference](https://apidocs.aikido.dev/reference/exportissues).
**`semgrep`** converts a `semgrep scan --json` report, modeled against
[Semgrep's published JSON output docs](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif).

See `docs/severity-handling.md` for how each adapter's severity vocabulary
is handled, and `docs/aikido/issue-mapping.md` for Aikido's
identity-mapping trade-off.

Try any of them against its bundled sample report:

```sh
go run ./cmd/adapter/gitleaks --file gitleaks/testdata/sample-report.json
go run ./cmd/adapter/trivy --file trivy/testdata/sample-report.json
go run ./cmd/adapter/aikido --file aikido/testdata/sample-issues.json
go run ./cmd/adapter/semgrep --file semgrep/testdata/sample-report.json
```

## What the adapters do (and don't) prove

They prove the Observation contract's shape holds up against real tools of
genuinely different character, and that `identity_components` being a
free-form map (rather than a fixed schema per source type) works for all
four. They do **not** prove an end-to-end integration; see
`docs/cli-output.md` for why the CLIs only print to stdout.

## Adding a new adapter

1. Read fireline-spec's `schemas/v1/observation.schema.json`: that's the
   contract you're emitting, regardless of language. `gitleaks/gitleaks.go`,
   `trivy/trivy.go`, `aikido/aikido.go`, and `semgrep/semgrep.go` are worked
   examples of mapping a real tool's fields onto it, including the kind of
   judgment call (Gitleaks' severity, Aikido's general-purpose identity
   mapping) that mapping can force.
2. If you're writing Go, `observation.New` + `Validate` gets you a
   conforming value with minimal ceremony. In another language, build the
   equivalent JSON object by hand against the schema.
3. Check your output against fireline-spec's fixture suite
   (`fixtures/v1/observation/`) as you go.

## Testing

```sh
task test
```

No external services, no Docker: this repo has zero dependencies beyond
the Go standard library.
