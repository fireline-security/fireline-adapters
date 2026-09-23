# AGENTS.md

## Purpose

Scanner adapters stay outside Fireline core by design: each importer talks
to core through a versioned JSON contract (defined canonically in
fireline-spec), not a Go import of core internals or a plugin ABI. This repo
holds `observation` (a typed, dependency-free Go mirror of that contract)
plus four prototype adapters, `gitleaks`, `trivy`, `aikido`, and `semgrep`:
each a `Convert`/`ConvertReport` (or `ConvertExport`) function plus a CLI
that reads a real report and prints Observation JSON to stdout. They exist
to prove the contract's shape against real tool output, not as production
integrations. Read README.md's "What the adapters do (and don't) prove"
before assuming more coverage or more polish than that.

## What to avoid

- **Don't add adapter-specific logic to the `observation` package.** It's a
  shared, generic mirror of the wire contract; a Semgrep-shaped helper, an
  Aikido-shaped helper, etc. belongs in that adapter's own package
  (`semgrep/`, `aikido/`, ...), not folded into this shared type.
- **Don't add a JSON-Schema validation dependency here without discussion.**
  `Validate()` does structural Go-level checks on purpose, not real
  JSON-Schema validation against fireline-spec's schema. See
  `docs/observation/validation-scope.md` for why, and when that's worth
  revisiting. Not something to "fix" casually in the meantime.
- **Don't treat `gitleaks`/`trivy`/`aikido`/`semgrep` as production-ready,
  and don't add more scanner coverage without checking scope first.** They're
  prototypes: read-only, print-to-stdout, no retry/logging/config story. In
  particular, `gitleaks`'s hardcoded `severity_raw: "HIGH"` (Gitleaks has no
  native severity) is a placeholder product decision, not a considered
  one; see `docs/severity-handling.md`. Don't quietly change it, and don't
  copy that pattern into a new adapter without flagging that it's a
  judgment call someone should sign off on.
- **Don't build out Aikido's OAuth2 client-credentials flow here without
  checking scope first.** `aikido/aikido.go` only converts an
  already-exported issues JSON file; it doesn't call Aikido's API. Adding
  the token exchange, refresh handling, and pagination a real integration
  needs is real scope (auth secrets, retry/backoff, rate limits), not
  something to bolt on incidentally while touching something else in this
  package.
- **Don't special-case `aikido`'s `identityComponents` per issue `Type`
  without discussion.** It includes whatever fields Aikido populated rather
  than switching on `Type`; see `docs/aikido/issue-mapping.md` for the
  trade-off. Tightening it per category is reasonable future work, not an
  obvious cleanup to do in passing.
- **Don't wire these adapters to an HTTP call or a "fake" ingest target.**
  fireline-core still has no ingest endpoint; stdout is the honest output
  for now. Building a fake target to make an adapter feel "integrated"
  would be a worse signal than admitting there's nothing to send to yet.
- **Don't invent a plugin ABI or import fireline-core's internal packages.**
  The JSON contract is the only interface between an adapter and core
  (that's the entire reason adapters live in a separate repo).
- **Don't let this package's copy of the contract drift silently.** If
  fireline-spec's `schemas/v1/observation.schema.json` changes, update
  `observation.go`'s fields and `Validate()` in the same change you'd make
  anywhere else that hand-copies it (see fireline-core's `AGENTS.md` for its
  own copy).

## What to ensure

- Anything built here (and any future adapter) produces JSON that validates
  against fireline-spec's `schemas/v1/observation.schema.json`; check
  against the real fixtures in that repo, not just this package's own tests.
- A new adapter follows the established shape: a `Convert`/`ConvertReport`
  pair in its own top-level package (not under `internal/`, so it stays
  importable), a `testdata/sample-*.json` the tests read from (doubles as a
  manual demo input via the CLI's `--file` flag), and a thin
  `cmd/adapter/<tool>/main.go` that reads `--file` or stdin and prints a
  JSON array to stdout. See `gitleaks/`, `trivy/`, `aikido/`, and `semgrep/`
  for the library pattern; `cmd/adapter/*` for the CLI one.
- If a new adapter's source tool's fields aren't things you have direct,
  verified knowledge of (an internal tool, a newer or less common commercial
  platform), check its real docs or a real sample report before modeling its
  fields; don't invent a plausible-looking schema. `aikido/aikido.go`'s
  `Issue` type was built by reading Aikido's actual published API reference,
  not guessed; say so in the package doc comment the way it does, so the
  next reader knows how much to trust the field list.
- Prefer a directory hierarchy over a hyphenated compound name for a new
  package or command: `cmd/adapter/<tool>/`, not `cmd/<tool>-adapter/`.
  This applies repo-wide, not just under `cmd/`.
- `task test` and `task lint` (`gofmt`, `go vet`, `golangci-lint`) are clean
  before a change is done.
- Keep this repo's dependency footprint minimal. `observation` is
  stdlib-only today; adding a dependency should be a conscious choice in
  its own change, not incidental to an unrelated one.
