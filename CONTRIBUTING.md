# Contributing to fireline-adapters

## Dev setup

Requires Go 1.26+. No external services needed.

```sh
task build
task test
```

## Adding a scanner adapter

See the README's "Adding a new adapter" section. In short: your adapter's
job is to produce JSON matching fireline-spec's
`schemas/v1/observation.schema.json`; the language and structure of your
adapter code is otherwise up to you.

## Code style

`task lint` runs `gofmt`, `go vet`, and `golangci-lint` (config in
`.golangci.yml`).

## Commit messages

Describe the *why*, not just the *what*: the diff already shows what
changed.

## Code comments

`docs/` is the source of truth for design rationale, trade-offs, and scope
decisions (use AGENTS.md/README.md for a repo with nothing in `docs/` yet).
A code comment should point to it, not restate it: `// see docs/<file>.md
for why.`

A doc comment says what a function or type does, in one to three lines.
Add local *why* only for something the code can't already show: an edge
case, a library quirk. Never a design decision or scope caveat; that
belongs in docs/. Keep it plain: no "X, not Y" framing, no "deliberately,"
no hedges like "it's worth noting," and no em dashes.
