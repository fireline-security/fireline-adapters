# Aikido's identity mapping

The `Issue` type in `aikido/aikido.go` was modeled from Aikido's real,
published API reference (https://apidocs.aikido.dev/reference/exportissues),
not guessed.

Aikido is a different shape of adapter problem than Gitleaks or Trivy: it's
an aggregator, not a single-purpose scanner. One "Export all issues" call
returns findings across many categories (SCA/open_source, leaked secrets,
SAST, cloud posture, IaC, container, EOL packages, and more), each with a
different subset of populated fields.

Rather than a per-category switch building a bespoke identity for each
`Type`, `identityComponents` takes the simpler approach of including
whatever relevant fields Aikido populated and skipping what it didn't.
This is a reasonable default for a prototype, not its final shape. A more
polished adapter might special-case identity composition per `Type` for
tighter `identity_components`.

This package only converts an already-exported JSON file; it doesn't call
Aikido's API itself. Doing that needs an OAuth2 client-credentials token
exchange (POST to Aikido's token endpoint, then a Bearer token on the
actual request) and token refresh handling. That isn't built here, for the
same reason the other adapters don't call a live ingest endpoint: proving
the mapping doesn't require it.
