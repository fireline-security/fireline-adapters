# Severity handling across adapters

Each adapter's `severity_raw` comes from a different vocabulary. None of
them are normalized into a shared scale here: that's Fireline's job, not
an adapter's (D-04). Source truth stays visible as each tool reported it.

| Adapter | Source vocabulary | How it's derived |
|---|---|---|
| `gitleaks` | none | Gitleaks reports no severity at all: every finding is "a secret was found." The adapter hardcodes `severity_raw: "HIGH"` for all of them (`gitleaks.defaultSeverity`). This is a placeholder product decision, not a considered one: don't quietly change it, and don't copy the pattern into a new adapter without flagging it as a judgment call to sign off on. |
| `trivy` | `UNKNOWN`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL` | Passed through verbatim as `severity_raw`. |
| `semgrep` | `WARNING`/`ERROR` | Passed through verbatim as `severity_raw`. |
| `aikido` | `critical`/`high`/`medium`/`low` | Passed through verbatim as `severity_raw`. |

If Fireline later wants finer-grained severity per Gitleaks rule (e.g.
treating a low-confidence generic-api-key match differently from a
confirmed AWS key), that's a product decision to make explicitly, not
something to infer from the rule ID.
