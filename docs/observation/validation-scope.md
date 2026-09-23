# Why `Validate()` isn't JSON-Schema validation

`observation.Validate()` does structural Go-level checks. It does not
validate against fireline-spec's real JSON Schema, and this package
doesn't embed a copy of it either.

Embedding a copy would be a third copy of the schema across three repos
(fireline-spec has the original, fireline-core's CLI has a fixture copy),
compounding drift risk for a package whose only consumer right now is
itself. The structural checks are sufficient to prove this SDK's shape for
a walking skeleton.

Once a second adapter language or a real scanner adapter exists, embedding
and validating against the real schema (or generating this type from it)
becomes worth doing. Until then, this is a gap to close later, not a
completed part of the package.
