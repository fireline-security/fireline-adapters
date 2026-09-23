// Package observation is fireline-adapters' hand-kept mirror of
// fireline-spec's schemas/v1/observation.schema.json, the wire contract a
// scanner adapter emits. It gives an adapter written in Go a typed,
// dependency-free way to build a conforming Observation.
//
// See docs/observation/validation-scope.md for why Validate() isn't real
// JSON-Schema validation.
package observation
