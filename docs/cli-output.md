# Why the adapter CLIs only write to stdout

Each `cmd/adapter/<tool>` binary reads a report or export file (`--file`,
or stdin if omitted) and writes a JSON array of Observations to stdout.
None of them call an ingest endpoint, because fireline-core doesn't have
one yet. Stdout is the whole job for now. Piping the output into
`fireline import --file <path>` proves one Observation's round trip
through storage, but doesn't exercise a real multi-Observation ingest path.

Building a fake HTTP target to make an adapter feel "integrated" would be
a worse signal than the current state: there's nothing to send to yet, and
stdout says so honestly.
