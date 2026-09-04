# fixtures

Minimal hand-written sample packages used by the integration tests.

- `benign/` -- packages that must NOT be flagged. These are the false-positive
  guard: every one of them exercises a pattern that looks suspicious in
  isolation but is legitimate in context.
- `malicious/` -- packages that MUST be flagged, each carrying exactly one
  attack technique from the Backstabber attack tree so that a failure points at
  a single rule.

These are fixtures, not corpora. The labelled evaluation sets (Datadog,
Backstabber) are downloaded separately and never committed -- see `.gitignore`.

**Safety:** fixture payloads are inert by construction. Nothing here is ever
executed; the analyser only reads source text.
