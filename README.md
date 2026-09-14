# phylaxis

A deterministic static analyser that looks for malicious code in Python packages published to
PyPI. It asks whether a dangerous capability is actually **reachable** from an untrusted
source inside the package — not merely whether the two happen to appear in the same file.

> **Status: in development.** The domain model is landing block by block; the analysis
> pipeline is scaffolded and not yet implemented. The tool does not run end to end today.
> See [Status](#status) before trying anything.

## The idea

Most open scanners for this problem decide by **co-occurrence**: a file mentions
`base64.b64decode` and also mentions `subprocess`, so the file is flagged. That is cheap and
catches real attacks, but it fires on any package that happens to do both for unrelated
reasons, and a reviewer has to read the file to find out which.

phylaxis builds a call graph and a data-flow graph over the whole package, then asks a
different question: **is there a path** from a source the attacker controls to a sink that
does something dangerous? A finding is only produced when such a path exists, and the
evidence attached to the finding *is* that path — the steps, with file and line, from source
to sink. There is nothing to reconstruct by hand.

Two further things follow from having the graph:

- **Execution phase matters.** Code reachable from `setup.py` or a `pyproject.toml` build
  backend runs at `pip install` time, before anyone imports anything. The same code reachable
  only from a rarely-called function is a much weaker signal, and is scored as such.
- **Imprecision is visible, not hidden.** Python cannot be resolved exactly without type
  inference, which is an open research problem. Where resolution runs out, phylaxis
  over-approximates — it adds a lower-confidence edge rather than dropping one — and a
  finding inherits the weakest confidence along its path. A missing edge is a silent false
  negative; an ambiguous edge is a finding a reviewer dismisses in seconds.

No machine learning is involved, deliberately. The reasoning, with the trade-off stated
honestly in both directions, is in [`docs/DECISIONS.md`](docs/DECISIONS.md) (ADR-001).

## Safety

**phylaxis never executes, imports or evaluates the package it analyses.** That is a
structural property, not a defensive one: there is no code path in the workspace that runs
package code, so there is nothing to bypass. Archives are extracted with path-traversal
protection and hard limits on entry count and size, so a decompression bomb fails closed
rather than exhausting memory. Network access lives behind an off-by-default feature flag and
reaches only the official index.

The threat model, the guarantees, the test that proves each one, and an explicit list of what
is **not** guaranteed are in [`docs/SAFETY.md`](docs/SAFETY.md).

## Scope

**In scope.** Python source in an sdist (`.tar.gz`) — `setup.py`, `pyproject.toml` and `.py`
modules; the intra-package call and data-flow graph; a fixed, versioned catalogue of rules;
evaluation against labelled datasets.

**Out of scope, and why.** Compiled extensions (`.so`, `.pyd`) need binary analysis, a
separate discipline — and empirically the malicious payload on PyPI arrives as source.
Dynamic analysis and sandboxed execution are excluded by the safety property above. Model
training is excluded by ADR-001. A compiled package can still appear as a *node* in the
dependency graph through its metadata; only its code is not analysed.

## Status

| Part | State |
|---|---|
| Domain model (`core`) | landing block by block — identity, inputs, syntax and symbols are in |
| Safe extraction, parsing (`parse`) | scaffolded, not implemented |
| Graphs and reachability (`graph`) | scaffolded, not implemented |
| Rule catalogue and engine (`rules`) | scaffolded, not implemented |
| CLI (`cli`), Python bindings (`py`) | scaffolded, not implemented |

The test suite is written ahead of the implementation, so a red test is the specification for
work not yet done rather than a regression. At present **49 of 129 tests pass**, and the
remaining 80 are red by design. `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo fmt --check` are clean.

Code is committed in blocks, and a block only lands once it is green *and* has been read and
understood by the author — so the history reflects the real pace of the work rather than the
moment a file was generated.

## Building

Requires a Rust toolchain at 1.85 or newer (edition 2024).

```sh
git clone https://github.com/demianchuk-o/phylaxis.git
cd phylaxis

cargo build --workspace
cargo test --workspace      # 49 pass, 80 red by design — see Status
```

Once the pipeline is implemented the tool is distributed as a wheel — `pip install phylaxis`,
giving both an importable module and a `phylaxis` console command. It is built with maturin
and PyO3 against the stable abi3 ABI, so one wheel per platform covers every CPython from 3.9.

## Layout

```
crates/core     domain model: packages, files, ASTs, symbols, graphs, findings
crates/parse    sha256, safe extraction, tree-sitter parsing
crates/graph    symbol table, call graph, data flow, phases, reachability
crates/rules    the rule catalogue and the engine that evaluates it
crates/cache    result cache keyed by file digest and ruleset version
crates/fetch    optional, feature-gated download from the official index
crates/cli      command line interface and output rendering
crates/py       Python bindings
docs/           the design documents — read ARCHITECTURE.md first
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the pipeline stage by stage, and which
  crate owns each step. Start here.
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — the decision records, with the alternatives that
  were rejected and why.
- [`docs/SAFETY.md`](docs/SAFETY.md) — threat model and guarantees.
- [`docs/RULES.md`](docs/RULES.md) — the rule catalogue.
- [`docs/EVALUATION.md`](docs/EVALUATION.md) — how the tool is measured, including the
  ablation that isolates what reachability contributes over co-occurrence.

These are written to be read with nothing but this repository to hand.

## Licence

MIT. See [`LICENSE`](LICENSE).
