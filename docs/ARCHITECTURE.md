# ARCHITECTURE — from sdist to finding

A digest for humans, not a code dump (SOUNDS VERY AI-ISH): what happens to an sdist, in order, and which crate owns each step. Decisions referenced as ADR-nnn are in `DECISIONS.md`; the safety guarantees and the threat model behind them are in `SAFETY.md`.
## The pipeline in one paragraph

An sdist (`.tar.gz`) or an already-extracted directory goes in. Its sha256 and the current
ruleset version form a cache key; a hit returns the stored report unchanged. On a miss the
archive is extracted with path-traversal protection, every `.py`, `setup.py` and
`pyproject.toml` is parsed by tree-sitter and lowered into an owned AST, the ASTs are joined
into one **package graph** (symbol table, call graph, data-flow graph, phase map), the rule
catalogue asks the graph for source→sink reachability paths, each path becomes a finding
whose evidence *is* the path, findings are scored deterministically into a package verdict,
and the resulting `ScanReport` is stored in the cache and rendered as JSON, SARIF or text. No
package code is ever executed, and nothing in the package can cause a network request.

## Stages and the crate that owns each

| # | Stage | Crate | Input → output | Design ground |
|---|---|---|---|---|
| 0 | Fetch (optional) | `fetch` | `PackageRef` → sdist on disk | Only from the official index, only behind the `network` feature (invariant 5). |
| 1 | Identify | `parse` | file → `Sha256Digest` | Invariant 6; ADR-017. |
| 2 | Cache lookup | `cache` | `CacheKey` → `Option<ScanReport>` | ADR-017. |
| 3 | Extract | `parse` | sdist → `ExtractedTree` (files under a fresh temp root) | Tar-slip safe; symlinks, absolute paths and `..` entries rejected; size and count limits. |
| 4 | Parse | `parse` | `SourceFile` → `Ast` (arena of `AstNode`) | ADR-014. `rayon` over files here: parsing is embarrassingly parallel. |
| 5 | Symbols | `graph` | `[Ast]` → `SymbolTable` | Import aliasing and scope chains; ADR-005 steps 1–4. |
| 6 | Call graph | `graph` | `SymbolTable` → `CallGraph` | ADR-004; any-callee fallback ADR-005 step 5; dynamic markers step 7. |
| 7 | Data flow | `graph` | `[Ast] + CallGraph` → `DataFlowGraph` | ADR-004; taint-preserving transforms ADR-006; literal folding ADR-018. |
| 8 | Phases | `graph` | `CallGraph` → `PhaseMap` | ADR-008: roots from `setup.py`, `cmdclass`, `pyproject` backend, `__init__.py`. |
| 9 | Reachability | `graph` | queries → `Vec<ReachabilityPath>` | Data paths (DFG) and control paths (CG); deterministic order. |
| 10 | Rules | `rules` | `PackageGraph + Catalogue` → `Vec<Finding>` | RULES.md; one query per rule; confidence and phase attached. |
| 11 | Score | `rules` | `[Finding]` → `RiskScore`, `Verdict` | ADR-010. |
| 12 | Report | `core` | everything → `ScanReport` | Serialisable, versioned schema. |
| 13 | Cache store | `cache` | `CacheKey + ScanReport` → () | Never overwritten. |
| 14 | Output | `cli` | `ScanReport` → json / sarif / text; exit code | Same code path for binary and Python (`run()`). |
| 15 | Python API | `py` | path(s) → JSON string → dict in the shim | ADR-013; `scan_many` releases the GIL and uses `rayon` across packages. |

Stages 5–9 are the analysis proper and carry the design weight; the rest is orchestration.

## Crate boundaries and what may depend on what

```
core  ←  parse  ←  graph  ←  rules  ←  cli  ←  py
core  ←  cache  ←  cli
core  ←  fetch  ←  cli
```

- `core` depends on `serde`, `thiserror`, `petgraph` (ADR-015) and nothing else in the
  workspace. It holds every domain type of the analyser, the error enums that cross crate
  boundaries, and the configuration struct. It has no I/O.
- `parse` is the only crate that knows tree-sitter, `tar`, `flate2` and the file system.
- `graph` is pure: it takes ASTs and returns graphs and paths. No I/O, no configuration files, no network. This is what makes it unit-testable from inline source strings.
- `rules` is data plus one evaluator. The catalogue is a static table.
- `cache` is the only crate that knows `redb`.
- `fetch` is the only crate that may ever open a socket, and only with the feature on.
- `cli` orchestrates and renders. `scan_one` and `scan_many` live here and are the only two
  functions the Python crate calls.
- `py` marshals. It contains no analysis logic and never will (ADR-013).

## Parallelism boundary

`WHY here and not elsewhere:` two `rayon` scopes and nothing else. (1) Inside one package:
files are parsed in parallel (stage 4) because parsing is independent per file; the graph
stages are sequential because they need all files. (2) Across packages: `scan_many` runs
`scan_one` per package in a `rayon` pool, which is where the evaluation harness gets its
throughput. The cache is opened once and shared; `redb` handles concurrent readers and
serialises writers. No async anywhere in the analysis path; `tokio` exists only inside
`fetch`.

## Safety invariants

The threat model, the five guarantees, where each is enforced and which test proves it are in
`SAFETY.md`. The short version is that the guarantees are structural rather than defensive.
`phylaxis` does not check that it will not execute  a package – it has no execution primitive 
to reach for. No crate but `fetch` links an HTTP client, so nothing in `parse`, `graph` or 
`rules` could make a request even if it tried. That is enforced by the dependency graph above.

## Data that crosses stage boundaries

- `SourceFile { rel_path, bytes, kind: Python | SetupPy | PyprojectToml }`
- `Ast { file: FileId, nodes: Vec<AstNode> }`, `AstNode { kind, span, text_range, children }`
- `PackageGraph { symbols, call_graph, dfg, phases }`
- `ReachabilityPath { kind, steps }` → `Evidence` → `Finding` → `ScanReport`

Everything after `Ast` is `Send`, which is what allows stage 4 to be parallel and stage 15 to
release the GIL.

## What is deliberately absent

- No type inference (ADR-005), no points-to analysis.
- No dynamic analysis, no sandbox.
- No wheel or binary analysis (invariant 2); a wheel-only distribution yields a report with
  `skipped: NotAnSdist`.
- No dependency-graph tier yet (phase 3): `DependencyGraph` and `BlastRadius` exist as types
  in `core` so the report schema is stable, with construction left as a phase-3 task.

## Keeping this document current

When a stage changes shape, update the table row here in the same change. This document and
`DECISIONS.md` are how the design is read without reading the crates; they are only worth that if they are true. (IS THIS EVEN FOR HUMAN TO READ?)
