# CLAUDE.md — phylax

> Working name `phylax` (Greek, "guardian"). Rename freely — change the line below and the
> crate names.
>
> **phylax** is a deterministic static analyser that detects malicious Python packages on
> PyPI by the data-flow and call graph inside a package. Written in Rust.
> Master's thesis project. Rust is being learned along the way — explain non-obvious decisions.

References (read as needed): @docs/ARCHITECTURE.md, @docs/DECISIONS.md, @docs/RULES.md,
@docs/EVALUATION.md, @docs/RESULTS.md, @docs/PROGRESS.md, @TASKS.md

---

## Immutable invariants (never violate)

1. **Determinism.** No ML training and no collection of training sets. Labelled datasets
   (Datadog, Backstabber) are used EXCLUSIVELY for evaluation: precision / recall / FP.
2. **Scope.** Analyse only Python source inside an sdist (`.tar.gz`): `setup.py`,
   `pyproject.toml`, `.py`. Compiled extensions (`.so`/`.pyd`, C/C++/Rust in a wheel) are
   out of scope.
3. **The signal is reachability, not co-occurrence.** A package is marked suspicious when
   the graph contains a real path from a source (env, files, `~/.ssh`) to a sink (network,
   `exec`/`eval` over decoded data). The mere presence of both in one file is a weaker signal.
4. **Taxonomy.** Every rule maps to a technique and an execution phase from the attack trees
   of Backstabber's Knife Collection (Ohm et al., 2020). Rules are not words off the top of
   one's head.
5. **SAFETY — critical.** NEVER execute the code of an analysed package: do not run
   `setup.py`, do not import modules, do not invoke `pip`. Archive extraction must be
   protected against path traversal (tar-slip / zip-slip). The network is permitted ONLY for
   downloading packages from the official PyPI index; no network action may ever be prompted
   by the contents of a package.
6. **The cache is immutable by construction.** Cache key = `sha256` of the package file +
   ruleset version. Files on PyPI are immutable (a filename is never reassigned), so the
   result for a given `sha256` can be cached forever. Changing the rules increments the
   ruleset version, which invalidates old entries.

---

## Repository layout — two halves, two repositories

This directory (`phylax/`) is the **code repository, and it stays code-only.**

The thesis lives in a sibling directory with its own separate git repository:

```
dep-graph-analyzer/          plain container folder, not a repository
├── phylax/    [git]         THIS repo — code only
└── thesis/    [git]         separate repo — thesis text, research material, notes
```

The bridge rule, in both directions:

- Code never imports from, or writes into, `../thesis/`.
- Thesis sessions never read raw Rust. They read `phylax/docs/*.md` and
  `../thesis/notes/*.md` only.

That bridge is what makes it possible to write the thesis later without pulling thousands
of lines of Rust into context. It only works if the digests below are kept current.

**Open Claude Code sessions at the container root** (`dep-graph-analyzer/`), not inside
either half — that keeps both halves reachable and keeps project memory on one path.

---

## Model roles

Do not spend an expensive model on cheap iteration, and do not let a cheap model invent
rules that should have been decided.

| Model | Owns |
|---|---|
| **Fable** | Design decisions, architecture, domain model, rule catalogue, evaluation protocol, thesis outline, task breakdown, scaffolding, test contracts. Does not debug, does not run tests, does not clear clippy. |
| **Opus** | The hard algorithms: graph construction, taint reachability, evaluation runs. Also explains tricky Rust to the author. |
| **Sonnet** | Turning tests green, clearing clippy, fixtures, plumbing, mechanical refactors, drafting thesis subchapters from the outline. |
| **Human** | Anything needing the department's methodology handbook, the defence narrative, final calls on scope. |

If a rule you need is missing, file a request in `docs/DECISIONS.md` — do not put the
decision straight into the code.

---

## Stack and crates

- Parsing: `tree-sitter` + `tree-sitter-python` (to start — resilient to broken and
  obfuscated code). Later, optionally `ruff_python_parser` for a fuller AST, but only by a
  recorded decision in DECISIONS.md.
- Graphs: `petgraph`.
- Parallelism: `rayon` (data-parallel over files and packages). `tokio` + `reqwest` are for
  downloading packages only, and only when the `fetch` crate's `network` feature is enabled.
  CPU analysis never blocks on async.
- Archives: `tar` + `flate2`.
- Cache: `redb` (embedded KV, pure Rust).
- CLI: `clap`. Output: `serde` + `serde_json` (SARIF later, for CI/CD).
- Errors: `thiserror` in library crates, `anyhow` in the binary. No `.unwrap()`/`.expect()`
  in library code (exceptions: tests, and documented invariants carrying a comment saying why).
- Logging: `tracing`.
- Tests: `#[test]` + `insta` (snapshots) + integration tests over fixtures.

Versions are pinned in `[workspace.dependencies]` in the root `Cargo.toml` and were
resolved against crates.io, not guessed. Do not go version-hunting; if a design need calls
for a different crate, record it in `docs/DECISIONS.md` first.

---

## Commands (all three must be green before calling anything "done")

```
cargo fmt
cargo clippy --all-targets -- -D warnings   # zero warnings
cargo test
cargo run -- scan <path-to-sdist-or-dir>     # manual check
```

---

## Code structure (Cargo workspace)

```
crates/
  core      — types, taxonomy (Backstabber), config, shared structures
  parse     — sdist → AST (tree-sitter); safe extraction
  graph     — AST → call graph + data flow; source→sink taint reachability
  rules     — sources / sinks / capabilities per the taxonomy; the rule engine
  cache     — redb; key = sha256 + ruleset_version
  fetch     — downloading packages from PyPI (optional feature)
  cli       — clap; orchestration; output (json / sarif)
docs/       — ARCHITECTURE.md, DECISIONS.md, RULES.md, EVALUATION.md, RESULTS.md,
              PROGRESS.md (living documents)
fixtures/   — small sample packages: benign/ and malicious/ (for tests)
tests/      — integration tests
```

---

## Working cycle (important for pausing and resuming between sessions)

- Work on ONE task from `TASKS.md`. Mark it done ONLY after the tests pass.
- Small commits with meaningful messages. Ask before committing — the author decides when.
- **Update `docs/PROGRESS.md` at the end of every session:** what was done, what is next,
  open questions. The next session reads it first — that is the memory between sessions.
- **Keep `docs/ARCHITECTURE.md` and `docs/RESULTS.md` current as you go.** These, not the
  raw code, are the source material for the thesis. Keep them human-readable.
- Do not expand scope without recording the decision in `docs/DECISIONS.md` (date + reason
  + alternatives).
- Explain non-obvious Rust (borrows/lifetimes, concurrency, `unsafe` if it ever appears) in
  short comments and in DECISIONS.md — this is a learning project. That explaining is Opus's
  and Sonnet's job, not Fable's.

## What NOT to do

- Do not add ML training.
- Do not make binary/wheel analysis the main path.
- Do not execute analysed code under any circumstances.
- Do not put volatile details in CLAUDE.md — they belong in TASKS.md / PROGRESS.md.
