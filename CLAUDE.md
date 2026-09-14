# CLAUDE.md — phylaxis

> Name: **phylaxis**, from Greek φύλαξις — "a guarding, a watching". (The shorter φύλαξ,
> *phylax* = "guard", was the earlier working name but is already taken on PyPI.) The
> distribution ships under this name on PyPI, so it is now fixed, not a working title.
>
> **phylaxis** is a deterministic static analyser that detects malicious Python packages on
> PyPI by the data-flow and call graph inside a package. Written in Rust.
> Master's thesis project. Rust is being learned along the way — explain non-obvious decisions.

References (read as needed): @docs/ARCHITECTURE.md, @docs/DECISIONS.md, @docs/SAFETY.md,
@docs/RULES.md, @docs/EVALUATION.md, @docs/RESULTS.md, @../notes/TASKS.md,
@../notes/PROGRESS.md

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

This directory (`phylaxis/`) is the **code repository, and it stays code-only.**

The thesis lives in a sibling directory with its own separate git repository:

```
dep-graph-analyzer/          plain container folder, not a repository
├── phylaxis/  [git]         THIS repo — code only
├── thesis/    [git]         separate repo — thesis text, research material, notes
└── notes/     [no git]      working files: TASKS, PROGRESS, HANDOFF, PROJECT, FABLE-BRIEF,
                             COMMIT-PLAN. Read and written freely; never committed anywhere.
```

**Why `notes/` is outside both repositories.** Those files are addressed to the models and
to the author mid-flight: a task board with model owner tags, a session log, a handoff, an
architecture brief. They are true today and stale next week, and they say nothing to a
reader of the published tool. Keeping them out of the tree means there is no decision to
make later about what to prune, and no `.gitignore` entry to explain. What is durable —
the decisions, the architecture, the rule catalogue, the evaluation protocol — lives in
`docs/` and is committed.

The trade is that `notes/` is not backed up by either repository. Nothing in it is
irreplaceable: the decisions it refers to are in `docs/DECISIONS.md`, which is.

The bridge rule, in both directions:

- Code never imports from, or writes into, `../thesis/`.
- Thesis sessions never read raw Rust. They read `phylaxis/docs/*.md` and
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
| **Opus** | The hard algorithms: graph construction, taint reachability, evaluation runs. Any task where a wrong implementation could still pass its test. Explains Rust to the author, and runs the reading sessions before a commit. |
| **Sonnet** | Work a failing test fully specifies: fixtures, plumbing, mechanical refactors, clearing clippy, drafting thesis subchapters from the outline. |
| **Human** | Anything needing the department's methodology handbook, the defence narrative, final calls on scope. |

The line between Opus and Sonnet is **not** cost — it is whether a plausible-looking wrong
answer would be caught. Give Sonnet the tasks where the test is the whole specification and
a mistake is loud. Keep for Opus the tasks where the code can be green and still wrong:
anything touching the graphs, the reachability predicate, the safety guards in `extract`,
or the evaluation numbers. When in doubt about which side a task falls on, it is Opus's;
an hour of debugging a subtly wrong graph costs more than the model did.

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
  core      — types, taxonomy (Backstabber), config, shared structures; depends on petgraph (ADR-015)
  parse     — sdist → AST (tree-sitter); safe extraction
  graph     — AST → call graph + data flow; source→sink taint reachability
  rules     — sources / sinks / capabilities per the taxonomy; the rule engine
  cache     — redb; key = sha256 + ruleset_version
  fetch     — downloading packages from PyPI (optional feature)
  cli       — clap; orchestration; output (json / sarif). A LIBRARY plus a thin binary:
              both the native binary and the Python console script call `run()`.
  py        — PyO3 bindings; built into the wheel by maturin. Marshalling only, no logic.
docs/       — ARCHITECTURE.md, DECISIONS.md, RULES.md, EVALUATION.md, RESULTS.md
              (living documents, committed)
fixtures/   — small sample packages: benign/ and malicious/ (for tests)
tests/      — README only: end-to-end tests live in crates/cli/tests/ (virtual workspace, ADR-016)
python/     — thin importable shim over the compiled module (`phylaxis/__init__.py`)
pyproject.toml — maturin build backend; the wheel's metadata
```

## Distribution

The tool ships **as a prebuilt wheel on PyPI**: `pip install phylaxis` must give both an
importable `phylaxis` module and a `phylaxis` console command. Its audience already lives
in the Python ecosystem, and the evaluation harness over the labelled datasets is easier to
drive from Python than from a foreign binary.

- Built by `maturin`, PyO3 with **abi3** (`abi3-py39`), so one wheel per platform covers
  every CPython ≥ 3.9 instead of one per interpreter version.
- `cargo` stays the build tool for development; `maturin build` is only for releases.
- Because of this, CLI logic must live in `crates/cli/src/lib.rs`, never in `main.rs` —
  the binary and the Python entry point must run the same code path.

Note for the thesis: the tool is distributed as a compiled artefact while invariant 2 puts
compiled extensions out of *analysis* scope. That is consistent — the scope statement is
about what phylaxis reads, not about how phylaxis is shipped — but it is exactly the kind
of thing worth pre-empting in writing, since a reviewer may well ask.

---

## Working cycle (important for pausing and resuming between sessions)

- Work on ONE task from `../notes/TASKS.md`. Mark it done ONLY after the tests pass.
- **The reading gate.** Code is not committed because it is green. It is committed after the
  author has read that block, been walked through it, and answered questions on it well
  enough that they could defend it. Green tests are the precondition; the author's
  understanding is the gate. The order of blocks is fixed in `../notes/COMMIT-PLAN.md`.
- Commit messages describe the block, not the session. Ask before committing — the author
  decides when. No AI attribution trailers (`Co-Authored-By`, `Claude-Session`); this is a
  standing decision, not something to re-request.
- **Update `../notes/PROGRESS.md` at the end of every session:** what was done, what is next,
  open questions. The next session reads it first — that is the memory between sessions.
- **Keep `docs/ARCHITECTURE.md` and `docs/RESULTS.md` current as you go.** These, not the
  raw code, are how the design is read without reading the crates.
- **Everything in `docs/` is written for whoever clones this repository** (ADR-019). It must
  be readable with only this repo in hand: prior work cited inline by author and year, no
  chapter tags, no `[N]` indices, no model role names, nothing about the dissertation. The
  same goes for source comments — code explains the code. `docs/SAFETY.md` sets the register.
- **`EXPLAIN(...)` markers are scaffolding, not documentation.** Fable leaves them where an
  explanation is owed to the author. Whoever implements that code writes the explanation and
  deletes the marker; a block is not committed with one still in it.
- Do not expand scope without recording the decision in `docs/DECISIONS.md` (date + reason
  + alternatives).
- Explain non-obvious Rust (borrows/lifetimes, concurrency, `unsafe` if it ever appears) in
  short comments and in DECISIONS.md — this is a learning project. That explaining is Opus's
  and Sonnet's job, not Fable's.

## What NOT to do

- Do not add ML training.
- Do not make binary/wheel analysis the main path.
- Do not execute analysed code under any circumstances.
- Do not put volatile details in CLAUDE.md — they belong in `../notes/TASKS.md` or
  `../notes/PROGRESS.md`.
