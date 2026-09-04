# FABLE-BRIEF — architecture session brief (Fable 5.1)

> This is not a "write the program" task. It is a **"close the decisions and lay the
> scaffolding"** task. The expensive thinking is yours. Grinding code to green is not.

---

## 0. Role and boundaries — read first, do not violate

**You are the senior architect on this project.** You close decisions, write the
constitution, and lay scaffolding so that the implementers (Opus / Sonnet) write code
afterwards **without inventing rules of their own**. Your value is in judgement, not in
the number of lines you edit.

### Model roles on this project

| Model | Owns |
|---|---|
| **Fable (you)** | Design decisions, architecture, domain model, rule catalogue, evaluation protocol, thesis outline, task breakdown, code scaffolding, test contracts. |
| **Opus** | Implementing the hard algorithms behind your design: graph construction, taint reachability, the evaluation runs. Also explaining tricky Rust to the author. |
| **Sonnet** | Making tests pass, clearing clippy, fixtures, plumbing, mechanical refactors, drafting thesis subchapters from your outline. |
| **Human** | Anything requiring the department's methodology handbook, the defence narrative, final judgement on scope. |

### ✅ Your work

- Read the input material (map in section 1) and turn it into project memory.
- Close the open decisions (section 3) — this is the main event.
- Write the constitution documents: architecture, domain model, rule catalogue,
  evaluation protocol, thesis outline, task breakdown (section 4).
- Lay the code scaffolding: types, signatures, `impl` skeletons, doc comments (section 5).
- Write the behaviour contracts as tests — **without ever running them** (section 6).
- Hand off explicitly via `phylax/HANDOFF.md` (section 7).

### ⛔ What you never do — not once, not even if "one more try will fix it"

| Forbidden | Why | Whose job |
|---|---|---|
| `cargo test` loops, driving tests to green | cheap mechanical iteration | Sonnet |
| Clearing `cargo clippy` warnings | same | Sonnet |
| Chasing borrow-checker errors past the budget below | same | Sonnet / Opus |
| Writing full bodies of non-trivial functions | implementation of your own design | Opus / Sonnet |
| **Teaching Rust** — explaining lifetimes, borrows, how `rayon` parallelism works | the author is learning Rust, but that tutoring is cheap to produce | Opus / Sonnet |
| Fixtures, corpora, snapshot files | implementation | Sonnet |
| Dependency version hunting, build fixing | mechanics — the workspace is already green | Sonnet |
| Downloading datasets, running scans, measuring | a separate stage, not architectural | Opus |
| Refactoring "to make it prettier" | produces no artefact | nobody, now |
| Spawning subagents | pays twice for the same context | — |

Note the distinction on comments: you **do** write `// WHY:` comments that record *design
rationale* — why this boundary, why this over-approximation, why this cache key. You **do
not** write comments that *teach Rust semantics*. If a piece of scaffolding needs a Rust
explanation for the author, leave `// EXPLAIN(opus): ...` and move on.

### Compilation budget — the single exception

The scaffolding must compile, otherwise there is nothing to hand over. So:

- `cargo check --workspace --all-targets` — **at most 3 invocations for the session**;
- at most **2 rounds of fixes** after them;
- if it still does not compile, **stop**, paste the errors into `phylax/HANDOFF.md` under
  "Does not compile, fix this first", and move on.

No `cargo test` and no `cargo clippy` in this session at all. The workspace was handed to
you compiling clean under `cargo fmt`, `cargo clippy -D warnings` and `cargo check`; if
you break that, note it in the handoff rather than grinding on it.

### Cost discipline

- One deep pass instead of a dozen small ones. Do not re-read what you have read.
- Read `thesis/research/CITATIONS.md`, **not** `selected_papers.json`, and do not grep
  through ПР2 — the index has been compiled for you.
- Do not open `PR1-...txt`: it is a draft of ПР2, the difference is cosmetic.
- Batch your questions to the human. At most 2 rounds per session, ≤ 4 questions each.

---

## 1. Material map: what to read, in what order

Read in exactly this order — each file builds on the previous.

| # | File | Size | What to take from it |
|---|---|---|---|
| 1 | `phylax/CLAUDE.md` | ~7 KB | **The immutable invariants** — determinism, scope, reachability-not-co-occurrence, taxonomy, safety, cache keying — plus the crate stack, workspace layout and session cycle. This is law. |
| 2 | `phylax/PROJECT.md` | ~7 KB | Goal / object / subject, scientific novelty, the two-tier architecture, baselines (Aura, GuardDog), evaluation methodology, phases 1–4. |
| 3 | `thesis/research/README.md` | ~3 KB | What the source base contains and the `[N]` numbering invariant. |
| 4 | `thesis/research/CITATIONS.md` | ~56 KB | 33 publications: `[N]` → metadata + field (SSC/GDM/MCD/MLC/SDA) + study type (ER/VR/SP) + abstract. **The only citation source.** |
| 5 | `thesis/research/PR2-systematic-mapping-final.txt` (Ukrainian) | ~81 KB | The submitted systematic mapping study. Read **selectively**: sections 1, 2.1–2.3, 4, 5 (the answers to RQ1–RQ3) and the reference list. Skip section 3 (abstracts) — it is already in `CITATIONS.md`. |
| 6 | `thesis/research/claude-desktop-init-response.md` (Ukrainian) | ~9 KB | Context behind earlier decisions: why Rust, why sha256 as cache key, writing by diffs, pandoc / ДСТУ. Reference, not instruction. |

The Ukrainian files stay Ukrainian on purpose — they feed the thesis text, which is
written in Ukrainian. Your own output documents are in **English**, except the thesis
material in `thesis/` (outline, notes, chapter drafts), which is **Ukrainian**.

### Where you are working

The project is **two sibling directories, each its own git repository**, under a plain
container folder that is not itself a repository:

```
dep-graph-analyzer/            container, no git
├── phylax/     [git repo]     the code half — paths below are relative to the container
│   ├── Cargo.toml             workspace, 7 members, versions pinned
│   ├── rust-toolchain.toml    stable + rustfmt + clippy
│   ├── crates/{core,parse,graph,rules,cache,fetch,cli}/
│   │                          each with Cargo.toml wired up and an empty lib.rs
│   ├── docs/                  code digests — you create these
│   ├── fixtures/{benign,malicious}/  and tests/   (both empty)
│   └── CLAUDE.md · PROJECT.md · FABLE-BRIEF.md   (TASKS.md: you create it)
└── thesis/     [git repo]     the written thesis — a SEPARATE repository
    ├── research/              input material, already populated, read-only
    ├── notes/ · assets/       empty, you create the structure
    └── OUTLINE.md · DSTU.md · CLAUDE.md   — you create these
```

The code repository stays **code-only**; that is why the thesis is a separate repository
rather than a subdirectory. When you write to `thesis/`, you are writing into the other
repository — that is intended. Never add thesis material to the `phylax` repo, and never
add code to the `thesis` repo.

Sessions run with the **container folder** as the working directory, so both halves are
reachable by the paths shown above.

Do not commit. The author decides when to commit, in both repositories.

The workspace is built and green: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`
and `cargo check` all pass, with and without the `network` feature. Dependency versions are
already resolved against crates.io. Treat them as given; if a genuine design need calls for
a different crate, record it in `phylax/docs/DECISIONS.md` rather than going version-hunting.

---

## 2. Step zero: project memory

The memory directory already exists:
`C:\Users\demya\.claude\projects\D--Projects-dep-graph-analyzer\memory\`

After reading, write **6–10 memory files** there (one fact per file, with
`name` / `description` / `metadata.type` frontmatter, and a pointer line in `MEMORY.md`).

Record only what is **not visible from the code and git**:

- `project` — thesis topic, goal / object / subject; practice deadline **2026-10-19**;
  the practice stage requires chapters **up to and including testing**; phases 1–4 and
  where we currently are.
- `project` — the `[N]` ↔ `selected_papers.json` ↔ ПР2 numbering invariant.
- `project` — the source-base gap (section 3.2 of this brief).
- `project` — the repository split into code half and thesis half (section 4.1).
- `feedback` — the model role split from section 0. **Why:** an expensive model must not
  be spent on mechanical iteration. **How to apply:** see the forbidden table in
  `phylax/FABLE-BRIEF.md`.
- `user` — the author is learning Rust as the project goes, so non-obvious Rust needs a
  short explanation — but that explanation is written by **Opus or Sonnet**, not by you.
- `project` — the thesis is written **iteratively by cheaper models**, one subchapter at
  a time, which is why `thesis/OUTLINE.md` must be granular and self-contained.

Do not duplicate into memory anything already written in `phylax/CLAUDE.md`.

---

## 3. Step one: close the decisions (the main work of the session)

Each decision below is its own entry in `phylax/docs/DECISIONS.md` (date, context, alternatives
considered, choice, consequences). Do not skip the alternatives — they are what later
turns into thesis prose.

### 3.1 The "ML vs determinism" contradiction — most important

ПР2 framed RQ2 as *"which machine learning models perform best?"* and its answer in §5.3
concluded that GNNs and hybrid ensembles win. Yet `phylax/CLAUDE.md` invariant #1 **forbids ML
outright**.

This is not an error, it is a deliberate pivot — but **it has to be defended in writing**,
because it is the first question at the defence. Build the justification out of those same
33 sources: reproducibility and determinism of the verdict, no need for a training set
(or for labelling one), explainability of a finding to a human auditor, immunity to data
drift, no adversarial evasion via training-set poisoning, and fitness for CI/CD. Show that
the work **does not ignore** ПР2's conclusion but deliberately picks a different point in
the trade-off space — and state the price of that choice honestly.

Output: an entry in `phylax/docs/DECISIONS.md` plus a draft subchapter in `thesis/notes/`.

### 3.2 The source-base gap

The 33 publications from ПР2 cover the **domain**, but not one of them is what the
implementation actually rests on: no Backstabber's Knife Collection (taxonomy), no Datadog
malicious-software-packages-dataset (evaluation set), no Aura and no GuardDog (baselines).

Produce `thesis/research/SOURCES-TO-ADD.md`: the sources that must be added to the thesis
bibliography, each with its role and its place in the thesis structure. **Invent nothing:**
where you do not know a publication's exact details, mark it `⚠ NEEDS VERIFICATION` and
describe what to look for. Do not use the network.

### 3.3 Reconciling the formulations

ПР2 states the subject as *"approaches, methods, models and tools for detecting potentially
malicious **or vulnerable** packages"*, while `phylax/PROJECT.md` narrows it to deterministic graph
analysis of malicious code. Vulnerabilities (CVEs in dependencies) are a different problem.
Produce one reconciled statement of goal / object / subject / novelty that contradicts
neither the already-submitted ПР2 nor the invariants. If the gap cannot be closed by
rewording, escalate it to the human.

### 3.4 The detection model

- What exactly is a **node** in the package graph — a call? a function definition? a
  module? — and why.
- How calls are resolved by name without type inference. ПР2 §5.4 names type inference and
  late binding as the central difficulty of Python analysis; that is your citable ground
  for conservative approximation.
- What a "source" and a "sink" are, and whether a "sanitiser" exists in this model at all.
- The over-approximation rule: under uncertainty, do we err toward false positives or
  false negatives — and why.
- How `install-time` context (`setup.py`, build backend) raises the weight of a finding.
- The shape of `Evidence`: a finding must present a **path** through the graph, not a fact.

### 3.5 The evaluation protocol — fix it before any code is written

Metrics, dataset splits, exactly how an FP is counted, how Aura and GuardDog get run over
the same set, and — separately — the **design of the ablation experiment**,
co-occurrence versus reachability, because that is what demonstrates the scientific
novelty. Specify the results table format so that `phylax/docs/RESULTS.md` can be filled in
mechanically.

### 3.6 Thesis structure

The practice stage ends **2026-10-19** and requires chapters **up to and including
testing**. The department's methodology handbook is **not** in the repository.

Propose the structure of chapters 1–4 as a **hypothesis**, marking every item that depends
on the handbook with `⚠ NEEDS HANDBOOK CHECK`. **Do not invent ДСТУ numbers, font sizes,
margins or formatting rules.** Instead create `thesis/DSTU.md` with empty slots and a list
of what the human has to fill in.

---

## 4. Step two: the constitution documents

### 4.1 The two halves, and the bridge between them

The split already exists on disk (see section 1). What does not yet exist is the **thesis
half's own structure**, which you create:

```
thesis/
├─ CLAUDE.md         rules for writing sessions (section 4.4)
├─ OUTLINE.md        chapter/subchapter structure with per-item status (section 4.5)
├─ DSTU.md           formatting slots, filled by the human (section 3.6)
├─ research/         input material — already populated, never edited
├─ notes/            code → text notes (section 4.4)
└─ assets/           diagrams (.mmd), tables — as separate files
```

The boundary rule, in both directions: **code never imports from or writes into
`thesis/`, and thesis sessions never read raw Rust** — only `phylax/docs/*.md` and
`thesis/notes/*.md`. That bridge is what makes it possible to write the thesis later
without pulling thousands of lines of Rust into context, and it is the reason the digests
in `phylax/docs/` have to be genuinely readable rather than a code dump.

Because these are two separate repositories, the bridge is enforced by the split rather
than by discipline alone — but a path reference can still cross it, so keep every
reference from a thesis document pointing at `phylax/docs/` or `notes/`, never at `phylax/crates/`.

### 4.2 Documents you write

| File | Contents |
|---|---|
| `phylax/docs/ARCHITECTURE.md` | Data flow from sdist to finding, crate boundaries, who owns what, why it is shaped this way. With a diagram (mermaid, in `thesis/assets/`). |
| `phylax/docs/DECISIONS.md` | Every decision from section 3, in ADR form. |
| `phylax/docs/RULES.md` | **The rule catalogue.** Per rule: identifier, what it catches, its technique in the Backstabber attack tree, execution phase, sources/sinks, expected FPs, how it will be verified. |
| `phylax/docs/EVALUATION.md` | The evaluation protocol and ablation design (section 3.5). |
| `phylax/docs/PROGRESS.md` | Session state: done / next / open questions. Update at the end. |
| `phylax/TASKS.md` | Task breakdown, each tagged with its owner — `[FABLE]` / `[OPUS]` / `[SONNET]` / `[HUMAN]` — with ordering, dependencies, and a schedule across the 45 days to 2026-10-19. |
| `thesis/OUTLINE.md` | Chapters 1–4 broken down to subchapter level (section 4.5). |
| `phylax/HANDOFF.md` | Section 7. |

`phylax/CLAUDE.md` already carries the model roles, the repository split and the bridge rule, so
you do not need to add them. Amend it only if a decision from section 3 changes a **stable**
rule there — and keep it stable: volatile detail belongs in `phylax/TASKS.md` or
`phylax/docs/PROGRESS.md`.

### 4.3 The domain model — the whole thesis rests on this

A dedicated file, `thesis/notes/domain-model.md`, written in **Ukrainian** (it becomes
thesis text directly). The author has said explicitly that the dissertation text will lean
on an **enumeration of the domain models**. So this is not a class diagram but a
**numbered enumeration of entities**, where each has:

1. its Ukrainian and English name;
2. a rigorous one-paragraph definition;
3. attributes and relationships to other entities;
4. a **citation anchor `[N]`** wherever the concept is drawn from the literature (call
   graphs and AST features have support in the SDA / GDM clusters);
5. the corresponding Rust type in `phylax/crates/core` — so that text and code cannot drift apart.

Minimum coverage (extend as needed):
`Package`, `Distribution`, `SourceFile`, `AstNode`, `Symbol`, `CallGraph`,
`DataFlowGraph`, `TaintSource`, `TaintSink`, `ReachabilityPath`, `Rule`,
`AttackTechnique` (Backstabber), `ExecutionPhase` (install / import / runtime),
`Finding`, `Evidence`, `Severity`, `RiskScore`, `DependencyGraph`, `BlastRadius`,
`CacheKey`, `RulesetVersion`, `ScanReport`.

### 4.4 Code → text notes

Create `thesis/notes/` and a **template**, `thesis/notes/_TEMPLATE.md`, which Opus/Sonnet
fill in after each completed task. One note per task. The template must demand exactly four
things and nothing more:

1. **What was done** — 3–5 sentences in plain language, no function names;
2. **What was decided and why** — the alternative rejected, and the reason;
3. **Where it goes in the thesis** — a specific subchapter id from `thesis/OUTLINE.md`;
4. **Citations** — the `[N]` numbers backing the decision (or "none").

In `thesis/CLAUDE.md`, write the drafting rules: **edit in place, touch only the requested
subchapter, never regenerate a whole chapter.**

### 4.5 The outline must be written for cheap models

The thesis is drafted **iteratively, by lower-tier models, one subchapter at a time**.
That constrains `thesis/OUTLINE.md` more than it might appear. Every subchapter entry must
be self-contained enough that a model which has read *only that entry* plus the files it
names can draft the text without further research. So each entry carries:

- a stable id (e.g. `2.3.1`) and a title;
- status: `todo` / `draft` / `done`;
- target length in pages, so a drafting model knows the scale;
- **the exact input files** that feed it — which `thesis/notes/*.md`, which `phylax/docs/*.md`,
  which figures in `thesis/assets/`;
- **the citation numbers `[N]`** admissible in that subchapter;
- one sentence stating the claim the subchapter must land.

A drafting model must never have to decide *what* a subchapter argues — only *how to
phrase it*. Deciding the claim is your job, here, now.

---

## 5. Step three: code scaffolding

Only after the documents above exist.

**What "scaffolding" means here:**

- In `core`: **all** the domain-model types from section 4.3, fully written out — structs,
  enums, newtypes, field types. This is not stub work; the types *are* the design.
- In the other crates: public function signatures, `impl` blocks with method signatures,
  `///` doc comments stating the contract, preconditions and invariants, and `todo!("...")`
  bodies naming what will go there.
- Error variants (`thiserror`) fully enumerated — they are part of the design too.
- `// WHY:` comments where a decision is non-obvious: tar-slip-safe extraction, the cache
  key, the `rayon` parallelism boundary. Design rationale only — not Rust tutoring.
- Safety invariants visible in the code as guard comments: package code is **never
  executed**; extraction is path-traversal safe; network access only to the official PyPI
  index and only behind the `network` feature flag.

**What must not be in the scaffolding:** working parsing logic, graph construction, taint
traversal, redb access, network calls. That is not your stage.

---

## 6. Step four: behaviour contracts as tests — written, never run

This is the most valuable handover artefact after the decisions, because it is what pins
down *behaviour* rather than *shape*. Types say what the data looks like; tests say what
the code must do.

**Write tests. Do not run them. Ever, this session.**

- Unit tests next to the code (`#[cfg(test)] mod tests`) for per-crate contracts;
  integration tests in `phylax/tests/` for end-to-end scan behaviour.
- Each test is a **specification**: a name that states the required behaviour, a comment
  giving the rationale, and concrete `assert!`/`assert_eq!` calls against the intended API.
- Tests will not pass — they call `todo!()` bodies and will panic. **That is correct and
  expected.** Do not "fix" it. Sonnet turns them green later; a red test suite is the
  specification handed to it.
- They must still **type-check**, since that is what proves your API design is coherent.
  `cargo check --workspace --all-targets` covers test code and falls under the section 0
  budget. That check is allowed; `cargo test` is not.
- Where a fixture is needed, do not build it — reference it by intended path
  (`phylax/fixtures/malicious/setup_py_exfil/`) and describe what it must contain in a comment.
  Sonnet builds fixtures.
- Mark anything that cannot compile yet with `#[ignore]` plus a comment explaining why,
  rather than deleting it.

Prioritise contracts in this order, and stop when the session runs short rather than
thinning all of them out:

1. **Safety invariants** — path traversal is rejected; no package code path ever executes;
   the network is unreachable without the feature flag. These are non-negotiable, so they
   are specified first.
2. **The novelty claim** — reachability finds a source→sink path; mere co-occurrence in a
   file does *not* produce a finding. This pair of tests is the executable form of the
   thesis contribution; write it carefully, it will be quoted in the text.
3. **Cache keying** — the same sha256 with the same ruleset version hits; a ruleset bump
   misses.
4. **Rule catalogue** — one test per rule in `phylax/docs/RULES.md`, positive and negative.
5. Everything else.

Record in `thesis/notes/` that the test suite doubles as the formal behaviour
specification — that is a point worth making in the testing chapter.

---

## 7. Handover

`phylax/HANDOFF.md` at the root is the last thing you write:

1. What this session produced (as a file list).
2. **What the next agent does first** — one concrete task from `phylax/TASKS.md`.
3. If the scaffolding does not compile: the exact errors and your hypothesis.
4. Expected state of the test suite: how many tests exist, that they are red by design,
   and which ones Sonnet should turn green first.
5. Questions left open for the human.
6. The rule for later sessions: *read `phylax/docs/PROGRESS.md` → `phylax/TASKS.md` → your task. The
   rules are already written — do not invent new ones; if a rule is missing, file a
   request in `phylax/docs/DECISIONS.md` rather than a decision in the code.*

---

## 8. Order and definition of done

```
memory → decisions (3) → documents (4) → scaffolding (5) → test contracts (6) → handoff (7)
```

Do not jump ahead. Code written before the decisions are closed has to be rewritten, and
that is precisely the expense this session exists to avoid.

**The session is done when:** every document in section 4 exists and contains no
placeholder prose (other than explicit `⚠ NEEDS HANDBOOK CHECK` markers), the scaffolding
is in place, the test contracts are written, `phylax/HANDOFF.md` exists, and `phylax/docs/PROGRESS.md`
is updated.

**If time or context runs short**, sacrifice in this order: scaffolding (5) first, then
test contracts (6), and never the decisions (3) or the documents (4). Cheaper models can
write code from good documents; nobody else can close the decisions for you.
