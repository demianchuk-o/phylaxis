# DECISIONS — architecture decision records

Every entry: date, context, alternatives considered, choice, consequences. The alternatives
are not decoration — the reason a rejected option was rejected is the part that stops it being
re-proposed six months later. Entries are appended, never rewritten; a reversed decision gets
a new entry superseding the old one, and numbering has gaps where entries were withdrawn.

If you need a rule that is not here, add a request under **Open requests** at the bottom and
proceed on the most conservative reading. Do not decide in the code.

Prior work is cited inline by author and year.

---

## ADR-001 — Deterministic rules instead of machine learning

**Date:** 2026-09-05. **Status:** accepted.

### Context

A survey of the malware-detection literature points one way: graph neural networks and hybrid
ensembles — a GNN over the program graph plus a random forest over lexical features, as in
PyComm (Zhou et al., 2021) at 0.955 reported accuracy — are the best-performing published
approach. phylaxis does not take it, and invariant 1 in `CLAUDE.md` rules out ML training
outright. "Why not machine learning?" is the first question anyone asks of a detection tool,
so the choice is argued below from that same literature rather than asserted.

### Alternatives considered

1. **Follow the literature: train a GNN or hybrid classifier** on the Datadog and Backstabber
   sets. Rejected, see below.
2. **Hybrid: deterministic graph extraction feeding a small learned classifier** (the SootFX
   pattern of SootFX (Karakaya et al., 2021)). Rejected: it inherits every ML cost
   listed below while adding a second component to explain, and the labelled sets would have
   to be split between training and evaluation, which halves the evaluation set.
3. **Deterministic rules over the same program graph, with reachability as the decision
   predicate.** Chosen.

### Choice

The published pipeline is kept intact up to the graph: static parsing to an AST, from which
data-flow and call-graph structure is built. The **final stage is replaced**: instead of
feeding the enriched graph to a neural classifier, the tool evaluates a fixed catalogue of
source→sink reachability rules over it. The work therefore does not ignore the literature's
conclusion; it takes the same intermediate representation and chooses a different point in
the trade-off space.

### Justification, source by source

| Property | Why it matters for a package scanner | Support in the 33 sources |
|---|---|---|
| **Reproducibility of the verdict** | A registry, a CI gate or an auditor must be able to re-run the scan and get the same answer; a verdict that changes with a retrained model cannot be cited in an incident report. | (Cai et al., 2023) shows graph-based inference depending on sampled neighbourhoods and introducing sampling bias; (Çakir et al., 2024) shows GNN community detection underperforming deterministic Louvain on the same dependency graphs. |
| **No training set, no labelling** | Labelled malicious packages are scarce and skewed toward one campaign type; whatever is used for training cannot be used for evaluation. | (Mir et al., 2021) needed 5 382 projects and 869 K annotations for a learned type inferencer; (Karakaya et al., 2021) documents feature extractors intertwined with the studies that trained them and not reusable. |
| **Explainability to a human auditor** | The consumer of a finding is a maintainer or a security team who must decide in seconds; a probability is not a reason. | (Huang et al., 2024) states outright that existing tools "require huge manual confirmation effort due to high false positives and binary detection results" and answers with explicit behaviour graphs, not scores. |
| **Immunity to data drift** | Attack campaigns on PyPI change every few months; a classifier trained on last year's campaign degrades silently. | (Alevizos et al., 2024) reports LLM-based scanners failing on "new and unfamiliar data patterns"; (Jeng et al., 2024) motivates its GNN by the "dynamic tactics of cyber-criminals", i.e. concedes the drift problem it then must chase. |
| **No adversarial evasion through the model** | An attacker who can publish packages can also poison a training set or craft adversarial examples. | (Zheng et al., 2024) is entirely about GNN malware detectors being "vulnerable to adversarial examples" and proposes masking as a mitigation, confirming the attack surface exists. A rule has no gradient to follow. |
| **Fitness for CI/CD** | A scanner in a pipeline must be fast, offline, and dependency-free; a model needs weights, a runtime and versioning of both. | (Cankar et al., 2023) positions SAST tools as the design-time component of DevSecOps; (Tamanna et al., 2024) shows that supply-chain frameworks fail on adoption complexity; (Mukherjee et al., 2022) demonstrates deterministic static rules reaching 83–85 % developer acceptance in a commercial service. |
| **Structure survives obfuscation** | Call structure stays largely fixed under obfuscation and dynamic loading, where lexical features do not. | (Huang et al., 2024), (Negrini et al., 2023) (a CFG abstraction detecting env-variable theft deterministically). |

### The price, stated honestly

- **Recall ceiling.** A rule catalogue finds only what it was written to find. A novel
  behaviour with no source→sink shape in the catalogue is missed. ML generalises; rules do not.
- **Predefined sensitive-API lists.** (Huang et al., 2024) criticises tools that "only consider a predefined
  set of sensitive APIs". This tool is exactly such a tool. Mitigation: the lists are
  versioned (`RulesetVersion`), auditable and cited to the taxonomy; and the reachability
  requirement is what separates it from the co-occurrence tools (Huang et al., 2024) criticises.
- **Maintenance.** Each new technique costs a rule, a fixture pair and a ruleset bump.
- **Conservative approximation.** Without type inference (ADR-005) the graph over-approximates
  calls, which costs precision on dynamic code. The evaluation measures this cost directly.

### Consequences

- The claim phylaxis makes is an *improvement of the detection method* — reachability over
  co-occurrence — not a new classifier.
- The labelled datasets are used for evaluation only; ADR-011 splits off a small development
  set so that rule constants are never tuned on the test set.

---

## ADR-004 — What a node is: two graphs over one symbol table

**Date:** 2026-09-05. **Status:** accepted.

### Context

"Node" had three candidate meanings: a call site, a function definition, or a module. The
answer decides what a path is, and therefore what `Evidence` shows.

### Alternatives considered

1. **Module as node.** Too coarse: every rule collapses to file-level co-occurrence, which is
   precisely the baseline we claim to improve on.
2. **Call site as node.** Every call becomes a node; the graph is large and the notion of
   "who can reach whom" is lost because a call site has no body.
3. **Single heterogeneous graph** mixing definitions, expressions and variables. Expressive
   but hard to explain and hard to keep deterministic in traversal order.
4. **Two graphs sharing one symbol table.** Chosen.

### Choice

The **package graph** is `PackageGraph = SymbolTable + CallGraph + DataFlowGraph + PhaseMap`.

- **CallGraph.** Nodes are *callable definitions*: every `def`, method, lambda (given a
  synthetic name), plus one synthetic `<module>` node per source file for module-level code,
  plus one *external* node per fully-qualified external name (`os.environ.get`,
  `requests.post`) that is called but not defined in the package. Edges are *call sites*,
  annotated with the location of the call. `WHY:` a definition is the unit of behaviour that
  can be reached; the `<module>` node is the home of install-time and import-time code, which
  is where ADR-008 anchors phases; external nodes are where sources and sinks attach.
- **DataFlowGraph.** Nodes are *symbol occurrences*: a definition or use of a variable,
  parameter, return value, attribute or the result of a call expression, each with a span.
  Edges are taint-carrying transfers: assignment, argument passing (actual→formal, following
  the call graph), return (callee return→call-expression result), and the taint-preserving
  transforms listed in ADR-006.
- The **SymbolTable** binds names to definitions per scope and holds the import alias table
  per module. Both graphs index into it, which is what keeps them consistent.
- **Determinism of traversal:** node and edge indices are assigned in a canonical order
  (files sorted by relative path, then source order), so two scans of the same sdist produce
  byte-identical reports. This is a tested contract.

### Consequences

- `ReachabilityPath` (ADR-009) is a sequence of DFG nodes (data reachability) or of call
  edges (control reachability), never a mixture.
- Both graph types live in `phylaxis-core` (ADR-015) so that the domain model has one home
  and the analysis crates share real types rather than mirrored copies.

---

## ADR-005 — Name resolution without type inference

**Date:** 2026-09-05. **Status:** accepted.

### Context

Type inference and late binding are the central difficulty of static analysis
for Python, citing (Zhao et al., 2023), (Venkatesh et al., 2023), (Mukherjee et al., 2022), (Rak-amnouykit et al., 2023). A sound points-to analysis for Python is an open problem
((Zhao et al., 2023): "creating a sound, or a soundy, analysis for Python remains an open problem"). The tool
needs call edges anyway.

### Alternatives considered

1. **Full type inference / points-to** (the layered strategy of (Mukherjee et al., 2022), PyCG-style assignment
   graphs as in (Venkatesh et al., 2023)). Most precise, but weeks of work and still unsound on dynamic code; out of
   reach within the project, and not what this tool is claiming.
2. **Names only, no resolution** — treat every call as external by its literal text.
   Trivial, but then `helper()` never connects to `def helper`, and intra-package paths, which
   are the entire point, disappear.
3. **Lexical resolution with a conservative any-callee fallback.** Chosen.

### Choice

Resolution proceeds in this fixed order and stops at the first match:

1. **Import aliasing.** Every module's `import x as y`, `from x import a as b`, relative
   imports and `__import__`/`importlib.import_module` **with a string literal** populate an
   alias table. Dotted names are canonicalised through it, so `r.post(...)` after
   `import requests as r` becomes `requests.post`.
2. **Bare-name calls** resolve through the lexical scope chain (local → enclosing → module →
   builtins). A name bound to a `def` in the package resolves to that definition.
3. **Qualified intra-package calls** (`pkg.mod.func()`, `from .mod import func`) resolve to
   the definition in the named module.
4. **`self.method()` / `cls.method()`** resolve within the enclosing class and its
   lexically-visible bases; if the base is external, fall through to 6.
5. **Attribute calls on an unknown receiver** (`obj.run()`) resolve to **every** definition
   named `run` in the package (any-callee over-approximation) **and** to an external
   `<unknown>.run` node. The resulting edges carry `Confidence::Ambiguous`.
6. **Anything else** is an external node under its canonical dotted name.
7. **Dynamic constructs.** `getattr(m, "name")()` with a literal folds to `m.name`;
   `getattr` with a non-literal, `exec`-built names, and `globals()[...]()` become an external
   `<dynamic>` node and additionally set the `DynamicDispatch` capability flag on the calling
   definition, which rules may use as an obfuscation signal.

`WHY:` with type inference unavailable, the analysis must
choose between missing edges (silent false negatives) and adding ambiguous edges (visible,
lower-confidence findings). ADR-007 makes the choice explicit.

### Consequences

- `CallEdge` carries `Confidence` and `Finding` inherits the minimum confidence along its path.
- The error analysis in EVALUATION.md has a "resolution gap" category so the cost of this
  approximation is measured, not guessed.

---

## ADR-006 — Sources, sinks, taint-preserving transforms, and no sanitiser

**Date:** 2026-09-05. **Status:** accepted.

### Context

Classic taint analysis (web vulnerabilities) has sources (user input), sinks (SQL, HTML) and
sanitisers (escaping) that neutralise taint. The question was whether that triad transfers.

### Alternatives considered

1. **Import the classic triad including sanitisers**, e.g. treat encryption or hashing as a
   sanitiser because the secret is "no longer readable". Rejected: an attacker exfiltrating
   `~/.ssh/id_rsa` over TLS or after `base64` has lost nothing; in this threat model no
   transformation of secret data makes its egress benign.
2. **Sources and sinks only, taint propagates through everything.** Simple but unbounded:
   `len(secret)` sent over the network would flag. Too many false positives.
3. **Sources, sinks and an enumerated set of taint-preserving transforms; no sanitiser.**
   Chosen.

### Choice

- A **`TaintSource`** is an external call or literal whose *result* carries data the attacker
  wants. Kinds: `Environment`, `SensitiveFile` (paths matched against a list: `~/.ssh`,
  `~/.aws`, `~/.netrc`, `~/.git-credentials`, browser profile and wallet directories,
  `/etc/passwd`, `.env` files), `SystemIdentity` (hostname, user name, platform, MAC address,
  public IP lookups), `UserInput` (clipboard, keystrokes), `NetworkResponse` (the body of an
  HTTP response or socket read: a *code* source for droppers), `DecodedLiteral` (the result of
  decoding a string literal: a code source for obfuscated payloads), `SuspiciousLiteral` (a
  URL not on the official index, a raw IP, a shell one-liner, a wallet address), and
  `PhaseRoot` (the synthetic install or import entry point, source of *control* for
  ADR-008's control reachability).
- A **`TaintSink`** is an external call whose *argument* is the dangerous consumer. Kinds:
  `NetworkEgress` (socket, http.client, urllib, requests, smtplib, ftplib, dns), `CodeExecution`
  (`exec`, `eval`, `compile`, `subprocess.*`, `os.system`, `os.popen`, `os.exec*`, `ctypes`,
  `pty.spawn`), `FileWrite` restricted to persistence locations (shell rc files, cron,
  autostart directories, `winreg` Run keys, site-packages `.pth` files), `DestructiveFs`
  (`shutil.rmtree`, `os.remove` loops over home or root), `ProcessControl` (`os.dup2` onto a
  socket, `os.fork` after connect: the reverse-shell shape).
- **Taint-preserving transforms** (edges in the DFG): string concatenation and formatting,
  `.encode/.decode`, `base64.*`, `binascii.*`, `codecs.*`, `zlib`, `gzip`, `bz2`, `lzma`,
  `json.dumps/loads`, `pickle`, `marshal`, `str.join/split/replace/translate`, slicing,
  `reversed`, `bytes/bytearray`, `chr/ord` chains, container construction (`[..]`, `{..}`,
  `dict(..)`) and element access, `os.path.*`, encryption from `cryptography`, `Crypto`,
  `Fernet`, `hashlib` (hashing a secret and sending the hash is still exfiltration for the
  purposes of credential stuffing). Everything not in the list **drops** taint.
- **There is no sanitiser.** The only edge that removes taint is the absence of a transform.
  `WHY:` the "attacker" is the code author; sanitisation is a defensive act and no defensive
  act exists in a payload. Encoding and encryption are recorded as an `obfuscated: bool`
  attribute on the path and *raise* severity.

### Consequences

- The source and sink lists are data in `phylaxis-rules` (`catalogue.rs`), versioned by
  `RulesetVersion`, and reproduced as a table in RULES.md.
- Length-of-path and transform-count are attributes of `Evidence` (auditor readability).

---

## ADR-007 — Over-approximation policy

**Date:** 2026-09-05. **Status:** accepted.

### Context

Under uncertainty (ADR-005 ambiguous callees, unknown receiver types, unmodelled transforms)
the analysis must lean one way. The headline metric is precision, which argues for leaning
toward silence; the threat model argues for leaning toward noise.

### Alternatives considered

1. **Under-approximate everywhere** (only fully resolved edges, only known transforms).
   Highest precision, but a false negative is invisible: nothing in the output tells the
   auditor that an edge was dropped, and the cost of an FN is a compromised host.
2. **Over-approximate everywhere and report everything.** Reproduces exactly the
   high-false-positive tools this work is reacting against.
3. **Over-approximate in the graph, be strict in the rule, and grade the report.** Chosen.

### Choice

- The **graph** errs toward **false positives**: ambiguous callees get edges, unknown
  receivers resolve to all candidates, unmodelled *containers* propagate taint.
- The **rule** is strict: a finding requires an actual path, never co-occurrence.
- The **report** grades: every path carries the minimum `Confidence` of its edges
  (`Resolved` = 1.0, `Ambiguous` = 0.6, `Dynamic` = 0.4), and the score (ADR-010) multiplies by
  it. Ambiguous findings are still *reported* because the auditor can see the path and reject
  it in seconds; they are ranked below resolved ones.
- Rationale in one line: **a wrong edge yields a visible path that a human can
  refute; a missing edge yields silence that nobody can audit.**

### Consequences

The ablation in EVALUATION.md reports precision at two operating points so that the cost of
the over-approximation is a number in RESULTS.md, not an assertion.

---

## ADR-008 — Execution phases and two kinds of reachability

**Date:** 2026-09-05. **Status:** accepted.

### Context

Backstabber's Knife Collection (Ohm et al., 2020) shows that most payloads run at **install**
time, some at **runtime** (subdivided into "on import" and "on specific call", possibly under
a condition). Invariant 3 says presence in a file is a weak signal; but a bare `urlopen()` in
`setup.py` is, empirically, one of the strongest signals there is. The model had to admit that
without breaking "finding = path".

### Alternatives considered

1. **Treat install-hook presence as its own rule** (as GuardDog's `cmd-overwrite` does).
   Rejected: it is not a path, and it fires on every package with a custom `install` command.
2. **Ignore phase; rely on data reachability only.** Rejected: loses the strongest empirical
   signal in the taxonomy and makes `setup.py` droppers without a data source invisible.
3. **Make the phase entry point a source of *control*, and define control reachability over
   the call graph.** Chosen.

### Choice

- `ExecutionPhase = { Install, Import, Runtime }`. The paper's execution attack tree names
  three lifecycle phases — *test cases*, *install scripts* and *runtime* — and has no separate
  import node. It gives `__init__.py`, invoked through an import statement, as the *Python
  example* of its `runtime` branch, and states that "the specifics of individual programming
  languages, package managers, etc. may easily be covered by refining this goal" (§4.3).
  `Import` is exactly that refinement, for one ecosystem, and is labelled as a refinement
  wherever it is reported. `WHY it earns its own phase:` module-level code in `__init__.py`
  runs on the first `import` with no call from the victim, which is a materially different
  exposure from code that runs only when something invokes it.
- **The `test cases` phase is deliberately out of scope**, so this enum covers two of the
  paper's three lifecycle phases plus the refinement of the third. `WHY:` the analysed
  artefact is an sdist and the modelled act is `pip install`, which builds and may import but
  never invokes a test runner. A test-time payload needs a maintainer or a CI job to run the
  suite — a different threat model with a different victim, the contributor rather than the
  downstream user. It is 1% of the paper's dataset. Recorded here so that the omission reads
  as a boundary rather than an oversight.
- The **PhaseMap** assigns a phase to every callable definition by reachability from
  **phase roots** in the call graph:
  - `Install` roots: `<module>` of `setup.py`; the `run` method of any class used as a
    `cmdclass` value (`install`, `develop`, `egg_info`, `build_py`, `bdist_*`, `sdist`);
    the module named by `[build-system] backend-path` / `build-backend` in `pyproject.toml`
    when it points inside the sdist; `setup_requires` hooks.
  - `Import` roots: `<module>` of every `__init__.py` and of every top-level module of the
    distribution's declared packages.
  - `Runtime`: everything else. A definition reachable from several roots takes the
    **strongest** phase (Install > Import > Runtime).
- Two kinds of reachability, both yielding a `ReachabilityPath`:
  - **Data reachability:** a DFG path from a `TaintSource` result to a `TaintSink` argument.
  - **Control reachability:** a call-graph path from a phase root (`PhaseRoot` source) to a
    definition that calls a `TaintSink`. Used by the `PHX-INS-*` rules only.
- **Weighting:** the phase of the definition containing the sink multiplies the score:
  `Install 1.0`, `Import 0.8`, `Runtime 0.5`. `WHY these numbers:` they encode the ordering
  from the taxonomy; they are constants, fixed here before any evaluation, and any change is
  recorded as a new ADR with the before/after measurement (ADR-011).
- A **conditional trigger** (the payload is guarded by an OS, hostname, environment or
  time check) is an attribute `conditional: bool` on the path, not a phase, mirroring
  Backstabber's separate "conditional execution" branch.

### Consequences

- The co-occurrence baseline for `PHX-INS-*` rules in the ablation is "sink present in a file
  that is an install file".
- `PhaseMap` construction is its own task; it needs `setup.py` `cmdclass` recognition, which is
  itself a name-resolution problem (ADR-005).

---

## ADR-009 — Evidence is a path

**Date:** 2026-09-05. **Status:** accepted.

### Context

Existing tools report a fact ("uses base64 and exec"). phylaxis requires that a finding
present a path through the graph.

### Alternatives considered

1. Evidence as a list of locations (fact-style). Rejected: indistinguishable from
   co-occurrence output; the auditor cannot tell whether the locations are connected.
2. Evidence as the full subgraph. Rejected: unreadable and non-deterministic to serialise.
3. **Evidence as an ordered path with typed steps.** Chosen.

### Choice

`Evidence { path: ReachabilityPath, phase, confidence, obfuscated, conditional, snippets }`
where `ReachabilityPath { kind: Data | Control, steps: Vec<PathStep> }` and
`PathStep { location, symbol, step_kind: Source | Transfer | Transform | Call | Return | Sink }`.
The constructor `Finding::new` **refuses** an empty path or a path whose first step is not a
`Source` or whose last step is not a `Sink`. That refusal is a unit test.

### Consequences

The SARIF `codeFlows` object maps one-to-one onto `ReachabilityPath`, which is why SARIF is a
cheap stretch goal (phase 3).

---

## ADR-010 — Risk score and verdict thresholds

**Date:** 2026-09-05. **Status:** accepted.

### Context

A deterministic score is needed to rank findings and to define "flagged" for the metrics.

### Alternatives considered

1. Binary flagged/not. Rejected: no ranking, no precision-recall curve, no way to compare
   operating points with Aura (which scores).
2. A learned weighting. Rejected by ADR-001.
3. **A fixed, documented formula.** Chosen.

### Choice

Per finding:
`score = severity_weight(rule) × phase_weight(phase) × confidence(path) × obfuscation_bonus`,
with `severity_weight: Critical 1.0, High 0.8, Medium 0.6, Low 0.4`, phase weights from
ADR-008, confidence from ADR-007, `obfuscation_bonus = 1.15 if obfuscated else 1.0`, clamped to
`[0, 1]`.

Per package: `risk = min(1, max_finding_score + 0.05 × (distinct_techniques − 1))`.

Verdict: `risk ≥ 0.70 → Malicious`, `0.40 ≤ risk < 0.70 → Suspicious`, `< 0.40 → Clean`.
"Flagged" in the metrics means `risk ≥ 0.40` at the primary operating point and `≥ 0.70` at
the strict one.

`WHY fixed now:` the constants must exist before the first evaluation run so that they cannot
be tuned on the test set. Any change is a new ADR with the development-set measurement that
motivated it (ADR-011).

### Consequences

`RiskScore` is a newtype over `f64` with the formula in one function in `phylaxis-core`
(`finding.rs`, alongside `Finding` itself so that a finding cannot be built without being
scored), covered by determinism tests.

---

## ADR-011 — Evaluation protocol and ablation

**Date:** 2026-09-05. **Status:** accepted. Full text: `EVALUATION.md`.

### Context

The protocol must be fixed before code exists so that the numbers cannot be shaped by the
implementation.

### Alternatives considered

1. Report accuracy on the whole labelled set. Rejected: class imbalance makes accuracy
   meaningless and there is no held-out set to sanity-check rules on.
2. k-fold cross-validation. Rejected: there is no training, so folds are pointless; a single
   fixed test set with a seeded split is reproducible and simpler to defend.
3. **Fixed seeded development/test split, package-level metrics at two operating points,
   baselines under identical inputs, and a four-configuration ablation.** Chosen.

### Choice (summary; EVALUATION.md is authoritative)

- Unit of evaluation: one distribution file (sdist). Malicious set: Datadog PyPI subset plus
  Backstabber PyPI subset, sdists only, deduplicated by sha256. Benign set: sdists of the
  most-downloaded PyPI projects, with the "popular ≠ benign" caveat stated.
- Development set: 20 malicious + 20 benign drawn with seed `20261019`, used only to
  sanity-check rules; never for tuning without an ADR. Test set: the rest.
- Metrics: precision, recall, F1, FP count, FP per 1 000 benign, findings per benign package,
  median wall time per package. An FP is a benign-labelled *package* with `risk ≥ τ`.
- Baselines: GuardDog and Aura run over the same file list, versions pinned, offline where
  the tool permits, "flagged" defined per tool in EVALUATION.md.
- Ablation: the same engine, same catalogue, same thresholds, in four configurations:
  A file-level co-occurrence, B definition-level co-occurrence, C reachability without phase
  weighting, D reachability with phase weighting (the full method). The A→D delta is the
  novelty claim; C→D isolates the phase contribution.
- Error analysis: every FN classified as out-of-scope (wheel-only, non-Python payload),
  parse failure, rule gap, or resolution gap.
- Results tables have a fixed format in `RESULTS.md` so they are filled mechanically.

---

## ADR-013 — The Python API surface

**Date:** 2026-09-05. **Status:** accepted.

### Context

`pip install phylaxis` gives a second public interface. The plumbing (maturin, abi3, console
script) is proven. What it exposes was undecided.

### Alternatives considered

| Question | Options | Choice and why |
|---|---|---|
| What `scan()` takes | bytes / a `Distribution` object / **a path** | A path to an sdist file or an extracted directory. Bytes would force the caller to manage temp files; an object would leak the domain model into Python. |
| What it returns | opaque handle with accessors / PyO3 classes / **plain data** | A plain `dict` with the same schema as `phylaxis scan --format json`. One schema for CLI, Python, SARIF conversion and downstream reporting; trivially stable across versions; no second copy of the domain model to keep in sync. |
| How data crosses FFI | per-field conversion / a `pythonize`-style crate / **a JSON string parsed by the shim** | JSON string. Costs one parse per package (negligible against analysis) and needs no new dependency. If profiling ever shows otherwise, adding a serde→PyObject crate is a new ADR. |
| Batch scanning | loop in Python / **`scan_many()` in Rust** | `scan_many()` keeps `rayon` parallelism inside Rust and releases the GIL for the whole batch; results come back in input order, per-item errors as `{"error": ...}` entries so one corrupt archive cannot abort a 1 500-package run. |
| Who drives the evaluation harness | CLI via subprocess / **the Python API** | The API. 1 500 process spawns and JSON re-parsing are avoidable; and `scan_many` is the same `scan_one` the CLI calls, so nothing can drift. Baselines are of course driven through *their* CLIs. |

### Choice — the surface

```
phylaxis.scan(path, *, cache=None, jobs=None, min_confidence=None) -> dict
phylaxis.scan_many(paths, *, cache=None, jobs=None, min_confidence=None) -> list[dict]
phylaxis.rules() -> list[dict]          # id, technique, phase, severity, sources, sinks
phylaxis.ruleset_version() -> int
phylaxis.version() -> str
phylaxis.cli_main(argv) -> int          # unchanged; the console script
```

Native functions (`_native`): `scan_json`, `scan_many_json`, `rules_json`,
`ruleset_version`, `version`, `cli_main`. The shim does `json.loads` and nothing else.

**Deliberately not exposed:** the AST, the symbol table, the graphs, the rule engine, the
cache, and the fetcher. The API is a *scanner*, not a program-analysis library; exposing the
model would freeze it.

### Consequences

- `phylaxis-cli` gains a `scan` module with `scan_one` and `scan_many`; both entry points use
  it. `crates/py` stays pure marshalling.
- `ScanReport` JSON is versioned by `schema_version` inside the report (ADR-017).

---

## ADR-014 — The parser lowers to an owned arena AST; the graph crate never sees tree-sitter

**Date:** 2026-09-05. **Status:** accepted.

**Context.** The domain model needs an `AstNode` type in `phylaxis-core`, and `rayon` needs
`Send` data across the file-parallel boundary. `phylaxis-core` must not depend on tree-sitter.
**Alternatives.** (1) Pass tree-sitter trees through: couples every crate to the parser and
makes a later switch to `ruff_python_parser` a rewrite. (2) Re-parse in the graph crate:
double work. (3) **Lower once into an owned, index-based arena (`Ast { nodes: Vec<AstNode> }`)
that carries kind, span, text slice and child indices.** Chosen. **Consequences.** Memory copy
per file (acceptable: sdists are small); the parser backend is swappable by a recorded
decision; the AST is trivially serialisable for snapshot tests.

**Amended 2026-09-22.** `Ast` also carries `rel_path`, the file's path relative to the
distribution root. The symbol stage derives a module's dotted name from that path
(`pkg/sub.py` is `pkg.sub`) and the evidence renderer prints it, so both needed it, and the
arena knew only a numeric `FileId`. The alternative was a side table from `FileId` to path,
passed alongside the slice of `Ast`s. It was rejected because `FileId` *is* a position in
that slice: a side table that drifts out of step with it produces wrong module names
silently, where a field on the node cannot. The cost is one `String` per file.

---

## ADR-015 — `phylaxis-core` depends on `petgraph`

**Date:** 2026-09-05. **Status:** accepted.

`CallGraph` and `DataFlowGraph` are domain entities and must be real types in `core`, so that
the domain model has exactly one definition. They wrap `petgraph::graph::DiGraph`. The
alternative, a hand-rolled adjacency list in `core` mirrored into petgraph in `graph`, is two
representations of one thing. `petgraph` is already a pinned workspace dependency, so this is
not version hunting. Consequence: `core` gains `petgraph.workspace = true`.

---

## ADR-016 — End-to-end tests live in `crates/cli/tests/`

**Date:** 2026-09-05. **Status:** accepted.

The workspace is virtual (no root package), so a root-level `tests/` directory is not
compiled by cargo. End-to-end contracts therefore live in `crates/cli/tests/e2e_*.rs`, in the
crate that owns orchestration; `phylaxis/tests/README.md` says so. Fixtures stay at
`phylaxis/fixtures/` and are addressed via `CARGO_MANIFEST_DIR/../../fixtures`. The
alternative, turning the root into a package, would change the workspace shape that was handed
over green.

---

## ADR-017 — Cache key layout and the ruleset-version convention

**Date:** 2026-09-05. **Status:** accepted.

- `CacheKey = sha256(file) ‖ ruleset_version (u32 big-endian)` = 36 bytes. Byte layout is a
  tested contract.
- `RulesetVersion` bumps whenever **either** the rule catalogue **or** the `ScanReport`
  schema changes. `WHY:` a cached report is only reusable if both what was computed and how it
  is shaped are unchanged; folding the schema into the same counter keeps invariant 6 to one
  number. `ScanReport.schema_version` is still emitted for consumers.
- Cache entries are never overwritten and never expire: PyPI filenames are immutable.
- Directories scanned from disk (not an sdist) are **not cached**: their content has no stable
  identity. The alternative, hashing the directory tree, was rejected because the identity
  claim rests on PyPI immutability, which a directory lacks.

---

## ADR-018 — Bounded literal folding for deobfuscation

**Date:** 2026-09-05. **Status:** accepted.

**Context.** Backstabber reports encoding as the dominant obfuscation; `exec(b64decode("..."))`
is the canonical PyPI payload. **Alternatives.** (1) Execute or emulate: forbidden by
invariant 5. (2) Regex on literals: misses `"".join(chr(c) for c in [...])` shapes.
(3) **Constant folding over literal-only expressions** for a closed set of pure functions
(`base64.*decode`, `bytes.fromhex`, `codecs.decode(rot13)`, `zlib.decompress`, `chr` joins,
string reversal, concatenation), bounded to depth 8 and 1 MiB output, producing a
`DecodedLiteral` source whose decoded text is itself scanned for URLs and import names.
Chosen. **Consequence.** `graph::fold` is pure and total: it never calls out, never allocates
beyond the bound, and on any non-literal input returns `None`. The safety test for this is in
the first tier of the test contracts.

---


## ADR-019 — `docs/` is written for whoever clones this repository

**Date:** 2026-09-05. **Status:** accepted.

### Context

This repository accompanies a research project whose write-up lives in a separate,
unconnected repository. The design documents here were originally drafted in that project's
vocabulary: entries carried the chapter of the write-up they fed, prior work was cited by
bare index (`[18]`) against a bibliography kept in the other repository, and some entries
recorded decisions about the document rather than about the software.

The result was a `docs/` directory that could not be read on its own. A reader who cloned the
tool met citations that resolved nowhere and section tags for a document they do not have.

### Choice

Everything in `docs/` must be readable end to end by someone who has only this repository.
Concretely:

- Prior work is cited **inline, by author and year** — "Backstabber's Knife Collection
  (Ohm et al., 2020)" — so the sentence carries its own reference. No bare `[N]` indices, and
  no separate bibliography file to keep in sync.
- No entry carries the chapter of the write-up it feeds.
- Decisions **about the write-up** — its bibliography, its formulations, its structure — are
  not architecture decisions and were moved out. They were ADR-002, ADR-003 and ADR-012;
  those numbers are retired and not reused, which is why the sequence has gaps.
- The same applies to source comments: code explains the code, not the document.

### Consequences

- Numbering gaps at 002, 003, 012 are permanent. Standard ADR practice: an identifier is
  never reused, because references to it exist elsewhere.
- `SAFETY.md` was added, stating the threat model and the guarantees with the test that
  proves each. It is the reference for the intended register of these documents.
- `ARCHITECTURE.md` no longer duplicates the safety table; it points at `SAFETY.md`, so the
  two cannot drift apart.
- Markers addressed to a future editor rather than to a reader — `EXPLAIN(...)` comments
  left in the scaffold — are resolved into the explanation they ask for before the code
  containing them is committed. They are scaffolding, not documentation.

---

## ADR-020 — Only Python source is written to disk; everything else is a manifest entry

**Date:** 2026-09-16. **Status:** accepted. Supersedes the open request filed with T-03.

### Context

Extraction wrote every validated archive member into the temporary root. The analyser reads
only `.py` and `pyproject.toml` (invariant 2), so every other member — bundled binaries,
nested archives, data files, documentation — was written, never opened, and deleted on drop.

That is not a hole. Nothing reads those bytes and nothing can execute them. But it makes the
safety story weaker than it needs to be: "phylaxis never opens a non-Python file" is a claim
about which code paths exist, and the only way to check it is to read the code and believe the
reader. Meanwhile the bytes really are sitting on a disk, written there by an untrusted
archive, for as long as the scan runs.

### Alternatives considered

1. **Write every member** (what T-03 landed, as the conservative reading of the module
   contract). The extraction root is a faithful copy of the sdist. Rejected: it materialises
   untrusted bytes that nothing will ever read, and leaves the guarantee unverifiable.
2. **Write only source files and discard everything else outright.** Rejected, and this is the
   interesting rejection. **Existence is signal.** `subprocess.run(["./vendor/helper.bin"])` is
   a package executing a payload it *ships* when that path is in the distribution, and the
   download-write-execute shape (PHX-DRP-002) when it is not — two different findings from one
   line of Python, separated by a fact about a file that nothing needs to read. Dropping
   non-source members entirely throws that discriminator away.
3. **Write only source files; record the path and declared size of every other member.**
   Chosen.

### Choice

`extract_sdist` writes a member only when `SourceFile::classify` accepts it. Every other
member's body is skipped unread, and `ManifestEntry { rel_path, size_bytes }` is appended to
`ExtractedTree::manifest`, sorted. `load_directory` does the same over a directory.
`ExtractedTree::contains_path` answers "does this distribution ship this path", spanning both
the analysed files and the manifest.

Three details worth stating:

- **The limits still count every member.** A multi-gigabyte data file is a decompression bomb
  whether or not it is written, so `max_entries` and `max_total_bytes` are unchanged and
  continue to see the whole archive. Only the write narrowed.
- **`size_bytes` is the tar header's claim, not a measurement**, because the body is never
  read. The field's documentation says so. Any future rule reasoning about the number must
  treat it as attacker-controlled. (For `load_directory` it is the real size on disk, where
  there is no attacker-written header in the way.)
- **This is not a scope change.** Invariant 2 already put compiled extensions outside
  *analysis*; this decision is about what reaches the file system, not about what is analysed.

### Consequences

- A new guarantee, **G6 in `SAFETY.md`**, with a test that walks the extraction root and
  asserts every file is `.py` or `pyproject.toml`. The claim becomes a property of the disk
  instead of an argument about code paths — which is the whole point.
- The extraction root shrinks to the part of an sdist that is usually a small fraction of it,
  so extraction gets cheaper as a side effect rather than as a goal.
- It opens a rule that cannot be written today: *the distribution ships a native executable and
  Python calls `subprocess` on that path*. Classifying a member by magic bytes (ELF, PE, Mach-O,
  nested archive) is deliberately **not** decided here — it is a new detection capability and
  needs its own ADR, its own row in `RULES.md` and its own fixture pair.
- Cross-language analysis stays out of scope: the corpus is PyPI and the parser is Python-only.
  But the manifest is the seam such work would attach to, and it costs nothing to have kept it.

---

## ADR-021 — A distribution's importable names are derived from its file list

**Date:** 2026-09-22. **Status:** accepted.

**Context.** A module is named after its path relative to the distribution root, so the
analyser has to know where that root effectively begins. For most projects it is the archive
root; for the `src/` layout the packages sit one directory lower, and calling `src/pkg/a.py`
the module `src.pkg.a` resolves every relative import inside it one level too deep. The
imports then point at modules that do not exist, the call edges are never built, and the
package is under-analysed silently — the tool reports fewer findings rather than an error.

**Alternatives.**

1. **Match the literal directory name `src`.** Rejected: it is a convention, not a rule.
   `lib/` and `source/` are used too, and a project that genuinely ships a package called
   `src` would be corrupted by it.
2. **Read `[tool.setuptools] packages` / `package-dir` from `pyproject.toml`.** Authoritative
   where it appears, because it is the project's own declaration. Rejected as the *only*
   mechanism: a large share of sdists declare their layout in `setup.cfg` or in `setup.py`,
   and `setup.py` cannot be executed (invariant 5). The answer would be right where it
   applied and silently missing everywhere else, which is the failure mode that is hardest to
   notice in an evaluation.
3. **Derive it structurally from the file list.** Chosen.
4. **Do nothing and document the miss.** Rejected: it costs recall on real packages for no
   saving beyond about thirty lines.

**Decision.** `parse::layout::discover_top_level_modules` returns the importable top-level
names, from the extracted file list alone, by three rules applied in order:

1. `X` for every `X/__init__.py` at the distribution root.
2. **Only if rule 1 found nothing**, `X` for every `C/X/__init__.py`. A root holding no
   package at all is the container layout's signature, and `C` is then a container directory.
3. `X` for every root-level `X.py` other than `setup.py` — the single-module distribution.

`symbols::build_symbol_table` drops a leading path component when the metadata says the
*next* component is importable and the first is not. The test is always the derived set,
never a directory name.

**Why rule 2 is conditional.** Treating any non-package root directory as a container
unconditionally would promote `tests/helpers/__init__.py` to the top-level name `helpers`,
and `tests/helpers/util.py` would then be named `helpers.util` — a wrong name, produced
quietly. The condition removes the case entirely: a project with a `tests/` directory also
has its own package at the root, so rule 1 fires and rule 2 never runs.

**Consequences.** The residual failures are misses, never wrong names, which is the direction
this project takes everywhere uncertainty appears:

- a distribution shipping both a root package and a `src/` tree keeps the `src.` prefix on
  the second one;
- a PEP 420 namespace package has no `__init__.py` and is not detected at all.

Both lose call edges; neither invents one. `parse_pyproject` still leaves `top_level_modules`
empty — it is a fact about the file list, not about that file — and the caller assembling
`ProjectMeta` fills it in.

---

## Open requests

Implementers append here. Format: date, who, what rule is missing, what conservative reading
was applied meanwhile.

- *(closed)* The T-06 `src/`-layout request was closed by **ADR-021** on 2026-09-22:
  importable top-level names are derived from the file list, root packages first, and a
  container directory is only seen through when the root holds no package at all.

- *(closed)* The T-03 extraction-scope request was closed by **ADR-020** on 2026-09-16:
  only `.py` and `pyproject.toml` are written, everything else becomes a manifest entry.
