# EVALUATION — protocol and ablation design

Fixed on 2026-09-05, before any analysis code exists (ADR-011). Changes to this protocol
after the first run require a new ADR that records what was measured before and after.

## 1. Research questions the experiment answers

- **E1 (precision).** Does requiring source→sink reachability reduce false positives compared
  with co-occurrence of the same indicators, at equal or better recall?
- **E2 (baselines).** How does the tool compare with GuardDog and Aura on the same packages?
- **E3 (phase).** What does install-phase weighting contribute on its own?
- **E4 (cost).** What is the cost of the conservative approximation (ADR-005/007) in
  ambiguous-confidence findings and in wall time?

## 2. Unit of evaluation and labels

- The unit is **one distribution file**, identified by sha256. A project with several
  versions in the malicious set contributes each distinct sdist once.
- **Malicious label:** membership in the Datadog `malicious-software-packages-dataset` PyPI
  set or the Backstabber
  (Ohm et al., 2020) PyPI subset. Wheels-only entries are counted in the *coverage* table and
  excluded from the metrics (invariant 2), never silently dropped.
- **Benign label:** the sdist of a project in the most-downloaded PyPI list
  `top-pypi-packages` at a recorded snapshot, one sdist per project (latest at snapshot).
  The caveat "popular is a proxy for benign, not a proof" is stated wherever these numbers
  are reported; any benign
  package flagged at the strict operating point is manually reviewed and, if it is in fact
  malicious, reported upstream and *kept as benign in the metrics* (the label set is frozen).
- Target sizes: all available malicious sdists (expected on the order of 1 000 after
  deduplication and wheel exclusion; the actual count goes into RESULTS.md) and 1 000 benign.

## 3. Development / test split

- Seed: `20261019`. Procedure: sort each label class by sha256, shuffle with the seed, take
  the first 20 of each class as the **development set**; the rest is the **test set**.
- The development set is used for one purpose: verifying that rules fire on real samples and
  are silent on real benign packages, i.e. catching implementation bugs. Rule constants
  (severity weights, phase weights, thresholds) are **fixed by ADR-010 and are not tuned**. If
  a development-set observation motivates changing a constant, that change is a new ADR that
  records the before/after numbers on the development set only, and the test set is run once,
  after all such changes.
- The test set is run **once per configuration** for the reported numbers. A rerun after a bug
  fix is recorded in RESULTS.md with the reason.
- `eval/manifest.json` lists every file (name, version, sha256, label, split). It is
  committed; the archives are not.

## 4. Operating points and definitions

| Term | Definition |
|---|---|
| Flagged (primary, τ = 0.40) | `ScanReport.risk ≥ 0.40` (verdict Suspicious or Malicious). |
| Flagged (strict, τ = 0.70) | `ScanReport.risk ≥ 0.70` (verdict Malicious). |
| TP | malicious-labelled package, flagged |
| FP | benign-labelled package, flagged |
| FN | malicious-labelled package, not flagged |
| TN | benign-labelled package, not flagged |
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | harmonic mean of precision and recall |
| FP per 1 000 benign | FP × 1 000 / (FP + TN) |
| Noise | mean number of findings per benign package (triage cost), counted at τ = 0.40 |
| Time | median and 95th-percentile wall time per package, single-threaded and with `jobs = cores` |

FPs are counted **per package**, not per finding: a package with five spurious findings is one
FP. Noise captures the per-finding cost separately.

## 5. Baselines

| Tool | Invocation | "Flagged" | Notes |
|---|---|---|---|
| GuardDog | `guarddog pypi scan <sdist>` with the default rule set, network heuristics disabled if the version allows, else results with only metadata rules are excluded and noted | at least one source-code rule result | Version pinned in RESULTS.md. |
| Aura | `aura scan <sdist>` with default configuration | Aura's own score above its default threshold, recorded | If Aura cannot be installed on the evaluation machine, RESULTS.md says so and E2 is answered with GuardDog only. |
| phylaxis | `phylaxis.scan_many(files)` | as in §4 | Same machine, same file list, same order. |

All three run over the identical file list from `eval/manifest.json`. Parse failures and
crashes of a baseline are counted as "not flagged" and listed.

## 6. The ablation (E1, E3): four configurations of one engine

Same catalogue, same phase roots, same constants; only the decision predicate changes.

| Config | Predicate for a rule to fire | What it models |
|---|---|---|
| **A** file co-occurrence | a source kind and a sink kind of the rule both occur in the same file | GuardDog-style pattern co-occurrence |
| **B** definition co-occurrence | both occur inside the same callable definition | a tighter co-occurrence, the strongest "cheap" baseline |
| **C** reachability, no phase weight | a data or control path exists; phase weight forced to 1.0 | the novelty without the taxonomy prior |
| **D** reachability with phase weight | the full method (ADR-008, ADR-010) | phylaxis |

For control rules (`PHX-INS-*`) configuration A means "sink present in an install file" and
B means "sink present in a definition that is itself an install root".

Reported for each: the full metric row of §4 at both operating points. The **A→D delta in FP
per 1 000 benign at equal or higher recall** is the headline number, quoted as the
contribution of reachability; **C→D** is the phase contribution. A per-rule breakdown (§8,
table R3) shows which rules gain most from reachability.

The ablation is implemented as `AnalysisMode { FileCooccurrence, DefinitionCooccurrence,
Reachability { phase_weighting: bool } }` in `ScanOptions`; all four modes share every line
of graph construction, so the comparison is exact.

## 7. Error analysis

Every FN at τ = 0.40 is assigned exactly one reason, by reading the package:

| Reason | Meaning |
|---|---|
| `out-of-scope` | payload not in Python source (wheel-only, compiled extension, shell script, data file) |
| `parse-failure` | tree-sitter error nodes cover the payload region |
| `rule-gap` | the behaviour is not in the catalogue (name the missing technique) |
| `resolution-gap` | the path exists semantically but a call or flow edge was not built (name the construct) |
| `fold-gap` | obfuscation not folded (name the encoding) |
| `label-noise` | the sample is not actually malicious (recorded, not removed) |

Every FP at τ = 0.70 is likewise classified: `accepted-class` (documented in RULES.md as an
expected FP), `resolution-overapprox` (ambiguous edge caused it), `rule-too-broad`, or
`label-noise` (actually malicious).

## 8. Results tables (format fixed; RESULTS.md holds the filled versions)

**R0 Coverage.** dataset · entries at snapshot · sdists · wheels-only (excluded) · duplicates ·
parse failures · in test set · in dev set.

**R1 Main results** (one row per tool/config, both operating points):
`config | τ | N_mal | N_ben | TP | FP | FN | TN | precision | recall | F1 | FP/1k | noise | t_median_ms | t_p95_ms`

**R2 Ablation** = R1 rows A, B, C, D plus two delta rows (A→D, C→D).

**R3 Per rule:** `rule | TP packages | FP packages | median confidence | phase split (I/Im/R)`.

**R4 Error analysis:** `reason | count | share | example package`.

**R5 Environment:** OS, CPU, Rust version, phylaxis commit, ruleset version, GuardDog
version, Aura version, dataset snapshots, date.

## 9. Threats to validity (to be written in 4.6; listed here so they are not forgotten)

Construct: popularity as a benign proxy; label noise in the malicious sets. Internal: the
development set touching rule implementation; deduplication by sha256 hiding near-duplicate
campaigns (report a campaign-clustered recall as a secondary number if time permits).
External: PyPI only; sdists only; a 2020–2025 snapshot of attack techniques. Reliability: all
inputs are listed by hash, all constants are in DECISIONS.md, the harness is committed.
