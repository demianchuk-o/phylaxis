# phylaxis — project overview

Orientation for any agent, and in particular for the first architecture session. Read
together with CLAUDE.md.

## In one sentence

A deterministic static analyser in Rust that detects malicious Python packages on PyPI by
the data-flow and call graph inside a package, prioritising findings by their impact in the
dependency graph.

## Problem and threat model

Software supply chain attacks are growing, and PyPI has no mandatory deep code review before
publication. In practice, malicious payloads on PyPI are almost always delivered as **Python
source**, most often through **install-time hooks** (overriding a command in `setup.py`, a
build backend in `pyproject.toml`) and through typosquatting. Those exact execution phases
and techniques are what the attack trees of Backstabber's Knife Collection describe. So
analysing source, with priority on code that runs at install and import time, covers the
bulk of the threat.

## Goal, object, subject (restated without ML)

- **Goal:** improve the precision of automated detection of malicious PyPI packages by means
  of deterministic contextual graph analysis.
- **Object:** software packages in the PyPI repository (Python source).
- **Subject:** deterministic methods and tools for detecting malicious code based on
  analysis of the data-flow / call graph inside a package and of the dependency graph.

## Scientific novelty

The detection method is improved by requiring **source → sink reachability** in the package
graph, rather than the simple co-occurrence of indicators in a file that existing tools rely
on. This raises precision and reduces false positives. In addition, confirmed findings are
prioritised by impact metrics — blast radius, centrality — in the dependency graph.

## Scope

**In scope:** Python source in an sdist (`setup.py`, `pyproject.toml`, `.py`); the
intra-package graph; deterministic rules; evaluation on labelled datasets; prioritisation by
the dependency graph.

**Out of scope, with justification:** compiled extensions (`.so`/`.pyd`) require binary
analysis, which is a separate discipline, and empirically the malicious payload on PyPI
arrives as source; dynamic analysis and sandboxed execution; ML model training. A compiled
package can still be a **node** in the dependency graph via its metadata — simply without
its code being analysed.

## Architecture (two tiers)

1. **Detection (core).** sdist → safe extraction → AST (tree-sitter) → package graph
   (call graph + data flow) → source→sink reachability check → deterministic risk score.
2. **Prioritisation (layer on top).** PyPI dependency graph → blast radius / centrality →
   ranking of confirmed findings by potential impact.

## Sources of truth and baselines

- **Threat taxonomy:** Backstabber's Knife Collection (Ohm et al., 2020) — 174 real
  malicious packages plus two attack trees (injection techniques and execution phase).
- **Labelled datasets for EVALUATION, not training:** the open Datadog dataset
  (`malicious-software-packages-dataset`, roughly 1500 real malicious packages) plus the 174
  from Backstabber.
- **Baselines for comparison:** Aura (AST + taint, high FP) and GuardDog (Semgrep/YARA +
  co-occurrence of capability and threat within a file). Run both over the same set and
  compare precision / recall / FP — that is a ready-made Evaluation Research contribution.

## Evaluation methodology

Precision, recall, F1 and false-positive count on the labelled set; comparison against Aura
and GuardDog as baselines; and separately, a measurement of what the source→sink reachability
requirement itself contributes to FP reduction (an ablation: co-occurrence versus
reachability).

## Caching

Key = `sha256` of the package file + ruleset version. PyPI files are immutable (a
distribution filename is never reassigned), so the result for a `sha256` is cached
indefinitely; changing the rules increments their version and invalidates old entries.
Storage: `redb`.

## Distribution

The tool is delivered as a **prebuilt wheel on PyPI** (`pip install phylaxis`), giving both
an importable module and a console command. The rationale is practical: the users and the
CI pipelines that would adopt such a scanner are already in the Python ecosystem, and the
evaluation harness over the Datadog and Backstabber datasets is far easier to script in
Python than around a foreign binary. Built with maturin and PyO3 under the abi3 stable ABI,
so one wheel per platform serves every CPython ≥ 3.9.

This is a claim to "practical value" that the thesis can actually demonstrate, rather than
assert: an installable artefact plus a CI integration is more convincing than a repository
of source.

## Roadmap (phases)

1. **MVP.** sdist extraction → AST → basic rules (obfuscation, install hooks, network,
   reading secrets) → precision/recall evaluation on the labelled set. Already a complete
   piece of work on its own.
2. **Novelty.** The package graph plus source→sink reachability; the ablation demonstrating
   FP reduction.
3. **Stretch, if time allows.** Dependency graph plus blast radius / centrality; SARIF
   output and a CI/CD integration demo.
4. **Tool quality.** Rust optimisation (`rayon`), caching, a comfortable CLI.

## Open questions (future work)

- A centralised opt-in database collecting anonymised results from different users — an
  attractive "practical value" claim, but out of scope for the MVP because of the
  infrastructure and privacy involved. Reconsider after phase 3.
