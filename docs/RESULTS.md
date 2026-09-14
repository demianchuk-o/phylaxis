# RESULTS — evaluation results (filled mechanically by the harness)

Format fixed by `EVALUATION.md` §8. Empty cells mean "not run yet". Every filled table must
name the run it came from (date, phylaxis commit, ruleset version) in R5. Do not edit numbers
by hand; regenerate from `eval/` output.

## R0 Coverage

| dataset | entries at snapshot | sdists | wheels-only (excluded) | duplicates | parse failures | in test set | in dev set |
|---|---|---|---|---|---|---|---|
| Datadog PyPI | | | | | | | |
| Backstabber PyPI | | | | | | | |
| Benign (top downloads) | | | | | | | |

## R1 Main results

| config | τ | N_mal | N_ben | TP | FP | FN | TN | precision | recall | F1 | FP/1k | noise | t_median_ms | t_p95_ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| phylaxis D | 0.40 | | | | | | | | | | | | | |
| phylaxis D | 0.70 | | | | | | | | | | | | | |
| GuardDog | — | | | | | | | | | | | | | |
| Aura | — | | | | | | | | | | | | | |

## R2 Ablation

| config | τ | N_mal | N_ben | TP | FP | FN | TN | precision | recall | F1 | FP/1k | noise |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A file co-occurrence | 0.40 | | | | | | | | | | | |
| B definition co-occurrence | 0.40 | | | | | | | | | | | |
| C reachability, no phase | 0.40 | | | | | | | | | | | |
| D reachability + phase | 0.40 | | | | | | | | | | | |
| Δ A→D | | | | | | | | | | | | |
| Δ C→D | | | | | | | | | | | | |

(Repeat at τ = 0.70.)

## R3 Per rule

| rule | TP packages | FP packages | median confidence | phase split (Install / Import / Runtime) |
|---|---|---|---|---|
| PHX-EXF-001 | | | | |
| PHX-EXF-002 | | | | |
| PHX-EXF-003 | | | | |
| PHX-EXF-004 | | | | |
| PHX-DRP-001 | | | | |
| PHX-DRP-002 | | | | |
| PHX-DRP-003 | | | | |
| PHX-OBF-001 | | | | |
| PHX-OBF-002 | | | | |
| PHX-BKD-001 | | | | |
| PHX-PER-001 | | | | |
| PHX-SAB-001 | | | | |
| PHX-INS-001 | | | | |
| PHX-INS-002 | | | | |
| PHX-INS-003 | | | | |

## R4 Error analysis

| reason | count (FN @0.40) | share | example package |
|---|---|---|---|
| out-of-scope | | | |
| parse-failure | | | |
| rule-gap | | | |
| resolution-gap | | | |
| fold-gap | | | |
| label-noise | | | |

| reason | count (FP @0.70) | share | example package |
|---|---|---|---|
| accepted-class | | | |
| resolution-overapprox | | | |
| rule-too-broad | | | |
| label-noise | | | |

## R5 Environment

| item | value |
|---|---|
| date | |
| OS / CPU | |
| rustc | |
| phylaxis commit | |
| ruleset version | |
| GuardDog version | |
| Aura version | |
| Datadog snapshot (commit) | |
| Backstabber snapshot | |
| benign list snapshot | |
| `jobs` | |

## Run log

| date | what ran | why (first run / bug fix / ADR) | tables affected |
|---|---|---|---|
| | | | |
