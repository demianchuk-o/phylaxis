"""Regenerates ``docs/RESULTS.md`` from the result files (EVALUATION.md §8).

    python eval/report.py                       # every ruleset whose files exist
    python eval/report.py --runs "=ruleset 2" "-r3=ruleset 3"

Nothing in RESULTS.md is typed by hand except the run log, which is carried over from the
existing file unchanged. A ruleset is a result-file tag (``test-D.jsonl`` is the untagged
ruleset-2 run, ``test-D-r3.jsonl`` the ruleset-3 one) and is reported only if its files exist;
two rulesets appear side by side, never one instead of the other (ADR-028).

**One counting rule for every tool:** an input that errored, timed out or was not scanned
counts as *not flagged*, and the errors are given in their own column. EVALUATION.md §5 says
so for the baselines; applying it to phylaxis too keeps the comparison symmetric.

The Backstabber split (ADR-026) is all malicious, so it gets a recall-only table, over the
packages no earlier run has seen (``new``) and over all of it.

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from acquire import DATA, HERE

RESULTS = DATA / "results"
DOC = HERE.parent / "docs" / "RESULTS.md"
THRESHOLDS = (0.40, 0.70)
MODES = {"A": "A file co-occurrence", "B": "B definition co-occurrence",
         "C": "C reachability, no phase", "D": "D reachability + phase"}
AURA_POINTS = (0, 10, 50, 100, 200, 500)
RULE_IDS = ["PHX-EXF-001", "PHX-EXF-002", "PHX-EXF-003", "PHX-EXF-004", "PHX-DRP-001",
            "PHX-DRP-002", "PHX-DRP-003", "PHX-OBF-001", "PHX-OBF-002", "PHX-BKD-001",
            "PHX-PER-001", "PHX-SAB-001", "PHX-INS-001", "PHX-INS-002", "PHX-INS-003"]


def rows(name: str) -> list[dict] | None:
    path = RESULTS / f"{name}.jsonl"
    if not path.is_file():
        return None
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def errored(r: dict) -> bool:
    return "error" in r or bool(r.get("errors")) or bool(r.get("skipped"))


def phylaxis_flag(tau: float):
    return lambda r: not errored(r) and r.get("risk", 0.0) >= tau


def guarddog_flag(r: dict) -> bool:
    return not errored(r) and bool(r.get("flagged"))


def aura_flag(threshold: float = 0):
    return lambda r: not errored(r) and (r.get("score") or 0) > threshold


def fmt(x: float, digits: int = 3) -> str:
    return f"{x:.{digits}f}"


def confusion(rs: list[dict], flag) -> dict:
    mal = [r for r in rs if r["label"] == "malicious"]
    ben = [r for r in rs if r["label"] == "benign"]
    tp = sum(map(flag, mal))
    fp = sum(map(flag, ben))
    fn, tn = len(mal) - tp, len(ben) - fp
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    secs = sorted(r["seconds"] for r in rs if "seconds" in r)
    return {
        "n_mal": len(mal), "n_ben": len(ben), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "p": p, "r": rec, "f1": 2 * p * rec / (p + rec) if p + rec else 0.0,
        "fp1k": fp * 1000 / (fp + tn) if fp + tn else 0.0,
        "errors": sum(map(errored, rs)),
        "t_med": secs[len(secs) // 2] * 1000 if secs else 0.0,
        "t_p95": secs[min(len(secs) - 1, int(len(secs) * 0.95))] * 1000 if secs else 0.0,
    }


def noise(rs: list[dict]) -> tuple[float, float]:
    """Mean findings and mean distinct sinks per scanned benign package."""
    b = [r for r in rs if r["label"] == "benign" and not errored(r)]
    if not b:
        return 0.0, 0.0
    return statistics.mean(r.get("findings", 0) for r in b), statistics.mean(r.get("sinks", 0) for r in b)


def r1_line(label: str, tau: str, c: dict, nz: str) -> str:
    return (f"| {label} | {tau} | {c['n_mal']} | {c['n_ben']} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | "
            f"{fmt(c['p'])} | {fmt(c['r'])} | {fmt(c['f1'])} | {c['fp1k']:.1f} | {nz} | {c['errors']} | "
            f"{c['t_med']:.0f} | {c['t_p95']:.0f} |")


R1_HEAD = ("| config | τ | N_mal | N_ben | TP | FP | FN | TN | precision | recall | F1 | FP/1k | "
           "noise (findings / sinks) | errors | t_median_ms | t_p95_ms |\n"
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")


def r0(manifest: list[dict], bkc: list[dict] | None) -> str:
    out = ["## R0 Coverage", "",
           "| dataset | entries at snapshot | sdists | wheels-only (excluded) | duplicates | other excluded | in test set | in dev set |",
           "|---|---|---|---|---|---|---|---|"]

    def line(name, es, wheel_key):
        ex = Counter(e["excluded"].split(":")[0] for e in es if "excluded" in e)
        wheels = sum(v for k, v in ex.items() if wheel_key in k)
        dups = ex.get("duplicate content", 0)
        other = sum(ex.values()) - wheels - dups
        split = Counter(e.get("split") for e in es)
        sdists = sum(e.get("kind") == "sdist" for e in es)
        return f"| {name} | {len(es)} | {sdists} | {wheels} | {dups} | {other} | {split.get('test', 0) + split.get('bkc', 0)} | {split.get('dev', 0)} |"

    out.append(line("Datadog PyPI", [e for e in manifest if e["source"] == "datadog"], "wheel"))
    if bkc is not None:
        out.append(line("Backstabber PyPI (split `bkc`)", bkc, "wheel"))
    out.append(line("Benign (top downloads)", [e for e in manifest if e["source"] != "datadog"], "wheel"))
    if bkc is not None:
        ov = Counter(e["overlap"] for e in bkc if e.get("split") == "bkc")
        out += ["", "Backstabber overlap with the main manifest (counted entries): "
                + ", ".join(f"`{k}` {v}" for k, v in sorted(ov.items())) + "."]
    return "\n".join(out)


def r1_r2(runs: list[tuple[str, str]]) -> str:
    out = ["## R1 Main results (test set)", "", R1_HEAD]
    for tag, label in runs:
        d = rows(f"test-D{tag}")
        if d is None:
            continue
        nz = noise(d)
        for tau in THRESHOLDS:
            out.append(r1_line(f"phylaxis D ({label})", f"{tau:.2f}", confusion(d, phylaxis_flag(tau)),
                               f"{nz[0]:.1f} / {nz[1]:.2f}"))
    g = rows("test-guarddog")
    if g:
        out.append(r1_line("GuardDog", "any rule", confusion(g, guarddog_flag), "—"))
    a = rows("test-aura")
    if a:
        out.append(r1_line("Aura", "score > 0", confusion(a, aura_flag(0)), "—"))
        out += ["", "Aura over its own score (the curve EVALUATION.md §5 asks for):", "",
                "| Aura threshold | TP | FP | precision | recall | FP/1k |", "|---|---|---|---|---|---|"]
        for t in AURA_POINTS:
            c = confusion(a, aura_flag(t))
            out.append(f"| score > {t} | {c['tp']} | {c['fp']} | {fmt(c['p'])} | {fmt(c['r'])} | {c['fp1k']:.1f} |")

    for tau in THRESHOLDS:
        out += ["", f"## R2 Ablation, τ = {tau:.2f}", "", R1_HEAD]
        for tag, label in runs:
            cs = {}
            for m, name in MODES.items():
                rs = rows(f"test-{m}{tag}")
                if rs is None:
                    continue
                cs[m] = confusion(rs, phylaxis_flag(tau))
                nz = noise(rs)
                out.append(r1_line(f"{name} ({label})", f"{tau:.2f}", cs[m], f"{nz[0]:.1f} / {nz[1]:.2f}"))
            for a_, b_ in (("A", "D"), ("C", "D")):
                if a_ in cs and b_ in cs:
                    x, y = cs[a_], cs[b_]
                    out.append(f"| Δ {a_}→{b_} ({label}) | | | | {y['tp'] - x['tp']:+d} | {y['fp'] - x['fp']:+d} | "
                               f"{y['fn'] - x['fn']:+d} | {y['tn'] - x['tn']:+d} | {y['p'] - x['p']:+.3f} | "
                               f"{y['r'] - x['r']:+.3f} | {y['f1'] - x['f1']:+.3f} | {y['fp1k'] - x['fp1k']:+.1f} | | | | |")
    return "\n".join(out)


def r3(runs: list[tuple[str, str]]) -> str:
    out = ["## R3 Per rule (mode D, τ = 0.40; packages flagged at that point, each counted once per rule by its best path)", ""]
    for tag, label in runs:
        d = rows(f"test-D{tag}")
        if d is None:
            continue
        flag = phylaxis_flag(0.40)
        tp, fp, conf, phase = Counter(), Counter(), defaultdict(list), defaultdict(Counter)
        for r in d:
            if not flag(r):
                continue
            for rule in r.get("rules", []):
                (tp if r["label"] == "malicious" else fp)[rule] += 1
                # Per package, the rule's best-scoring path: one vote per package, so a
                # package with ten thousand paths weighs the same as one with a single path.
                mine = [s for s in r.get("shapes", []) if s[0] == rule]
                if mine:
                    best = max(mine, key=lambda s: (s[3], s[4] == "resolved"))
                    conf[rule].append({"resolved": 1.0, "ambiguous": 0.6, "dynamic": 0.4}.get(best[4], 0.0))
                    phase[rule][best[5]] += 1
        out += [f"**{label}**", "", "| rule | TP packages | FP packages | median confidence | phase split (Install / Import / Runtime) |",
                "|---|---|---|---|---|"]
        for rule in RULE_IDS:
            ph = phase[rule]
            med = fmt(statistics.median(conf[rule]), 2) if conf[rule] else "—"
            out.append(f"| {rule} | {tp[rule]} | {fp[rule]} | {med} | {ph['install']} / {ph['import']} / {ph['runtime']} |")
        out.append("")
    return "\n".join(out).rstrip()


def r4(runs: list[tuple[str, str]]) -> str:
    out = ["## R4 Error analysis", "",
           "The mechanical split of the misses comes from the rows; the classification by cause "
           "(EVALUATION.md §7: out-of-scope, parse-failure, rule-gap, resolution-gap, fold-gap, "
           "label-noise) is done by reading samples, and ADR-028 records the first pass.", "",
           "| ruleset | missed at τ 0.40 | no finding at all | found, below τ | errored / not scanned |",
           "|---|---|---|---|---|"]
    for tag, label in runs:
        d = rows(f"test-D{tag}")
        if d is None:
            continue
        miss = [r for r in d if r["label"] == "malicious" and not phylaxis_flag(0.40)(r)]
        err = sum(map(errored, miss))
        none = sum(not errored(r) and r.get("findings", 0) == 0 for r in miss)
        out.append(f"| {label} | {len(miss)} | {none} | {len(miss) - none - err} | {err} |")
    return "\n".join(out)


def r6(runs: list[tuple[str, str]], bkc: list[dict] | None) -> str:
    if bkc is None:
        return ""
    sub = {e["id"]: e["overlap"] for e in bkc if e.get("split") == "bkc"}
    out = ["## R6 Backstabber split (ADR-026): recall only", "",
           "Every entry is malicious. `new` is the packages no earlier run has seen; `all` adds the "
           "ones byte-identical to, or named like, a Datadog sample.", "",
           "| tool / config | τ | recall `new` | recall `all` | N `new` | N `all` | errors |", "|---|---|---|---|---|---|---|"]

    def line(label, tau, rs, flag):
        rs = [r for r in rs if r["id"] in sub]
        new = [r for r in rs if sub[r["id"]] == "new"]
        rec = lambda xs: sum(map(flag, xs)) / len(xs) if xs else 0.0
        return f"| {label} | {tau} | {fmt(rec(new))} | {fmt(rec(rs))} | {len(new)} | {len(rs)} | {sum(map(errored, rs))} |"

    for tag, label in runs:
        for m, name in MODES.items():
            rs = rows(f"bkc-{m}{tag}")
            if rs is not None:
                for tau in THRESHOLDS:
                    out.append(line(f"{name} ({label})", f"{tau:.2f}", rs, phylaxis_flag(tau)))
    g = rows("bkc-guarddog")
    if g:
        out.append(line("GuardDog", "any rule", g, guarddog_flag))
    a = rows("bkc-aura")
    if a:
        out.append(line("Aura", "score > 0", a, aura_flag(0)))
    return "\n".join(out)


def os_name() -> str:
    """Windows 11 reports release "10"; the build number tells them apart (22000 and up)."""
    if platform.system() == "Windows":
        build = platform.version().split(".")[-1]
        if build.isdigit() and int(build) >= 22000:
            return f"Windows 11 (build {build})"
    return f"{platform.system()} {platform.release()}"


def r5(runs: list[tuple[str, str]], manifest_doc: dict, bkc_doc: dict | None) -> str:
    def cmd(*args):
        try:
            return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return "?"
    versions = {}
    for split in ("test", "bkc"):
        p = RESULTS / f"{split}-baseline-versions.json"
        if p.is_file():
            versions[split] = json.loads(p.read_text(encoding="utf-8"))
    tv = versions.get("test", {})
    out = ["## R5 Environment", "", "| item | value |", "|---|---|",
           f"| generated | {cmd('git', '-C', str(HERE.parent), 'log', '-1', '--format=%cs')} by `eval/report.py` |",
           f"| OS / CPU | {os_name()} / {platform.processor() or platform.machine()} |",
           f"| rustc | {cmd('rustc', '--version')} |",
           f"| phylaxis commit (report generated at) | {cmd('git', '-C', str(HERE.parent), 'rev-parse', '--short', 'HEAD')} |",
           f"| rulesets reported | {', '.join(label for _, label in runs)} |",
           f"| GuardDog version | {tv.get('guarddog', '?')} |",
           f"| Aura image | `{tv.get('aura_image', '?')}` |",
           f"| Datadog snapshot (commit) | {manifest_doc.get('datadog_commit', '?')} |",
           f"| Backstabber snapshot | {(bkc_doc or {}).get('bkc_version', {}).get('git_revision', '—')} |",
           f"| benign list snapshot | {manifest_doc.get('top_pypi_snapshot', '?')} |",
           "| `jobs` | phylaxis 6, baselines 5 (timings are per package under that concurrency) |"]
    return "\n".join(out)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--runs", nargs="*", default=["=ruleset 2", "-r5=ruleset 5"],
                   help="tag=label pairs; a run is reported only if its files exist")
    p.add_argument("--stdout", action="store_true", help="print instead of writing docs/RESULTS.md")
    args = p.parse_args()
    runs = [tuple(x.split("=", 1)) for x in args.runs]
    runs = [(t, l) for t, l in runs if (RESULTS / f"test-D{t}.jsonl").is_file() or (RESULTS / f"bkc-D{t}.jsonl").is_file()]

    manifest_doc = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    bkc_path = DATA / "bkc-manifest.json"
    bkc_doc = json.loads(bkc_path.read_text(encoding="utf-8")) if bkc_path.is_file() else None
    bkc = bkc_doc["entries"] if bkc_doc else None

    old = DOC.read_text(encoding="utf-8") if DOC.is_file() else ""
    log = old[old.index("## Run log"):].rstrip() if "## Run log" in old else "## Run log"
    parts = [
        "# RESULTS — evaluation results (generated by `eval/report.py`)",
        "",
        "Format fixed by `EVALUATION.md` §8. **Do not edit numbers by hand**: regenerate with "
        "`python eval/report.py`. Only the run log at the end is written by hand. An errored or "
        "unscanned input counts as not flagged for every tool. Ruleset 3 was shaped by the "
        "test-set error analysis (ADR-028), so its test-set rows are post-hoc and stand beside "
        "ruleset 2's; its honest measurement is R6 `new`.",
        "", r0(manifest_doc["entries"], bkc), "", r1_r2(runs), "", r3(runs), "", r4(runs), "",
        r6(runs, bkc), "", r5(runs, manifest_doc, bkc_doc), "", log, "",
    ]
    text = "\n".join(x for x in parts if x is not None)
    if args.stdout:
        print(text)
    else:
        DOC.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {DOC}")


if __name__ == "__main__":
    main()
