"""Runs phylaxis over one split of ``eval/manifest.json`` and scores it (EVALUATION.md §4).

    python eval/run.py --split dev --mode D
    python eval/run.py --split dev --all-modes

Writes one JSON line per manifest entry to ``<data>/results/<split>-<mode>.jsonl`` and prints
the metric row at both operating points. Development-set numbers stay in the data directory
(TASKS T-14); only the test-set runs of T-15 feed ``docs/RESULTS.md``.

A benign entry is an sdist and is scanned as the archive, through phylaxis's own safe
extraction. A Datadog entry is an unpacked sample inside an encrypted zip (ADR-023): it is
unpacked into ``$PHYLAXIS_EVAL_WORK`` (default ``<data>/unpacked``), scanned as a directory,
and deleted before the next one. That folder is the only place a sample ever exists as
plain files, which is why it is the one folder an antivirus exclusion has to cover.

Each sample is scanned in a worker process of its own (``--jobs`` at a time), under a
``--timeout``. A scan that aborts, runs out of memory or hangs costs its own row, marked as
an error, and never the run.

Nothing here imports or runs a sample: the scanner reads files, and so does this script.
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import phylaxis

from acquire import DATA, HERE
from manifest import PASSWORD
from resume import run_resumable

WORK = Path(os.environ.get("PHYLAXIS_EVAL_WORK", DATA / "unpacked"))
THRESHOLDS = {"primary": 0.40, "strict": 0.70}


def unpack(entry: dict) -> tuple[Path, list[Path]]:
    """Unpacks the sample's package root into a fresh directory under WORK and returns it
    with the list of files written. Member names are validated before anything is written:
    no absolute paths, drive letters or `..` (the zips are Datadog's, but they are still
    input to this script)."""
    target = WORK / entry["id"][:16]
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    root = entry["root"]
    written = []
    with zipfile.ZipFile(DATA / entry["file"]) as z:
        for info in z.infolist():
            name = info.filename
            if info.is_dir() or (root and not name.startswith(root + "/")):
                continue
            rel = posixpath.relpath(name, root) if root else name
            parts = rel.replace("\\", "/").split("/")
            if rel.startswith(("/", "\\")) or ".." in parts or ":" in parts[0]:
                raise ValueError(f"unsafe member name {name!r}")
            dest = target.joinpath(*parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(z.read(info, pwd=PASSWORD))
            written.append(dest)
    return target, written


def unreadable(files: list[Path]) -> list[str]:
    """Files that vanished or cannot be read any more. An antivirus that quarantines or
    blocks a file mid-scan would otherwise turn into a silent false negative."""
    bad = []
    for f in files:
        try:
            with open(f, "rb") as fh:
                fh.read(1)
        except OSError:
            bad.append(f.name)
    return bad


def scan_entry(entry: dict, mode: str) -> dict:
    row = {k: entry.get(k) for k in ("id", "label", "source", "name", "version")}
    start = time.perf_counter()
    try:
        if entry["source"] == "datadog":
            target, files = unpack(entry)
            try:
                report = phylaxis.scan(target, mode=mode)
                bad = unreadable(files)
            finally:
                shutil.rmtree(target, ignore_errors=True)
            if bad:
                row["error"] = f"files unreadable after scan (antivirus?): {bad[:5]}"
        else:
            report = phylaxis.scan(DATA / entry["file"], mode=mode)
    except Exception as err:  # a failed input is a coverage row, never a stopped run
        row["error"] = f"{type(err).__name__}: {err}"
        report = None
    row["seconds"] = round(time.perf_counter() - start, 4)
    if report is not None:
        row.update(
            verdict=report["verdict"],
            risk=report["risk"],
            skipped=report.get("skipped"),
            rules=sorted({f["rule"] for f in report["findings"]}),
            findings=len(report["findings"]),
            # ADR-030: findings whose sink sits under an environment guard.
            conditional=sum(bool(f["evidence"]["path"].get("conditional")) for f in report["findings"]),
            **finding_summary(report["findings"]),
        )
    return row


def finding_summary(findings: list[dict]) -> dict:
    """Findings folded into distinct shapes, enough to recompute the package risk under a
    filter (confidence, phase, path length) without rescanning. A large package can carry
    tens of thousands of paths that differ only in location; their shapes are a handful.

    `shapes`: [rule, objective, path kind, score, confidence, phase, steps, ambiguous
    steps, count]. `sinks`: distinct (rule, sink file, sink line), the per-finding cost an
    auditor sees once duplicate paths to one call are merged."""
    shapes: dict[tuple, int] = {}
    sinks = set()
    for f in findings:
        path = f["evidence"]["path"]
        steps = path["steps"]
        key = (
            f["rule"], f["technique"]["objective"], path["kind"], round(f["score"], 4),
            f["confidence"], f["phase"], len(steps),
            sum(s["symbol"].startswith("<any of") for s in steps),
        )
        shapes[key] = shapes.get(key, 0) + 1
        end = steps[-1]["location"] if steps else {}
        sinks.add((f["rule"], end.get("path"), end.get("span", {}).get("start_line")))
    return {"shapes": [[*k, n] for k, n in sorted(shapes.items())], "sinks": len(sinks)}


def isolated(entry: dict, mode: str, timeout: float) -> dict:
    """`scan_entry` in a fresh worker process. The scanner is native code: an abort or an
    out-of-memory kill cannot be caught in-process, and would end the whole run."""
    row = {k: entry.get(k) for k in ("id", "label", "source", "name", "version")}
    start = time.perf_counter()
    try:
        done = subprocess.run(
            [sys.executable, __file__, "--worker", mode],
            input=json.dumps(entry),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        if entry.get("source") == "datadog":
            shutil.rmtree(WORK / entry["id"][:16], ignore_errors=True)
        row.update(error=f"timeout after {timeout:g} s", seconds=round(time.perf_counter() - start, 4))
        return row
    lines = done.stdout.strip().splitlines()
    if done.returncode != 0 or not lines:
        if entry.get("source") == "datadog":
            shutil.rmtree(WORK / entry["id"][:16], ignore_errors=True)
        tail = (done.stderr.strip().splitlines() or ["no output"])[-1]
        row.update(error=f"worker exited {done.returncode}: {tail[:200]}", seconds=round(time.perf_counter() - start, 4))
        return row
    return json.loads(lines[-1])


def metrics(rows: list[dict]) -> dict:
    """EVALUATION.md §4. Errored and skipped inputs are reported and left out of the
    confusion matrix, never counted as a pass or a miss."""
    scored = [r for r in rows if "risk" in r and not r.get("skipped")]
    out = {"inputs": len(rows), "scored": len(scored), "errors": sum("error" in r for r in rows)}
    for name, tau in THRESHOLDS.items():
        tp = sum(r["label"] == "malicious" and r["risk"] >= tau for r in scored)
        fn = sum(r["label"] == "malicious" and r["risk"] < tau for r in scored)
        fp = sum(r["label"] == "benign" and r["risk"] >= tau for r in scored)
        tn = sum(r["label"] == "benign" and r["risk"] < tau for r in scored)
        p = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        out[name] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(p, 4), "recall": round(rec, 4),
            "f1": round(2 * p * rec / (p + rec), 4) if p + rec else 0.0,
            "fp_per_1000_benign": round(fp * 1000 / (fp + tn), 1) if fp + tn else 0.0,
        }
    benign = [r for r in scored if r["label"] == "benign"]
    out["noise"] = round(sum(r["findings"] for r in benign) / len(benign), 3) if benign else 0.0
    times = sorted(r["seconds"] for r in rows)
    if times:
        out["median_seconds"] = times[len(times) // 2]
        out["p95_seconds"] = times[min(len(times) - 1, int(len(times) * 0.95))]
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--split", choices=["dev", "test", "bkc"], default="dev")
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="worker processes at a time")
    p.add_argument("--timeout", type=float, default=300.0, help="seconds per sample")
    p.add_argument("--tag", default="", help="suffix for the result files, e.g. -r3 for another ruleset")
    p.add_argument("--worker", metavar="MODE", help=argparse.SUPPRESS)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--mode", choices=list("ABCD"), default="D")
    mode.add_argument("--all-modes", action="store_true")
    args = p.parse_args()
    if args.worker:
        # One sample from stdin, one row to stdout: the unit `isolated` runs in a process.
        print(json.dumps(scan_entry(json.loads(sys.stdin.read()), args.worker)))
        return

    # ADR-026: the Backstabber split has its own manifest, kept with the dataset.
    manifest = DATA / "bkc-manifest.json" if args.split == "bkc" else HERE / "manifest.json"
    entries = [e for e in json.loads(manifest.read_text(encoding="utf-8"))["entries"] if e.get("split") == args.split]
    (DATA / "results").mkdir(parents=True, exist_ok=True)
    for m in ("ABCD" if args.all_modes else args.mode):
        out = DATA / "results" / f"{args.split}-{m}{args.tag}.jsonl"
        rows = run_resumable(
            entries, lambda e, m=m: isolated(e, m, args.timeout), out, args.jobs, f"phylaxis {m}"
        )
        print(f"== {args.split} mode {m} ({out})")
        print(json.dumps(metrics(rows), indent=1))


if __name__ == "__main__":
    main()
