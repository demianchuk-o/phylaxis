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

Nothing here imports or runs a sample: the scanner reads files, and so does this script.
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import shutil
import time
import zipfile
from pathlib import Path

import phylaxis

from acquire import DATA, HERE
from manifest import PASSWORD

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
        )
    return row


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
    p.add_argument("--split", choices=["dev", "test"], default="dev")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--mode", choices=list("ABCD"), default="D")
    mode.add_argument("--all-modes", action="store_true")
    args = p.parse_args()

    entries = [e for e in json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))["entries"] if e.get("split") == args.split]
    (DATA / "results").mkdir(parents=True, exist_ok=True)
    for m in ("ABCD" if args.all_modes else args.mode):
        rows = [scan_entry(e, m) for e in entries]
        out = DATA / "results" / f"{args.split}-{m}.jsonl"
        out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        print(f"== {args.split} mode {m} ({out})")
        print(json.dumps(metrics(rows), indent=1))


if __name__ == "__main__":
    main()
