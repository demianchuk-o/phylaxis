"""Attributed recall on the Backstabber split (ADR-031).

    python eval/attribution.py --tag -r6

Per-package recall counts a package as detected whenever its risk crosses the threshold,
whatever the finding was about. For a co-occurrence detector that rewards coincidences: an
`os.system('cls')` next to an unrelated request counts the same as the payload. Backstabber
annotates, for some packages, the file the malicious snippet is in
(``locationOfMaliciousSnippet``). Here a detection is *attributed* when the package is flagged
**and** at least one finding has a step in that file.

The annotation is free text and not always a path in the archive: some carry the sdist's
top directory (`pkg-1.0/setup.py`), some a bare file name, some several files joined by `&`,
and a few name a file of another layout or of an npm package. Each one is resolved against
the archive's own member list (read in memory, nothing extracted): a candidate matches a
member whose trailing path components equal it, with or without its first component. A
package whose annotation resolves to no `.py` member is left out of the attributed
denominator and counted, rather than counted as a miss for every mode alike.

The measure is coarse on purpose and says so: a one-file package, or a `setup.py` package
flagged by any rule in `setup.py`, is attributed whatever the rule was. It bounds the
coincidence share from below; it does not measure it exactly.

Scans each annotated package in every mode with the installed wheel (so run it from the venv
of the ruleset being measured) and writes ``<data>/results/bkc-attribution<tag>.json``.
Nothing is extracted or run here: the scanner reads the archive.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tarfile
from concurrent.futures import ProcessPoolExecutor

import phylaxis

from acquire import DATA
from run import THRESHOLDS

MODES = "ABCD"


def steps_files(report: dict) -> list[str]:
    return sorted({
        s["location"]["path"]
        for f in report["findings"]
        for s in f["evidence"]["path"]["steps"]
        if s.get("location") and s["location"].get("path")
    })


def resolve(entry: dict) -> list[str]:
    """The `.py` members (relative to the sdist's top directory, lower-cased) that the
    annotation names."""
    try:
        with tarfile.open(DATA / entry["file"], "r:gz") as t:
            members = [m.name.split("/", 1)[1].lower() for m in t.getmembers()
                       if m.isfile() and "/" in m.name and m.name.endswith(".py")]
    except (tarfile.TarError, OSError, EOFError):
        return []
    found = set()
    for cand in re.split(r"\s*[&,;]\s*|\s+and\s+", entry["bkc"]["locationOfMaliciousSnippet"]):
        parts = [c for c in cand.strip().lower().split("/") if c]
        if not parts:
            continue
        for m in members:
            mp = m.split("/")
            if mp[-len(parts):] == parts or (len(parts) > 1 and mp[-(len(parts) - 1):] == parts[1:]):
                found.add(m)
    return sorted(found)


def scan(entry: dict) -> dict:
    row = {"id": entry["id"], "name": entry["name"], "overlap": entry["overlap"],
           "snippet": entry["bkc"]["locationOfMaliciousSnippet"], "resolved": resolve(entry)}
    for m in MODES:
        try:
            r = phylaxis.scan(DATA / entry["file"], mode=m)
            row[m] = {"risk": r["risk"], "files": steps_files(r)}
        except Exception as err:  # an error counts as not flagged, as everywhere else
            row[m] = {"error": f"{type(err).__name__}: {err}"}
    return row


def attributed(row: dict, mode: str, tau: float) -> tuple[bool, bool]:
    r = row[mode]
    flagged = (r.get("risk") or 0) >= tau
    return flagged, flagged and any(f.lower() in row["resolved"] for f in r.get("files", []))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--tag", default="", help="result-file suffix of the ruleset, e.g. -r6")
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    args = p.parse_args()
    entries = [e for e in json.loads((DATA / "bkc-manifest.json").read_text(encoding="utf-8"))["entries"]
               if e.get("split") == "bkc" and e["bkc"].get("locationOfMaliciousSnippet")]
    with ProcessPoolExecutor(args.jobs) as ex:
        rows = list(ex.map(scan, entries, chunksize=4))
    summary = {}
    for stratum in ("new", "all"):
        sel = [r for r in rows if (stratum == "all" or r["overlap"] == "new") and r["resolved"]]
        summary[f"{stratum}/unresolved"] = sum(
            1 for r in rows if (stratum == "all" or r["overlap"] == "new") and not r["resolved"])
        for tau_name, tau in THRESHOLDS.items():
            for m in MODES:
                hits = [attributed(r, m, tau) for r in sel]
                summary[f"{stratum}/{tau_name}/{m}"] = {
                    "n": len(sel),
                    "recall": round(sum(h[0] for h in hits) / len(sel), 4),
                    "attributed": round(sum(h[1] for h in hits) / len(sel), 4),
                }
    out = DATA / "results" / f"bkc-attribution{args.tag}.json"
    out.write_text(json.dumps({"ruleset": phylaxis.__version__ if hasattr(phylaxis, "__version__") else None,
                               "summary": summary, "rows": rows}, indent=1) + "\n", encoding="utf-8")
    print(f"{'stratum/tau/mode':<22} {'n':>4} {'recall':>7} {'attrib':>7}")
    for k, v in summary.items():
        if isinstance(v, int):
            print(f"{k:<22} {v:>4}  (annotation names no .py member; left out)")
        else:
            print(f"{k:<22} {v['n']:>4} {v['recall']:>7.3f} {v['attributed']:>7.3f}")


if __name__ == "__main__":
    main()
