"""Adds a benign half to the holdout split ``fresh`` (ADR-031): sdists no run has read.

    python eval/manifest_fresh_benign.py

The benign test set (980 sdists of the top 1 000 PyPI projects) was read while rulesets 3–5
were shaped, so its false-positive count is post-hoc for every later ruleset. This draws the
next ``TARGET`` sdists down the same committed ranking snapshot (``top-pypi-packages.json``),
starting below the lowest rank the benign set used, with the same rule as ``acquire.benign``:
the latest ``.tar.gz`` sdist of each project, from the official index only, checked against
the published sha256. Projects without one are recorded and skipped, never silently.

The entries are appended to ``<data>/fresh-manifest.json`` with ``split: fresh`` and
``label: benign``; the malicious entries are not touched. An sdist whose hash is already in
the benign set is left out. Nothing is extracted or run here.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import date

from acquire import DATA, TOP_PYPI_SNAPSHOT, fetch_latest_sdist, write_atomic

TARGET = 1000
OUT = DATA / "benign-fresh"
MANIFEST = DATA / "fresh-manifest.json"


def main() -> None:
    ranking = json.loads(TOP_PYPI_SNAPSHOT.read_text(encoding="utf-8"))["rows"]
    used = json.loads((DATA / "benign" / "index.json").read_text(encoding="utf-8"))
    start = max(v.get("rank", 0) for v in used.values())
    known = {v["sha256"] for v in used.values() if v.get("sha256")}

    index_path = OUT / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.is_file() else {}
    have = sum(1 for v in index.values() if v.get("file"))
    for rank, row in enumerate(ranking, 1):
        if rank <= start:
            continue
        if have >= TARGET:
            break
        project = row["project"]
        entry = index.get(project)
        if entry and (not entry.get("file") or (OUT / entry["file"]).is_file()):
            continue
        try:
            entry = fetch_latest_sdist(project, OUT)
        except Exception as err:  # a failed download is a coverage row
            entry = {"error": str(err)}
        if entry.get("sha256") in known:
            entry = {"version": entry.get("version"), "duplicate_of_benign_set": True}
        entry["rank"] = rank
        index[project] = entry
        have += bool(entry.get("file"))
        if rank % 100 == 0:
            write_atomic(index_path, json.dumps(index, indent=1, sort_keys=True).encode())
            print(f"benign-fresh: rank {rank}, {have} sdists", flush=True)
    write_atomic(index_path, json.dumps(index, indent=1, sort_keys=True).encode())

    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    doc["entries"] = [e for e in doc["entries"] if e["label"] != "benign"]
    for project, v in sorted(index.items(), key=lambda kv: kv[1].get("rank", 0)):
        e = {"source": "top-pypi", "label": "benign", "name": project, "version": v.get("version"),
             "rank": v.get("rank")}
        if v.get("file"):
            e.update(file=f"benign-fresh/{v['file']}", kind="sdist", id=v["sha256"], split="fresh")
        else:
            e["excluded"] = ("no .tar.gz sdist" if v.get("no_sdist") else
                             "too large" if v.get("too_large") else
                             "already in the benign set" if v.get("duplicate_of_benign_set") else
                             f"download failed: {v.get('error')}")
        doc["entries"].append(e)
    ranks = [v["rank"] for v in index.values() if v.get("file")]
    doc["benign"] = {"snapshot": TOP_PYPI_SNAPSHOT.name, "ranks": [min(ranks), max(ranks)] if ranks else None,
                     "downloaded": date.today().isoformat(), "sdists": len(ranks),
                     "excluded": dict(Counter(e["excluded"].split(":")[0] for e in doc["entries"]
                                              if e["label"] == "benign" and "excluded" in e))}
    MANIFEST.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(doc["benign"], indent=1))


if __name__ == "__main__":
    main()
