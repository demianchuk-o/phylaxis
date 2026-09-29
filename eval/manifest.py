"""Builds ``eval/manifest.json``: every evaluated file, its label, kind and split
(EVALUATION.md §2–3, ADR-023).

    python eval/manifest.py

Reads what ``acquire.py`` put in the data directory. Datadog samples are read **in memory**:
the encrypted zip is listed and each member hashed without anything being written to disk,
so this step never materialises a sample. The manifest is committed; the archives are not.

Per class (malicious, benign) the split is the protocol's: sort by id, shuffle with the seed
``20261019``, the first 20 are the development set and the rest the test set. Only entries
that count toward the metrics take part in the split; excluded ones keep their reason, for
the coverage table.
"""

from __future__ import annotations

import hashlib
import io
import json
import posixpath
import random
import re
import zipfile
from collections import Counter
from pathlib import Path

from acquire import DATA, HERE

SEED = 20261019
DEV_PER_CLASS = 20
PASSWORD = b"infected"
BUILD_FILES = {"setup.py", "pyproject.toml", "setup.cfg"}

# `malicious_intent/<pkg>/<version>/<date>-<pkg>-v<version>.zip`, or without the version
# directory when Datadog did not record one.
SAMPLE_PATH = re.compile(r"^(?P<cat>[^/]+)/(?P<pkg>[^/]+)/(?:(?P<ver>[^/]+)/)?[^/]+\.zip$")


def content_id(members: dict[str, bytes], root: str) -> str:
    """sha256 over the sorted (path relative to the package root, sha256 of bytes) pairs.

    WHY not the zip's own hash: Datadog's zips are re-packed with their own timestamps, so
    two identical packages give two different zips. The content under the package root is
    what an sdist of that package would have held, and what the protocol deduplicates on.
    """
    h = hashlib.sha256()
    for path in sorted(members):
        rel = posixpath.relpath(path, root) if root else path
        h.update(rel.encode() + b"\0" + hashlib.sha256(members[path]).digest())
    return h.hexdigest()


def classify(names: list[str]) -> tuple[str, str]:
    """(kind, package root). `sdist` when a build file is present (an unpacked sdist),
    `wheel` when only `*.dist-info` metadata is (an unpacked wheel, out of scope by
    invariant 2), `other` otherwise. The root is the shallowest directory holding a build
    file, which is where `phylaxis.scan` is pointed."""
    build = [n for n in names if posixpath.basename(n) in BUILD_FILES]
    if build:
        shallowest = min(build, key=lambda n: (n.count("/"), n))
        return "sdist", posixpath.dirname(shallowest)
    if any(".dist-info/" in n for n in names):
        return "wheel", ""
    return "other", ""


def datadog_entries() -> list[dict]:
    base = DATA / "datadog"
    labels = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    listing = json.loads((base / "listing.json").read_text(encoding="utf-8"))
    out = []
    for f in listing["files"]:
        m = SAMPLE_PATH.match(f["path"])
        e = {
            "source": "datadog",
            "label": "malicious",
            "file": f"datadog/samples/{f['path']}",
            "name": m["pkg"] if m else None,
            "version": m["ver"] if m else None,
            "category": m["cat"] if m else None,
        }
        out.append(e)
        path = DATA / e["file"]
        if not path.is_file():
            e["excluded"] = "not downloaded"
            continue
        # Label (Datadog README): a `null` manifest entry marks malicious intent, so every
        # version counts; a list names the compromised versions of an otherwise benign
        # project, and any other version is not labelled malicious.
        if e["name"] not in labels:
            e["excluded"] = "not in Datadog manifest"
        elif labels[e["name"]] is not None and e["version"] not in labels[e["name"]]:
            e["excluded"] = "version not listed as compromised"
        try:
            with zipfile.ZipFile(path) as z:
                names = [n for n in z.namelist() if not n.endswith("/")]
                kind, root = classify(names)
                members = {n: z.read(n, pwd=PASSWORD) for n in names if not root or n.startswith(root + "/")}
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as err:
            e.setdefault("excluded", f"unreadable zip: {err}")
            continue
        e.update(kind=kind, root=root, py_files=sum(n.endswith(".py") for n in members))
        e["id"] = content_id(members, root)
        if kind != "sdist":
            e.setdefault("excluded", f"unpacked {kind}, not an sdist (invariant 2)")
        elif e["py_files"] == 0:
            e.setdefault("excluded", "no Python source")
    return out


def benign_entries() -> list[dict]:
    index = json.loads((DATA / "benign" / "index.json").read_text(encoding="utf-8"))
    out = []
    for project, v in sorted(index.items(), key=lambda kv: kv[1].get("rank", 0)):
        e = {"source": "top-pypi", "label": "benign", "name": project, "version": v.get("version"), "rank": v.get("rank")}
        if v.get("file"):
            e.update(file=f"benign/{v['file']}", kind="sdist", id=v["sha256"])
        else:
            e["excluded"] = "no .tar.gz sdist" if v.get("no_sdist") else ("too large" if v.get("too_large") else f"download failed: {v.get('error')}")
        out.append(e)
    return out


def split(entries: list[dict]) -> None:
    """EVALUATION.md §3, per class. A duplicate id is excluded after its first occurrence
    (in id order, so the choice does not depend on download order)."""
    for label in ("malicious", "benign"):
        pool = sorted((e for e in entries if e["label"] == label and "excluded" not in e), key=lambda e: (e["id"], e.get("file", "")))
        seen, unique = set(), []
        for e in pool:
            if e["id"] in seen:
                e["excluded"] = "duplicate content"
            else:
                seen.add(e["id"])
                unique.append(e)
        random.Random(SEED).shuffle(unique)
        for i, e in enumerate(unique):
            e["split"] = "dev" if i < DEV_PER_CLASS else "test"


def main() -> None:
    entries = datadog_entries() + benign_entries()
    split(entries)
    counts = Counter((e["label"], e.get("split") or "excluded") for e in entries)
    reasons = Counter((e["label"], e["excluded"].split(":")[0]) for e in entries if "excluded" in e)
    doc = {
        "protocol": "EVALUATION.md §2-3, ADR-023",
        "seed": SEED,
        "datadog_commit": json.loads((DATA / "datadog" / "listing.json").read_text(encoding="utf-8"))["commit"],
        "top_pypi_snapshot": json.loads((HERE / "top-pypi-packages.json").read_text(encoding="utf-8")).get("last_update"),
        "counts": {f"{k[0]}/{k[1]}": v for k, v in sorted(counts.items())},
        "excluded": {f"{k[0]}/{k[1]}": v for k, v in sorted(reasons.items())},
        "entries": entries,
    }
    (HERE / "manifest.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"counts": doc["counts"], "excluded": doc["excluded"]}, indent=1))


if __name__ == "__main__":
    main()
