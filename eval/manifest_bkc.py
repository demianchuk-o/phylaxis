"""Builds ``<data>/bkc-manifest.json``: the Backstabber's Knife Collection PyPI subset as a
third evaluation split, ``bkc`` (ADR-026).

    python eval/manifest_bkc.py

Every BKC entry is malicious, and every one goes to the ``bkc`` split: the development set
was drawn from the main manifest before BKC was available and is not redrawn. Each entry is
tagged with its overlap with the main manifest, so the report can give the BKC numbers both
over everything and over the packages no earlier run has seen.

The samples are the original sdist files, so the unit is the one §2 first defined: one
``.tar.gz``, identified by the sha256 of the file, scanned as an archive. Archives are read
**in memory** to compute the ADR-023 content id (for the overlap with Datadog's unpacked
samples); nothing is extracted to disk here.

The manifest is written to the data directory, not committed: the package list came with
dataset access, and stays with the dataset.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import urllib.parse
from collections import Counter
from pathlib import Path

from acquire import DATA, HERE
from manifest import classify, content_id

BKC = DATA / "Backstabber's Knife Collection"
SAMPLES = BKC / "samples" / "pypi"
OUT = DATA / "bkc-manifest.json"
# The archive is attacker-controlled; reading it in memory must not become a memory bomb.
MAX_MEMBER = 64 << 20
MAX_TOTAL = 256 << 20
INDEX_FIELDS = ("trigger", "objective", "locationOfMaliciousSnippet", "targetedOS",
                "conditional", "obfuscated", "injectionComponent", "typoTarget", "campaign")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tar_content_id(path: Path) -> tuple[str | None, int, str | None]:
    """(content id, .py files under the package root, problem). Same id as ADR-023's over
    Datadog zips, so the same package unpacked by Datadog and archived by BKC matches."""
    try:
        with tarfile.open(path, "r:gz") as t:
            files = [m for m in t.getmembers() if m.isfile()]
            if sum(m.size for m in files) > MAX_TOTAL or any(m.size > MAX_MEMBER for m in files):
                return None, 0, "too large to hash in memory"
            names = [m.name for m in files]
            _, root = classify(names)
            members = {}
            for m in files:
                if root and not m.name.startswith(root + "/"):
                    continue
                f = t.extractfile(m)
                members[m.name] = f.read() if f else b""
    except (tarfile.TarError, OSError, EOFError) as err:
        return None, 0, f"unreadable archive: {err}"
    return content_id(members, root), sum(n.endswith(".py") for n in members), None


def index_metadata() -> dict[tuple[str, str], dict]:
    """(normalised name, version) → the index fields that carry a value."""
    out = {}
    for line in (BKC / "package_index.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        purl = r["purl"]["value"]
        if not purl.startswith("pkg:pypi/"):
            continue
        name, _, ver = purl[len("pkg:pypi/"):].partition("@")
        meta = {k: r[k]["value"] for k in INDEX_FIELDS if r.get(k, {}).get("value") not in (None, "", [])}
        out[(norm(urllib.parse.unquote(name)), urllib.parse.unquote(ver))] = meta
    return out


def main() -> None:
    main_manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))["entries"]
    datadog = [e for e in main_manifest if e["source"] == "datadog"]
    by_content = {e["id"]: e.get("split") or "excluded" for e in datadog if e.get("id")}
    by_name_ver = {(norm(e["name"]), e["version"]): e.get("split") or "excluded" for e in datadog if e.get("name")}
    meta = index_metadata()

    entries = []
    for vdir in sorted(p for p in SAMPLES.glob("*/*") if p.is_dir()):
        pkg, ver = vdir.parent.name, vdir.name
        files = sorted(f for f in vdir.rglob("*") if f.is_file())
        sdists = [f for f in files if f.name.endswith(".tar.gz")]
        base = {"source": "bkc", "label": "malicious", "name": pkg, "version": ver,
                "bkc": meta.get((norm(pkg), ver), {})}
        if not sdists:
            kinds = sorted({f.suffix or f.name for f in files if f.name != "meta.json.zst"})
            reason = "wheel-only (invariant 2)" if ".whl" in kinds else f"no sdist ({', '.join(kinds) or 'empty'})"
            entries.append({**base, "excluded": reason})
            continue
        for f in sdists:
            e = {**base, "file": f.relative_to(DATA).as_posix(), "kind": "sdist", "id": sha256_file(f)}
            cid, py, problem = tar_content_id(f)
            e.update(content_id=cid, py_files=py)
            if problem and problem.startswith("unreadable"):
                e["excluded"] = problem
            elif problem:
                e["note"] = problem  # still scanned; overlap falls back to name and version
            elif py == 0:
                e["excluded"] = "no Python source"
            dd = by_content.get(cid) if cid else None
            e["overlap"] = (f"datadog-{dd}" if dd else
                            f"datadog-{by_name_ver[(norm(pkg), ver)]}-name" if (norm(pkg), ver) in by_name_ver else
                            "new")
            entries.append(e)

    # Duplicates by file hash: first in hash order counts, as in manifest.split.
    seen = set()
    for e in sorted((e for e in entries if "excluded" not in e), key=lambda e: (e["id"], e["file"])):
        if e["id"] in seen:
            e["excluded"] = "duplicate content"
        else:
            seen.add(e["id"])
            e["split"] = "bkc"

    counted = [e for e in entries if e.get("split") == "bkc"]
    doc = {
        "protocol": "EVALUATION.md §2, ADR-026",
        "bkc_version": json.loads((BKC / "version.json").read_text(encoding="utf-8")),
        "counts": {"versions": len({(e["name"], e["version"]) for e in entries}), "bkc": len(counted),
                   "excluded": dict(Counter(e["excluded"].split(":")[0] for e in entries if "excluded" in e))},
        "overlap": dict(Counter(e["overlap"] for e in counted)),
        "with_trigger": sum("trigger" in e["bkc"] for e in counted),
        "entries": entries,
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: doc[k] for k in ("counts", "overlap", "with_trigger")}, indent=1))


if __name__ == "__main__":
    main()
