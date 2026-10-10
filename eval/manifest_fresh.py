"""Builds ``<data>/fresh-manifest.json``: a holdout of malicious PyPI sdists that no earlier
run, and no reading of the data, has touched, as the split ``fresh`` (ADR-031).

    python eval/manifest_fresh.py

Why it exists. Rulesets 3–5 were shaped by errors read on the Datadog test set, and ruleset 6
by packages read from Backstabber's Knife Collection, so neither set is an unseen measurement
any more. Datadog added no PyPI samples after the manifest commit, so the holdout comes from
a third collection: ``pypi_malregistry`` (Guo et al., 2023), pinned at ``COMMIT``.

Selection, fixed before any scan: every ``<name>/<version>/<file>.tar.gz`` whose (name,
version) is absent from both earlier manifests; one version per name (campaigns publish the
same payload under many versions); a seeded shuffle; the first ``SAMPLE`` names. The archives
are downloaded to ``<data>/malregistry/`` and read **in memory** for the ADR-023 content id,
which tags each entry's overlap with Datadog and BKC by content as well; an entry whose content
was already seen is excluded, not merely tagged, since the point of the split is that it is
unseen. Nothing is extracted or executed here.
"""

from __future__ import annotations

import json
import random
import re
import urllib.parse
from collections import Counter

from acquire import DATA, HERE, get, write_atomic
from manifest_bkc import norm, sha256_file, tar_content_id

REPO = "lxyeternal/pypi_malregistry"
COMMIT = "5f2592d2d750a1beb68e8ed1a5a63fcd1905899c"
SEED = 20261010
SAMPLE = 2000
OUT = DATA / "fresh-manifest.json"
BASE = DATA / "malregistry"
SDIST = re.compile(r"^(?P<pkg>[^/]+)/(?P<ver>[^/]+)/[^/]+\.tar\.gz$")


def main() -> None:
    commit = json.loads(get(f"https://api.github.com/repos/{REPO}/commits/{COMMIT}"))["sha"]
    tree = json.loads(get(f"https://api.github.com/repos/{REPO}/git/trees/{commit}?recursive=1"))
    if tree.get("truncated"):
        raise SystemExit("git tree listing was truncated; cannot enumerate samples reliably")
    listing = [e for e in tree["tree"] if e["type"] == "blob" and SDIST.match(e["path"])]
    write_atomic(BASE / "listing.json", json.dumps(
        {"commit": commit, "files": [{"path": e["path"], "size": e["size"]} for e in listing]}, indent=1).encode())

    main_entries = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))["entries"]
    bkc_entries = json.loads((DATA / "bkc-manifest.json").read_text(encoding="utf-8"))["entries"]
    seen_nv = {(norm(e["name"]), e.get("version")) for e in main_entries + bkc_entries if e.get("name")}
    seen_content = {e[k]: f"{e['source']}-{e.get('split') or 'excluded'}"
                    for e in main_entries + bkc_entries for k in ("id", "content_id") if e.get(k)}

    by_name: dict[str, list[dict]] = {}
    for e in listing:
        m = SDIST.match(e["path"])
        if (norm(m["pkg"]), m["ver"]) not in seen_nv:
            by_name.setdefault(norm(m["pkg"]), []).append(e)
    rng = random.Random(SEED)
    names = sorted(by_name)
    rng.shuffle(names)
    picked = [rng.choice(sorted(by_name[n], key=lambda e: e["path"])) for n in names[:SAMPLE]]

    raw = f"https://raw.githubusercontent.com/{REPO}/{commit}/"
    entries = []
    for i, f in enumerate(picked, 1):
        m = SDIST.match(f["path"])
        e = {"source": "malregistry", "label": "malicious", "name": m["pkg"], "version": m["ver"],
             "file": f"malregistry/{f['path']}", "kind": "sdist"}
        entries.append(e)
        target = DATA / e["file"]
        if not (target.is_file() and target.stat().st_size == f["size"]):
            try:
                data = get(raw + urllib.parse.quote(f["path"]))
                if len(data) != f["size"]:
                    raise ValueError(f"size {len(data)} != listed {f['size']}")
                write_atomic(target, data)
            except Exception as err:  # a failed download is a coverage row
                e["excluded"] = f"download failed: {err}"
                continue
        e["id"] = sha256_file(target)
        cid, py, problem = tar_content_id(target)
        e.update(content_id=cid, py_files=py)
        if problem and problem.startswith("unreadable"):
            e["excluded"] = problem
        elif problem:
            e["note"] = problem
        elif py == 0:
            e["excluded"] = "no Python source"
        seen = seen_content.get(e["id"]) or (seen_content.get(cid) if cid else None)
        if seen:
            e.setdefault("excluded", f"content already seen ({seen})")
        if i % 200 == 0:
            print(f"fresh: {i}/{len(picked)}", flush=True)

    dup = set()
    for e in sorted((e for e in entries if "excluded" not in e), key=lambda e: (e["id"], e["file"])):
        if e["id"] in dup or (e["content_id"] and e["content_id"] in dup):
            e["excluded"] = "duplicate content"
        else:
            dup.update(x for x in (e["id"], e["content_id"]) if x)
            e["split"] = "fresh"

    counted = [e for e in entries if e.get("split") == "fresh"]
    doc = {
        "protocol": "EVALUATION.md §2, ADR-031",
        "source": {"repo": REPO, "commit": commit, "listed_sdists": len(listing),
                   "unseen_names": len(by_name), "seed": SEED, "sample": SAMPLE},
        "counts": {"picked": len(entries), "fresh": len(counted),
                   "excluded": dict(Counter(e["excluded"].split(" (")[0].split(":")[0]
                                            for e in entries if "excluded" in e))},
        "entries": entries,
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: doc[k] for k in ("source", "counts")}, indent=1))


if __name__ == "__main__":
    main()
