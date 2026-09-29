"""Dataset acquisition for the evaluation (EVALUATION.md §2, ADR-023).

    python eval/acquire.py datadog   # malicious: the Datadog PyPI samples, kept encrypted
    python eval/acquire.py benign    # benign: sdists of the top-downloaded PyPI projects

Everything lands under the data directory, ``$PHYLAXIS_EVAL_DATA`` or ``../eval-data``
next to the repository; nothing downloaded is ever committed. Both commands are resumable:
a file already on disk with the expected size (Datadog) or sha256 (PyPI) is skipped.

Nothing here decrypts, extracts, imports or runs a sample. The Datadog zips stay encrypted
on disk (password ``infected``); ``manifest.py`` only *lists* their entries, and ``run.py``
is the one place a sample is ever unpacked, for the duration of its scan.

Standard library only, so the harness runs on any CPython >= 3.9 with the phylaxis wheel.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("PHYLAXIS_EVAL_DATA", HERE.parent.parent / "eval-data"))

DATADOG_REPO = "DataDog/malicious-software-packages-dataset"
DATADOG_RAW = f"https://raw.githubusercontent.com/{DATADOG_REPO}/main/samples/pypi/"

# The benign snapshot is committed next to this file, so the benign set is reproducible even
# after the upstream list moves on. EVALUATION.md §2: the latest sdist per project at the
# snapshot date.
TOP_PYPI_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
TOP_PYPI_SNAPSHOT = HERE / "top-pypi-packages.json"
BENIGN_TARGET = 1000
MAX_SDIST_BYTES = 512 * 1024 * 1024
USER_AGENT = "phylaxis-eval (research; https://github.com/demianchuk-o/phylaxis)"


def get(url: str, attempts: int = 4) -> bytes:
    """GET with a few retries and backoff; raises the last error."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404 or i == attempts - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if i == attempts - 1:
                raise
        time.sleep(2**i)
    raise AssertionError("unreachable")


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    tmp.write_bytes(data)
    tmp.replace(path)


# --- malicious: Datadog -------------------------------------------------------------------


def datadog() -> None:
    """Downloads every PyPI sample zip plus the label manifest and the file listing.

    The listing (git tree) is saved as well: it pins exactly which files the evaluation saw,
    and its per-file sizes are what makes the download resumable.
    """
    out = DATA / "datadog"
    commit = json.loads(get(f"https://api.github.com/repos/{DATADOG_REPO}/commits/main"))["sha"]
    samples = json.loads(get(f"https://api.github.com/repos/{DATADOG_REPO}/contents/samples?ref={commit}"))
    pypi_sha = next(x["sha"] for x in samples if x["name"] == "pypi")
    tree = json.loads(get(f"https://api.github.com/repos/{DATADOG_REPO}/git/trees/{pypi_sha}?recursive=1"))
    if tree.get("truncated"):
        sys.exit("git tree listing was truncated; cannot enumerate samples reliably")
    zips = sorted((e for e in tree["tree"] if e["path"].endswith(".zip")), key=lambda e: e["path"])

    raw = f"https://raw.githubusercontent.com/{DATADOG_REPO}/{commit}/samples/pypi/"
    write_atomic(out / "manifest.json", get(raw + "manifest.json"))
    write_atomic(
        out / "listing.json",
        json.dumps({"commit": commit, "files": [{"path": e["path"], "size": e["size"]} for e in zips]}, indent=1).encode(),
    )

    done = failed = 0
    for n, e in enumerate(zips, 1):
        target = out / "samples" / e["path"]
        if target.is_file() and target.stat().st_size == e["size"]:
            done += 1
            continue
        try:
            data = get(raw + urllib.parse.quote(e["path"]))
            if len(data) != e["size"]:
                raise ValueError(f"size {len(data)} != listed {e['size']}")
            write_atomic(target, data)
            done += 1
        except Exception as err:  # one bad sample is a coverage row, not a stopped run
            failed += 1
            print(f"  failed {e['path']}: {err}", file=sys.stderr)
        if n % 100 == 0:
            print(f"datadog: {n}/{len(zips)}", flush=True)
    print(f"datadog: {done} samples on disk, {failed} failed, commit {commit[:12]}")


# --- benign: top PyPI -------------------------------------------------------------------------


def benign() -> None:
    """Downloads the latest sdist of the most-downloaded projects until BENIGN_TARGET sdists
    are on disk, walking down the ranking. Projects without a `.tar.gz` sdist are recorded
    as such in `benign/index.json` (the coverage table), never silently skipped.
    """
    out = DATA / "benign"
    if not TOP_PYPI_SNAPSHOT.is_file():
        write_atomic(TOP_PYPI_SNAPSHOT, get(TOP_PYPI_URL))
    ranking = json.loads(TOP_PYPI_SNAPSHOT.read_text(encoding="utf-8"))
    index_path = out / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.is_file() else {}

    have = sum(1 for v in index.values() if v.get("file"))
    for rank, row in enumerate(ranking["rows"], 1):
        if have >= BENIGN_TARGET:
            break
        project = row["project"]
        entry = index.get(project)
        if entry and (not entry.get("file") or (out / entry["file"]).is_file()):
            continue
        try:
            entry = fetch_latest_sdist(project, out)
        except Exception as err:
            entry = {"error": str(err)}
        entry["rank"] = rank
        index[project] = entry
        have += bool(entry.get("file"))
        if rank % 50 == 0:
            write_atomic(index_path, json.dumps(index, indent=1, sort_keys=True).encode())
            print(f"benign: rank {rank}, {have} sdists", flush=True)
    write_atomic(index_path, json.dumps(index, indent=1, sort_keys=True).encode())
    print(f"benign: {have} sdists from snapshot {ranking.get('last_update')}")


def fetch_latest_sdist(project: str, out: Path) -> dict:
    meta = json.loads(get(f"https://pypi.org/pypi/{urllib.parse.quote(project)}/json"))
    version = meta["info"]["version"]
    sdists = [u for u in meta.get("urls", []) if u["packagetype"] == "sdist" and u["filename"].endswith(".tar.gz")]
    if not sdists:
        return {"version": version, "no_sdist": True}
    u = sdists[0]
    name = u["filename"]
    # The same guards as the fetcher crate: official host only, a plain file name, a size
    # cap, and the published sha256.
    host = urllib.parse.urlsplit(u["url"]).hostname
    if host not in ("files.pythonhosted.org", "pypi.org") or "/" in name or "\\" in name or name.startswith("."):
        raise ValueError(f"refusing {u['url']!r}")
    if u.get("size", 0) > MAX_SDIST_BYTES:
        return {"version": version, "too_large": u["size"]}
    target = out / "sdists" / name
    want = u["digests"]["sha256"]
    if not (target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == want):
        data = get(u["url"])
        if hashlib.sha256(data).hexdigest() != want:
            raise ValueError("sha256 mismatch")
        write_atomic(target, data)
    return {"version": version, "file": f"sdists/{name}", "sha256": want}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("dataset", choices=["datadog", "benign"])
    args = p.parse_args()
    print(f"data directory: {DATA}")
    {"datadog": datadog, "benign": benign}[args.dataset]()


if __name__ == "__main__":
    main()
