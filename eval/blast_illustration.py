"""The ecosystem illustration of ADR-027: blast radius over the top-N PyPI projects.

    python eval/blast_illustration.py fetch [--top 15000]   # declared dependencies, resumable
    python eval/blast_illustration.py report [--top 15000] [--show litellm xinference ...]

Not part of the tool. ``phylaxis project`` ranks findings inside one project's dependency
set; this script asks the same question of the ecosystem's head once, for the evaluation
chapter: how much of the most-downloaded PyPI projects would a compromise of package X reach?

``fetch`` reads each project's ``requires_dist`` from the PyPI JSON API (metadata only, no
package file is downloaded) into ``<data>/blast/top-requires.json``, with the fetch date.
``report`` builds the graph among those N projects — a requirement naming a project outside
them is dropped, and one behind ``extra == ...`` is too, since it is not installed by default —
then prints the projects with the most transitive dependents and the requested ones, and
writes ``<data>/blast/top-blast.csv`` for the figure.

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from acquire import DATA, HERE

OUT = DATA / "blast"
CACHE = OUT / "top-requires.json"


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(req: str) -> str | None:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
    return norm(m.group(1)) if m else None


def top_names(n: int) -> list[str]:
    rows = json.loads((HERE / "top-pypi-packages.json").read_text(encoding="utf-8"))["rows"]
    return [r["project"] for r in rows[:n]]


def fetch_one(name: str) -> tuple[str, list[str] | None]:
    url = f"https://pypi.org/pypi/{name}/json"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                return name, json.load(resp)["info"].get("requires_dist") or []
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return name, None
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(2 * (attempt + 1))
    return name, None


def fetch(top: int, jobs: int) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    doc = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.is_file() else {"requires": {}}
    todo = [n for n in top_names(top) if n not in doc["requires"]]
    print(f"{len(doc['requires'])} cached, {len(todo)} to fetch")
    with ThreadPoolExecutor(jobs) as pool:
        for i, (name, reqs) in enumerate(pool.map(fetch_one, todo), 1):
            doc["requires"][name] = reqs
            if i % 500 == 0 or i == len(todo):
                doc["fetched"] = time.strftime("%Y-%m-%d")
                CACHE.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
                print(f"  {i}/{len(todo)}")


def report(top: int, show: list[str], head: int) -> None:
    doc = json.loads(CACHE.read_text(encoding="utf-8"))
    names = top_names(top)
    rank = {norm(n): i + 1 for i, n in enumerate(names)}
    dependents: dict[str, set[str]] = {norm(n): set() for n in names}
    for name in names:
        for req in doc["requires"].get(name) or []:
            if re.search(r"\bextra\s*==", req):
                continue
            dep = requirement_name(req)
            if dep in dependents and dep != norm(name):
                dependents[dep].add(norm(name))

    def transitive(start: str) -> int:
        seen, queue = {start}, deque([start])
        while queue:
            for d in dependents[queue.popleft()]:
                if d not in seen:
                    seen.add(d)
                    queue.append(d)
        return len(seen) - 1

    rows = sorted(
        ((n, rank[n], len(dependents[n]), transitive(n)) for n in dependents),
        key=lambda r: (-r[3], r[1]),
    )
    with open(OUT / "top-blast.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["project", "download_rank", "direct_dependents", "transitive_dependents"])
        w.writerows(rows)
    known = sum(doc["requires"].get(n) is not None for n in names)
    print(f"top {top} (snapshot {json.loads((HERE / 'top-pypi-packages.json').read_text(encoding='utf-8'))['last_update'][:10]}, "
          f"dependencies fetched {doc.get('fetched')}; {known} with metadata)")
    print(f"{'project':32s} {'rank':>6s} {'direct':>7s} {'transitive':>10s} {'share':>7s}")
    by_name = {r[0]: r for r in rows}
    for r in rows[:head] + [by_name[norm(s)] for s in show if norm(s) in by_name]:
        print(f"{r[0]:32s} {r[1]:6d} {r[2]:7d} {r[3]:10d} {r[3] / (top - 1):7.2%}")
    for s in show:
        if norm(s) not in by_name:
            print(f"{s:32s}  not among the top {top}: no project there depends on it")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("command", choices=["fetch", "report"])
    p.add_argument("--top", type=int, default=15000)
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--head", type=int, default=15)
    p.add_argument("--show", nargs="*", default=[])
    args = p.parse_args()
    if args.command == "fetch":
        fetch(args.top, args.jobs)
    else:
        report(args.top, args.show, args.head)


if __name__ == "__main__":
    main()
