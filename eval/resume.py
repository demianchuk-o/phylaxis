"""Resumable batch runs for the evaluation (shared by ``run.py`` and ``baselines.py``).

A test-set run is hours long. Each finished row is appended to ``<out>.partial.jsonl`` the
moment it exists, and a restarted run skips every id already there, so a reboot or a killed
session costs the rows in flight, not the run. When every entry has a row, the final file is
written in manifest order and the partial file removed. Resuming a run is not a rerun in the
sense of EVALUATION.md §3: no finished row is ever computed twice.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable


def run_resumable(
    entries: list[dict],
    work: Callable[[dict], dict],
    out: Path,
    jobs: int,
    label: str,
) -> list[dict]:
    partial = out.with_name(out.stem + ".partial.jsonl")
    # A finished run started again (a scheduled task firing after a reboot) does nothing.
    if out.is_file() and not partial.is_file():
        finished = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
        if [r["id"] for r in finished] == [e["id"] for e in entries]:
            print(f"[{label}] already complete: {out}", flush=True)
            return finished
    done: dict[str, dict] = {}
    if partial.is_file():
        for line in partial.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                done[row["id"]] = row
    todo = [e for e in entries if e["id"] not in done]
    total, start = len(entries), time.time()
    print(f"[{label}] {len(done)} of {total} already done, {len(todo)} to go", flush=True)

    lock = threading.Lock()

    def one(entry: dict) -> None:
        row = work(entry)
        with lock:
            with open(partial, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row) + "\n")
            done[row["id"]] = row
            n = len(done)
            if n % 25 == 0 or n == total:
                rate = (n - (total - len(todo))) / max(1.0, time.time() - start)
                left = (total - n) / rate if rate > 0 else 0
                print(f"[{label}] {n}/{total}  ~{left / 60:.0f} min left", flush=True)

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        list(pool.map(one, todo))

    rows = [done[e["id"]] for e in entries]
    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    partial.unlink(missing_ok=True)
    return rows
