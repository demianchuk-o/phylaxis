"""Runs the baselines of EVALUATION.md §5, GuardDog and Aura, over one split of
``eval/manifest.json``. Runs on Linux (WSL on the evaluation machine):

    python3 eval/baselines.py --split dev

GuardDog is a local install (``$PHYLAXIS_GUARDDOG``, default
``~/phx-tools/guarddog/bin/guarddog``); Aura is the project's own image
(``sourcecodeai/aura:dev``), run with ``--network none``. Both see exactly what phylaxis
sees: the benign sdist file, or the Datadog sample's package root unpacked from its zip
(ADR-023). Every input is staged on the native filesystem first: GuardDog's kernel sandbox
cannot read a Windows-mounted drive and then reports "no risks" instead of failing, which
would silently turn every sample into a miss.

Writes ``<data>/results/<split>-guarddog.jsonl`` and ``<split>-aura.jsonl`` with each tool's
raw output reduced to what scoring needs: GuardDog's fired rules, Aura's score and detection
types. Parse failures, crashes and timeouts are rows with ``error``; §5 counts them as
not flagged and lists them.

Standard library only; nothing here imports or runs a sample.
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import shutil
import subprocess
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("PHYLAXIS_EVAL_DATA", HERE.parent.parent / "eval-data"))
GUARDDOG = os.environ.get("PHYLAXIS_GUARDDOG", str(Path.home() / "phx-tools/guarddog/bin/guarddog"))
AURA_IMAGE = "sourcecodeai/aura:dev"
# Aura's default is every installed analyzer. This is that list minus `req_analyzer`, which
# looks up each declared requirement on pypi.org: offline it raises and the whole scan is
# lost, and EVALUATION.md §5 asks for network heuristics off where the version allows it.
AURA_ANALYZERS = [
    "archive", "behavioral_analysis", "crypto_gen_key", "data_finder", "directory_tree_stats",
    "file_analyzer", "jinja", "misc", "non_ascii_characters", "pypirc", "pyproject_toml",
    "python_dists", "secrets", "setup_py", "sqli", "stats", "string_finder", "taint_analysis",
    "xml", "yara",
]
PASSWORD = b"infected"


def stage(entry: dict, into: Path) -> Path:
    """Puts the input on the native filesystem and returns the path to scan: a copy of the
    benign sdist, or the Datadog sample's package root, with member names validated."""
    if entry["source"] != "datadog":
        target = into / posixpath.basename(entry["file"])
        shutil.copyfile(DATA / entry["file"], target)
        return target
    root, target = entry["root"], into / "pkg"
    with zipfile.ZipFile(DATA / entry["file"]) as z:
        for info in z.infolist():
            name = info.filename
            if info.is_dir() or (root and not name.startswith(root + "/")):
                continue
            rel = posixpath.relpath(name, root) if root else name
            parts = rel.split("/")
            if rel.startswith("/") or ".." in parts:
                raise ValueError(f"unsafe member name {name!r}")
            dest = target.joinpath(*parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(z.read(info, pwd=PASSWORD))
    return target


def json_tail(text: str) -> dict:
    """Both tools print log lines before their JSON document."""
    i = text.find("{")
    if i < 0:
        raise ValueError(f"no JSON in output: {text.strip()[:200]!r}")
    return json.loads(text[i:])


def guarddog(path: Path, timeout: float) -> dict:
    done = subprocess.run(
        [GUARDDOG, "pypi", "scan", "--output-format", "json", str(path)],
        capture_output=True, text=True, timeout=timeout,
    )
    doc = json_tail(done.stdout)
    fired = sorted(rule for rule, hits in (doc.get("results") or {}).items() if hits)
    # EVALUATION.md §5: flagged = at least one source-code rule result. A local scan runs no
    # metadata rules unless given `--metadata`, so every result here is a source-code one.
    return {"flagged": bool(fired), "rules": fired, "issues": doc.get("issues"), "errors": doc.get("errors") or None}


def aura(path: Path, timeout: float) -> dict:
    mount = path if path.is_dir() else path.parent
    target = "/data" if path.is_dir() else f"/data/{path.name}"
    done = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{mount}:/data:ro", AURA_IMAGE, "scan", target, "-f", "json",
         *[arg for a in AURA_ANALYZERS for arg in ("-a", a)]],
        capture_output=True, text=True, timeout=timeout,
    )
    scans = json_tail(done.stdout).get("scans") or []
    score = max((s.get("score") or 0 for s in scans), default=0)
    types = sorted({d.get("type") for s in scans for d in s.get("detections", []) if d.get("score")})
    # Aura defines no verdict threshold of its own; the score is recorded and the threshold
    # is applied at scoring time (see the harness README).
    return {"score": score, "scored_detections": types}


def one(entry: dict, tool: str, timeout: float) -> dict:
    row = {k: entry.get(k) for k in ("id", "label", "source", "name", "version")}
    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="phx-baseline-") as tmp:
        try:
            path = stage(entry, Path(tmp))
            row.update(guarddog(path, timeout) if tool == "guarddog" else aura(path, timeout))
        except subprocess.TimeoutExpired:
            row["error"] = f"timeout after {timeout:g} s"
        except Exception as err:  # a failed input is a row, never a stopped run
            row["error"] = f"{type(err).__name__}: {str(err)[:300]}"
    row["seconds"] = round(time.perf_counter() - start, 3)
    return row


def versions() -> dict:
    gd = subprocess.run([GUARDDOG, "--version"], capture_output=True, text=True).stdout.strip()
    image = subprocess.run(["docker", "image", "inspect", AURA_IMAGE, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip()
    return {"guarddog": gd, "aura_image": f"{AURA_IMAGE}@{image}"}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--split", choices=["dev", "test"], default="dev")
    p.add_argument("--tool", choices=["guarddog", "aura", "both"], default="both")
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    p.add_argument("--timeout", type=float, default=300.0)
    args = p.parse_args()

    entries = [e for e in json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))["entries"] if e.get("split") == args.split]
    out_dir = DATA / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{args.split}-baseline-versions.json").write_text(json.dumps(versions(), indent=1) + "\n", encoding="utf-8")
    for tool in (["guarddog", "aura"] if args.tool == "both" else [args.tool]):
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            rows = list(pool.map(lambda e, t=tool: one(e, t, args.timeout), entries))
        out = out_dir / f"{args.split}-{tool}.jsonl"
        out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        errors = sum("error" in r for r in rows)
        print(f"{tool}: {len(rows)} rows, {errors} errors -> {out}")


if __name__ == "__main__":
    main()
