"""phylaxis -- deterministic static analysis of PyPI packages.

The analysis is implemented in Rust and reached through the compiled ``_native``
module. This package is a thin surface over it (DECISIONS.md, ADR-013):

* ``scan(path, **options)``       -> ``dict``        one report
* ``scan_many(paths, **options)`` -> ``list[dict]``  reports in input order,
  ``{"error": "..."}`` for inputs that could not be scanned
* ``rules()``                     -> ``list[dict]``  the rule catalogue
* ``ruleset_version()``           -> ``int``
* ``version()``                   -> ``str``
* ``cli_main(argv)``              -> ``int``         the console script

Reports have exactly the schema of ``phylaxis scan --format json``. Nothing else is
exposed on purpose: the AST, graphs, rule engine, cache and fetcher are internal.

Options (all keyword-only, all optional): ``mode`` (``"A"``/``"B"``/``"C"``/``"D"``,
default ``"D"``), ``min_confidence`` (``"dynamic"``/``"ambiguous"``/``"resolved"``),
``jobs`` (int), ``cache`` (path). They are marshalled to the Rust ``ScanOptions`` JSON.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterable, Optional, Union

from ._native import cli_main, rules_json, ruleset_version, scan_json, scan_many_json, version

__all__ = ["scan", "scan_many", "rules", "ruleset_version", "version", "cli_main", "__version__"]

__version__ = version()

_MODES = {
    "A": {"mode": "file_cooccurrence"},
    "B": {"mode": "definition_cooccurrence"},
    "C": {"mode": "reachability", "phase_weighting": False},
    "D": {"mode": "reachability", "phase_weighting": True},
}

PathLike = Union[str, "os.PathLike[str]"]


def _options(
    mode: str = "D",
    min_confidence: Optional[str] = None,
    jobs: Optional[int] = None,
    cache: Optional[PathLike] = None,
) -> str:
    """Builds the ScanOptions JSON. Unknown modes raise ValueError here, in Python,
    before any native call."""
    try:
        opts: dict[str, Any] = {"mode": _MODES[mode.upper()]}
    except KeyError:
        raise ValueError(f"mode must be one of A, B, C, D; got {mode!r}") from None
    if min_confidence is not None:
        opts["min_confidence"] = min_confidence
    if jobs is not None:
        opts["jobs"] = int(jobs)
    if cache is not None:
        opts["cache_path"] = os.fspath(cache)
    return json.dumps(opts)


def scan(path: PathLike, *, mode: str = "D", min_confidence: Optional[str] = None, jobs: Optional[int] = None, cache: Optional[PathLike] = None) -> dict[str, Any]:
    """Scan one sdist (``.tar.gz``) or one extracted directory and return its report."""
    return json.loads(scan_json(os.fspath(path), _options(mode, min_confidence, jobs, cache)))


def scan_many(paths: Iterable[PathLike], *, mode: str = "D", min_confidence: Optional[str] = None, jobs: Optional[int] = None, cache: Optional[PathLike] = None) -> list[dict[str, Any]]:
    """Scan many inputs in parallel inside Rust (the GIL is released for the batch).
    Results are in input order; an input that could not be scanned yields
    ``{"error": "..."}`` instead of raising, so one bad archive never aborts a run."""
    return json.loads(scan_many_json([os.fspath(p) for p in paths], _options(mode, min_confidence, jobs, cache)))


def rules() -> list[dict[str, Any]]:
    """The rule catalogue: id, title, objective, phase, severity, sources, sinks."""
    return json.loads(rules_json())
