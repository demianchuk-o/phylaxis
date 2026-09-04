"""phylaxis -- deterministic static analysis of PyPI packages.

The analysis itself is implemented in Rust and reached through the compiled
``_native`` module. This package is only a thin, importable surface over it so
that an evaluation harness can drive the scanner from Python.

The public API is designed in the architecture session; right now only
``version()`` is real.
"""

from ._native import cli_main, version

__all__ = ["cli_main", "version", "__version__"]

__version__ = version()
