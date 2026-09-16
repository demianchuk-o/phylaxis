"""PHX-OBF-002 negative: a dynamic import whose name is concatenated, not decoded.

Compatibility shims build module names from strings all the time. Concatenation folds to a
readable literal, so the name is still auditable and there is no DecodedLiteral source --
which is exactly the distinction ADR-018 draws.
"""
import importlib

_MAJOR = "5"


def qt_core():
    return importlib.import_module("PyQt" + _MAJOR + ".QtCore")
