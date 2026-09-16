"""PHX-INS-003 negative: install-time environment reads that are all build variables.

CFLAGS, LDFLAGS and CC are on the build-variable allow-list in catalogue.rs, so they are not
sources for this rule. Reading them is how a package with a C extension is configured, and
suppressing the rule for them is a named allow-list rather than a heuristic.
"""
import os

from setuptools import Extension, setup

_cflags = os.environ.get("CFLAGS", "")
_ldflags = os.environ.get("LDFLAGS", "")
_cc = os.environ.get("CC", "cc")

_ext = Extension(
    "setup_py_env_cflags._speedups",
    sources=["src/speedups.c"],
    extra_compile_args=_cflags.split(),
    extra_link_args=_ldflags.split(),
)

setup(name="setup-py-env-cflags", version="1.0", packages=[], ext_modules=[_ext])
