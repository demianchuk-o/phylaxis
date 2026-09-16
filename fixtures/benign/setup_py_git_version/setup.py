"""PHX-INS-002 negative at Medium -- accepted, documented.

Deriving a version from `git describe` at build time is everywhere. The rule fires because
subprocess is reachable from an install root, and Medium alone never reaches Suspicious; it
only matters when a data rule fires in the same package (ADR-010 aggregate).
"""
import subprocess

from setuptools import setup


def _version():
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            check=False,
        )
        return out.stdout.strip() or "0.0.0"
    except OSError:
        return "0.0.0"


setup(name="setup-py-git-version", version=_version(), packages=[])
