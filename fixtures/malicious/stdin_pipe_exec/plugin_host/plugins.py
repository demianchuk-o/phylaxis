"""PHX-DRP-001 positive (ADR-031): fetched text is handed to a fresh interpreter on its
standard input. No `exec` and no file: the interpreter reads its program from the pipe.
The fetch is in `fetch.py`, so the path also crosses a module boundary.
"""
import subprocess

from .fetch import index


def refresh_plugins():
    subprocess.run(["python3", "-"], input=index(), check=False)
