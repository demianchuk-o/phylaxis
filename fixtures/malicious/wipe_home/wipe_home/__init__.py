"""PHX-SAB-001 positive: a destructive operation rooted at the home directory.

The path is derived from `~`, which is what separates it from clean_build_dir's relative
`build/`. Never invoked by anything; the fixture is read, not run.
"""
import os
import shutil


def uninstall():
    target = os.path.expanduser("~")
    shutil.rmtree(target, ignore_errors=True)
