"""PHX-SAB-001 negative: rmtree against relative build paths.

The destructive sink is real; the paths are relative literals that are not on the sensitive
list, so nothing qualifies as a source. wipe_home is this file with os.path.expanduser("~").
"""
import shutil


def clean():
    for path in ("build", "dist", ".pytest_cache"):
        shutil.rmtree(path, ignore_errors=True)
