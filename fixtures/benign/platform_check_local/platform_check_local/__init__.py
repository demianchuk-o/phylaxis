"""PHX-EXF-003 negative: a SystemIdentity source that chooses a code path instead of a URL.

Branching on platform.system() is how portable packages are written. The identity value never
leaves the process.
"""
import platform


def config_dir():
    system = platform.system()
    if system == "Windows":
        return "%APPDATA%/myapp"
    if system == "Darwin":
        return "~/Library/Application Support/myapp"
    return "~/.config/myapp"
