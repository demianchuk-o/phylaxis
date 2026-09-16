"""PHX-DRP-003 negative: subprocess reached by a literal that is not suspicious.

An argument list rather than a shell string, a known tool name, no URL and no pipeline. The
sink is real; the source is not.
"""
import subprocess


def git_describe():
    result = subprocess.run(
        ["git", "describe", "--tags", "--always"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()
