"""PHX-PER-001 negative: a persistence location written with a known literal.

Installing shell completion appends to ~/.bashrc, which is a PersistenceWrite sink. The rule
needs the written content to come from a network response or a decoded literal; here it is a
constant visible in the source, so there is no source and no path.
"""
import os

_LINE = 'eval "$(mytool completion bash)"'


def install_completion():
    rc = os.path.expanduser("~/.bashrc")
    with open(rc, "a") as fh:
        fh.write("\n" + _LINE + "\n")
