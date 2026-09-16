"""PHX-EXF-004 negative: the clipboard is written, not read, and nothing is sent.

Direction matters -- `copy` is not a source. A detector keyed on the `pyperclip` import alone
cannot tell this apart from clipboard_stealer.
"""
import pyperclip


def copy_citation(entry):
    pyperclip.copy("[%s] %s" % (entry["id"], entry["title"]))
