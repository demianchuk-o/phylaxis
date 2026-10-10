"""PHX-DRP-002 negative, the twin of chained_write_run: the same unnamed-handle write of a
download, and the file is left in the cache. Nothing runs it.
"""
import os
import tempfile
import urllib.request


def cache_licence():
    body = urllib.request.urlopen("https://cdn.example.invalid/LICENSE.txt").read().decode()
    p = os.path.join(tempfile.gettempdir(), "LICENSE.txt")
    open(p, "w").write(body)
    return p
