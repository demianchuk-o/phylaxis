"""PHX-DRP-002 negative: a network response written to disk and left there.

No chmod, no subprocess, no import of the written path. The write is the end of the path, and
the write alone is not a sink -- the difference from download_and_run is the two lines that
fixture has after the write.
"""
import os
import urllib.request


def fetch_font(cache_dir):
    body = urllib.request.urlopen("https://assets.example.invalid/f.woff2").read()
    target = os.path.join(cache_dir, "f.woff2")
    with open(target, "wb") as fh:
        fh.write(body)
    return target
