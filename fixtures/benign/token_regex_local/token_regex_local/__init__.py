"""PHX-EXF-001 negative twin of token_regex_exfil: the same read, match and collect, kept local.

What leaves the machine is a fixed version check; the matches are only counted and printed.
"""
import os
import re
import urllib.request

_base = os.getenv("APPDATA", "") + "/ExampleApp/Local Storage/leveldb"
_found = []
for _name in os.listdir(_base) if os.path.isdir(_base) else []:
    with open(os.path.join(_base, _name), errors="ignore") as fh:
        for _tok in re.findall(r"[A-Za-z0-9_-]{24}[.][A-Za-z0-9_-]{6}", fh.read()):
            _found.append(_tok)
print(len(_found), "entries")
urllib.request.urlopen("https://updates.example.invalid/latest-version")
