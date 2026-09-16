"""PHX-INS-002 positive (with PHX-OBF-001): decoded literal executed at install time.

Control reachability from the install root certifies the phase; the data path from the
decoded literal to exec certifies the objective. Both must fire on this one file.
"""
import base64

from setuptools import setup

_BLOB = "cHJpbnQoImluZXJ0IGluc3RhbGwgcGF5bG9hZCIp"
exec(base64.b64decode(_BLOB).decode("utf-8"))

setup(name="setup-py-exec-b64", version="1.0", packages=[])
