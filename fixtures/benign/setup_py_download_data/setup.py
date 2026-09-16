"""PHX-INS-001 positive at High but NOT Critical -- a documented, accepted false positive.

Fetching a data file during install is a real pattern in older packages and this rule reports
it rather than suppressing it. It must not reach Malicious on its own: there is no data rule
firing here, so the aggregate stays at the control-rule level. If this fixture ever scores
Critical, the aggregate in ADR-010 has drifted.
"""
import os
import urllib.request

from setuptools import setup

_DATA_URL = "https://files.example.invalid/corpus-1.0.json"
_target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.json")

if not os.path.exists(_target):
    with open(_target, "wb") as _fh:
        _fh.write(urllib.request.urlopen(_DATA_URL).read())

setup(name="setup-py-download-data", version="1.0", packages=[])
