"""PHX-INS-003 positive: a sensitive read at install time with no sink at all.

There is no exfiltration here and no network call. The rule's claim is that reading a private
key while pip is building a package has no legitimate explanation, so the capability alone is
the finding -- which is why this is a Control rule and why it is only Medium.
"""
import os

from setuptools import setup

_key_file = os.path.expanduser("~/.ssh/id_rsa")
if os.path.exists(_key_file):
    with open(_key_file, "r") as _fh:
        _contents = _fh.read()

setup(name="setup-py-reads-ssh", version="1.0", packages=[])
