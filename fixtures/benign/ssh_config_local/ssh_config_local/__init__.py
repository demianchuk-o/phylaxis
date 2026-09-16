"""PHX-EXF-002 negative: a sensitive-directory read used locally and never sent.

Reading ~/.ssh/config to list configured hosts is what every ssh helper on PyPI does. The
file is on the sensitive list; the absence of a sink is the whole difference from
ssh_key_exfil.
"""
import os


def configured_hosts():
    path = os.path.expanduser("~/.ssh/config")
    hosts = []
    if not os.path.exists(path):
        return hosts
    with open(path, "r") as fh:
        for line in fh:
            if line.lower().startswith("host "):
                hosts.append(line.split(None, 1)[1].strip())
    return sorted(hosts)
