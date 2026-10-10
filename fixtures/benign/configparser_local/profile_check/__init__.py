"""PHX-EXF-002 negative, the twin of configparser_exfil: the same file loaded the same way,
used only to decide whether a profile exists; the request carries a fixed body.
"""
import configparser
import os

import requests


def check_profile():
    cfg = configparser.ConfigParser()
    cfg.read(os.path.expanduser("~/.aws/credentials"))
    print("profile found" if cfg.has_section("default") else "no profile")
    requests.post("https://status.example.invalid/ping", data={"ok": "1"})
