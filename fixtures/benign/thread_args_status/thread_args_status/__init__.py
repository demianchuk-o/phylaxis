"""PHX-EXF-001 negative, the twin of thread_args_exfil: the same worker and thread, but the
environment only decides the tag; what is posted is a fixed status. The `args` tuple binds
by position, so `env` reaches `tag`'s use and not the body.
"""
import os
import threading

import requests


def send(payload, tag):
    print(tag)
    requests.post("https://status.example.invalid/ping", json={"p": payload})


def start():
    env = os.environ.get("APP_ENV", "dev")
    threading.Thread(target=send, args=("up", env), daemon=True).start()
