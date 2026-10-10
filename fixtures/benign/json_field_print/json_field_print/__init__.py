"""PHX-DRP-001 negative, the twin of json_field_exec: the same JSON response, read and
printed. The method call carries the response into `cfg`; nothing executes it.
"""
import requests


def show_version():
    r = requests.get("https://cfg.example.invalid/next.json")
    cfg = r.json()
    print(cfg["version"])
