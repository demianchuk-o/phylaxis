"""PHX-EXF-001 negative -- THE ABLATION PAIR. Quoted in the thesis alongside env_exfil_setup.

An Environment source and a NetworkEgress sink sit in the same file, in the same class, four
lines apart. Every co-occurrence detector flags this. There is no data-flow path between them:
`api_token` is read from the environment and returned to the caller, while `publish` sends a
caller-supplied document to a configured endpoint. Nothing that touches the environment ever
reaches the request body.

Configurations A and B of the ablation flag this file. Configurations C and D must not. That
difference is the measurement the whole method rests on.
"""
import os

import requests


class Client:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def api_token(self):
        return os.environ.get("MYAPP_API_TOKEN", "")

    def publish(self, document):
        return requests.post(self.endpoint, json={"document": document})
