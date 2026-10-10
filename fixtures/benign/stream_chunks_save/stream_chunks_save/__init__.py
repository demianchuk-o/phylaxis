"""PHX-DRP-002 negative, the twin of stream_chunks_run: the same streamed download, written
chunk by chunk and left on disk. A model file is saved, not run.
"""
import os
import tempfile

import requests


def fetch_model():
    r = requests.get("https://cdn.example.invalid/model.bin", stream=True)
    path = os.path.join(tempfile.gettempdir(), "model.bin")
    with open(path, "wb") as fh:
        for chunk in r.iter_content(chunk_size=8192):
            fh.write(chunk)
    return path
