"""PHX-DRP-002 negative, the twin of urlretrieve_run: `urlretrieve` saves a dataset, which is
then read and counted. The download reaches `open`, not an interpreter or a shell.
"""
import os
import tempfile
from urllib.request import urlretrieve


def load_words():
    p = os.path.join(tempfile.gettempdir(), "words.txt")
    urlretrieve("https://data.example.invalid/words.txt", p)
    with open(p) as fh:
        return len(fh.read().split())
