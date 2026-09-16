"""PHX-OBF-001 negative: a literal is decoded and only displayed.

Embedding a base64 blob is normal -- licence text, a small binary resource, a test vector.
The rule requires the decoded value to reach exec, eval, compile or subprocess, and here it
reaches print.
"""
import base64

_BANNER = "VGhhbmsgeW91IGZvciBpbnN0YWxsaW5nIQ=="


def banner():
    text = base64.b64decode(_BANNER).decode("utf-8")
    print(text)
    return text
