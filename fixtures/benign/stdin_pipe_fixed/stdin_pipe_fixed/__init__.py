"""PHX-DRP-001 negative, the twin of stdin_pipe_exec: the same interpreter fed through its
standard input, with a fixed program; the fetched text is only printed.
"""
import subprocess
import urllib.request


def report_versions():
    body = urllib.request.urlopen("https://plugins.example.invalid/index").read()
    subprocess.run(["python3", "-"], input=b"import sys; print(sys.version)", check=False)
    print(body.decode()[:80])
