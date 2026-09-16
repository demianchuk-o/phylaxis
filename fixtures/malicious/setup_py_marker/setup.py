"""SAFETY fixture, not a rule fixture. Referenced by `e2e_safety.rs`.

If this module is ever executed, the block below writes a file named PHYLAXIS_EXECUTED next
to it. The analyser must read this file as text and never import, exec or subprocess it, so
the marker must not exist before or after a scan. The write is the assertion.
"""
import os

from setuptools import setup

_marker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PHYLAXIS_EXECUTED")
with open(_marker, "w") as _fh:
    _fh.write("setup.py was executed\n")

setup(name="setup-py-marker", version="1.0", packages=[])
