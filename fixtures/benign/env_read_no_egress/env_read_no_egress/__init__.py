"""PHX-EXF-001 negative: an Environment source with no sink anywhere in the package.

This is the ordinary way configuration is read. No network import, so there is nothing for a
path to end at.
"""
import os

DEBUG = os.environ.get("MYAPP_DEBUG", "0") == "1"
LOG_LEVEL = os.getenv("MYAPP_LOG_LEVEL", "info")


def describe():
    return "debug=%s level=%s" % (DEBUG, LOG_LEVEL)
