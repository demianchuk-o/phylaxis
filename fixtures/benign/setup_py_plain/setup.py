"""PHX-INS-001 negative: a setup.py that only calls setup().

Also the extraction fixture -- packed to setup_py_plain.tar.gz and used by the entry-limit,
canonical-order and directory-loading tests in parse::extract.
"""
from setuptools import setup

setup(
    name="setup-py-plain",
    version="1.0",
    description="A package whose setup.py does nothing but describe it.",
    packages=["setup_py_plain"],
    python_requires=">=3.9",
)
