"""PHX-DRP-003 negative twin of download_cmd_exec: a URL template handed to git.

A link with holes being filled in, the way maintenance scripts build repository URLs; a
template matches only as part of a command line (ADR-028).
"""
import subprocess

owner, repo = "example", "project"
subprocess.run(["git", "ls-remote", f"https://git.example.invalid/{owner}/{repo}.git"], check=False)
