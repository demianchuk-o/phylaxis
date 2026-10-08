"""PHX-EXF-003 negative twin of discord_webhook_beacon: the same webhook, a constant message.

Reads the hostname for a local log line; what is sent is fixed text.
"""
import socket

from discord import SyncWebhook

print("building on", socket.gethostname())
_hook = SyncWebhook.from_url("https://discord.example.invalid/api/webhooks/1/x")
_hook.send(content="build finished")
