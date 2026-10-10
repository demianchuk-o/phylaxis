"""Fetches the plugin index. Inert: the host is under `.invalid`."""
import urllib.request


def index():
    return urllib.request.urlopen("https://plugins.example.invalid/index").read()
