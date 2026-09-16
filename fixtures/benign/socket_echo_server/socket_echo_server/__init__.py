"""PHX-BKD-001 negative: sockets without the dup2-onto-stdio step.

Binding, accepting and echoing is what a network library does. reverse_shell is this file
plus three dup2 calls and a shell spawn; nothing else distinguishes them.
"""
import socket


def serve(port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    conn, _addr = server.accept()
    data = conn.recv(1024)
    conn.sendall(data)
    conn.close()
