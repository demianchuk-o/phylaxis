"""PHX-OBF-001 negative twin of escaped_eval: escapes, but the honest kind.

Control characters (an ANSI colour, a newline) are written as escapes because they have no
printable spelling; nothing escaped is executed.
"""
GREEN = "\x1b[32m"
RESET = "\x1b[0m"
print(GREEN + "ok" + RESET + "\n")
