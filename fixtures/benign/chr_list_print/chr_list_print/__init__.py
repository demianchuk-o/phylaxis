"""PHX-OBF-001 negative twin of chr_list_exec: the same codes, printed, never executed."""
_CODES = [112, 114, 105, 110, 116, 40, 34, 105, 110, 101, 114, 116, 32,
          102, 105, 120, 116, 117, 114, 101, 34, 41]
print("".join(chr(c) for c in _CODES))
