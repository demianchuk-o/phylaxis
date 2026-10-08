"""PHX-OBF-001 positive (ADR-028): chr over a list of codes, executed, with no other decoder.

The pyobfuscate shape. The codes spell print("inert fixture").
"""
_CODES = [112, 114, 105, 110, 116, 40, 34, 105, 110, 101, 114, 116, 32,
          102, 105, 120, 116, 117, 114, 101, 34, 41]
exec("".join(chr(c) for c in _CODES))
