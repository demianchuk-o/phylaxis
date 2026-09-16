"""PHX-OBF-001 positive, exercising folding depth rather than a single decode.

chr-join, then base64: two transforms stacked rather than one, which is what the depth bound
of ADR-018 exists for. The innermost payload decodes to print("inert fixture") and nothing
else -- folding it is a pure string operation, never an evaluation.
"""
import base64

_CODES = [
    99, 72, 74, 112, 98, 110, 81, 111, 73, 109, 108, 117, 90, 88, 74, 48,
    73, 71, 90, 112, 101, 72, 82, 49, 99, 109, 85, 105, 75, 81, 61, 61,
]
_STAGE1 = "".join(chr(c) for c in _CODES)
_STAGE2 = base64.b64decode(_STAGE1).decode("utf-8")
exec(_STAGE2)
