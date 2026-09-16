"""PHX-OBF-001 positive: DecodedLiteral -> CodeExecution, folding depth 1.

The literal decodes to `print("inert fixture payload")` and nothing else. It is never run;
folding it is a pure string operation (ADR-018).
"""
import base64

_BLOB = "cHJpbnQoImluZXJ0IGZpeHR1cmUgcGF5bG9hZCIp"
exec(base64.b64decode(_BLOB).decode("utf-8"))
