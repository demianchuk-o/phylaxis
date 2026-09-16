"""PHX-OBF-002 positive: DecodedLiteral -> DynamicImport.

Which module is loaded is not readable from the source. The decoded name is `socket`, which
is harmless on its own -- the rule is about the concealment, not the module.
"""
import base64
import importlib

_NAME = base64.b64decode("c29ja2V0").decode("utf-8")
_mod = importlib.import_module(_NAME)
_other = __import__(base64.b64decode("YmFzZTY0").decode("utf-8"))
