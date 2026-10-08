"""PHX-OBF-001 positive (ADR-028): the encoding is done by the lexer.

The name of a builtin is spelled in octal and hex escapes, the BlankOBF pattern, so no
decoder call appears anywhere. The evaluated payload is print("inert fixture").
"""
_f = eval("\145\166\x61\x6c")
_f("print('inert fixture')")
