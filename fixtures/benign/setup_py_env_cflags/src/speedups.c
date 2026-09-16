/* Out of analysis scope (invariant 2): compiled extensions are not read. Present so the
   fixture is a plausible sdist rather than a setup.py with a dangling sources entry. */
int phylaxis_fixture_noop(void) { return 0; }
