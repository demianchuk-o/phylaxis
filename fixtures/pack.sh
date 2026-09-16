#!/bin/sh
# Build the fixture archives reproducibly. See pack.py for what and why.
#
#   ./pack.sh          write the archives
#   ./pack.sh --check  build twice and compare digests, writing nothing
#
# POSIX sh on purpose: this has to run unchanged on Linux, macOS and Git Bash.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# WHY a probe rather than `command -v`: on Windows, `python3` is usually an App Execution
# Alias -- a stub on PATH that exists, is executable, and does nothing but advertise the
# Microsoft Store. It satisfies `command -v` and then fails. Running one real statement is
# the only reliable test that an interpreter is an interpreter.
for py in python3 python py; do
    if "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
        >/dev/null 2>&1; then
        exec "$py" "$dir/pack.py" "$@"
    fi
done

echo "pack.sh: no working Python 3.9+ found (tried python3, python, py)" >&2
exit 1
