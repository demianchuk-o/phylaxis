#!/usr/bin/env python3
"""Build the fixture archives, byte-for-byte reproducibly.

Run it through `pack.sh`, or directly with any Python 3.9+.

WHY Python and not tar(1): the archives have to be identical on every machine, and the flags
that make GNU tar deterministic (--sort, --mtime, --owner) do not exist in the bsdtar that
macOS ships. `tarfile` behaves the same everywhere. It is also the only portable way to write
the hostile entries in tar_slip.tar.gz at all -- GNU tar refuses to store a `..` path and
strips a leading `/`, which is precisely what the fixture needs to contain.

Determinism, in full: entries sorted by archive name, mtime pinned to a constant, uid/gid 0
with empty owner names, modes forced to 0644/0755, GNU tar format, and a gzip header with no
timestamp and no original filename. `--check` builds everything twice and compares digests.

SAFETY: nothing here is executed. The archives contain text, and tar_slip.tar.gz is hostile by
design -- it must only ever be opened by code that validates entry paths first.
"""

import argparse
import gzip
import hashlib
import io
import os
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

# 2026-01-01T00:00:00Z. Any constant works; it just must never be "now".
FIXED_MTIME = 1767225600
DIR_MODE = 0o755
FILE_MODE = 0o644

# Directories that are never packed into an sdist's source tree.
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", "build", "dist"}


def _info(name, size=0, kind=tarfile.REGTYPE, linkname=""):
    ti = tarfile.TarInfo(name)
    ti.size = size
    ti.type = kind
    ti.linkname = linkname
    ti.mtime = FIXED_MTIME
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    ti.mode = DIR_MODE if kind == tarfile.DIRTYPE else FILE_MODE
    return ti


def _write_targz(members):
    """members: list of (TarInfo, bytes|None). Returns the .tar.gz bytes."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for ti, payload in members:
            tf.addfile(ti, io.BytesIO(payload) if payload is not None else None)
    gz_buf = io.BytesIO()
    # mtime=0 and an empty filename keep the gzip header free of anything variable.
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=0) as gz:
        gz.write(tar_buf.getvalue())
    return gz_buf.getvalue()


def _collect(src_dir):
    """Every file under src_dir, as (relative posix path, bytes), sorted by path."""
    out = []
    for dirpath, dirnames, filenames in os.walk(src_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, src_dir).replace(os.sep, "/")
            with open(full, "rb") as fh:
                out.append((rel, fh.read()))
    return sorted(out, key=lambda p: p[0])


def build_sdist(src_dir, top_level):
    """Pack a fixture directory as an sdist: one top-level {name}-{version}/ directory."""
    files = _collect(src_dir)
    members = [(_info(top_level + "/", kind=tarfile.DIRTYPE), None)]
    seen = {""}
    for rel, _payload in files:
        parts = rel.split("/")[:-1]
        for i in range(len(parts)):
            d = "/".join(parts[: i + 1])
            if d not in seen:
                seen.add(d)
                members.append((_info(top_level + "/" + d + "/", kind=tarfile.DIRTYPE), None))
    for rel, payload in files:
        members.append((_info(top_level + "/" + rel, size=len(payload)), payload))
    members.sort(key=lambda m: m[0].name)
    return _write_targz(members)


def build_tar_slip():
    """The hostile archive: three escape attempts plus one innocent entry.

    Each entry targets a different guard in parse::validate_entry, so a partial implementation
    fails loudly rather than passing three quarters of the test:
      ../../evil.py      -- relative traversal out of the extraction root
      /abs/evil.py       -- absolute path, ignoring the root entirely
      tar_slip-1.0/passwd-> /etc/passwd  -- a symlink, which escapes on the *read* side
    The innocent setup.py is there so that an implementation which rejects the archive only
    because it cannot parse it is not mistaken for one that rejects it on the guards. The whole
    archive must be rejected, not just the bad entries.
    """
    evil = b"# inert fixture payload; if this file ever appears outside the extraction\n"
    evil += b"# root, path validation failed.\n"
    good = b'from setuptools import setup\n\nsetup(name="tar-slip", version="1.0")\n'
    members = [
        (_info("tar_slip-1.0/", kind=tarfile.DIRTYPE), None),
        (_info("tar_slip-1.0/setup.py", size=len(good)), good),
        (_info("../../evil.py", size=len(evil)), evil),
        (_info("/abs/evil.py", size=len(evil)), evil),
        (_info("tar_slip-1.0/passwd", kind=tarfile.SYMTYPE, linkname="/etc/passwd"), None),
    ]
    return _write_targz(members)


def build_wheel():
    """A minimal wheel. Out of analysis scope (invariant 2); it exists so that the scanner can
    be shown reporting NotAnSdist rather than trying to read it."""
    entries = [
        (
            "wheel_only/__init__.py",
            b'"""A wheel is never analysed: invariant 2."""\n\n__version__ = "1.0"\n',
        ),
        (
            "wheel_only-1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: wheel-only\nVersion: 1.0\n",
        ),
        (
            "wheel_only-1.0.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nGenerator: phylaxis-fixtures\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\n",
        ),
        ("wheel_only-1.0.dist-info/RECORD", b""),
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in sorted(entries):
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.external_attr = FILE_MODE << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, payload)
    return buf.getvalue()


TARGETS = {
    "benign/setup_py_plain.tar.gz": lambda: build_sdist(
        os.path.join(HERE, "benign", "setup_py_plain"), "setup_py_plain-1.0"
    ),
    "malicious/tar_slip.tar.gz": build_tar_slip,
    "benign/wheel_only-1.0-py3-none-any.whl": build_wheel,
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--check",
        action="store_true",
        help="build twice and compare digests instead of writing",
    )
    args = ap.parse_args(argv)

    failures = 0
    for rel, build in sorted(TARGETS.items()):
        data = build()
        digest = hashlib.sha256(data).hexdigest()
        if args.check:
            again = hashlib.sha256(build()).hexdigest()
            status = "ok " if again == digest else "DIFFERS"
            if again != digest:
                failures += 1
            print("%s  %s  %s" % (status, digest[:16], rel))
        else:
            out = os.path.join(HERE, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(data)
            print("%6d bytes  %s  %s" % (len(data), digest[:16], rel))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
