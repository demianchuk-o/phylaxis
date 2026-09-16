# SAFETY — analysing hostile code without running it

phylaxis reads code that was written to attack whoever processes it. Its inputs are, by
design, malicious PyPI packages. That makes the analyser itself a target, and it means the
usual static-analysis assumption — that the input is merely *broken*, not *hostile* — does
not hold here.

This document states what phylaxis guarantees, where each guarantee is enforced, and what
proves it. It also states what is **not** guaranteed, because a security document that only
lists strengths is not one.

## Threat model

The attacker controls the entire contents of an sdist: file names, archive metadata, Python
source, `setup.py`, `pyproject.toml`. They know phylaxis is scanning them. They want one of
the following:

| # | Attacker goal | Classic way to get it |
|---|---|---|
| T1 | Execute their code on the scanning machine | Get the tool to run `setup.py`, import a module, or shell out to `pip` |
| T2 | Write outside the extraction directory | Archive entries named `../../.ssh/authorized_keys` or `/etc/cron.d/x`, or a symlink pointing out of the tree |
| T3 | Exhaust the scanner's resources | Decompression bomb, a million tiny entries, deeply nested archives |
| T4 | Learn that they were scanned, or reach the network | Any callback triggered by package contents |
| T5 | Make the verdict unreliable | Inputs that make the tool non-deterministic, so a finding cannot be reproduced |

T1 is the one that matters most. A large share of malicious PyPI packages carry their
payload in an install hook precisely because so much tooling — and so many humans — will run
`pip install` or `python setup.py` to find out what a package does.

## Guarantees

### G1 — Package code is never executed

phylaxis has no code path that spawns a process, loads a Python interpreter, imports a
module, or invokes `pip`. This is not a check that could be bypassed; the capability is
absent. `parse` reads bytes and hands them to a parser. Nothing downstream of it has an
execution primitive to reach for.

*Proven by:* `crates/cli/tests/e2e_safety.rs::extraction_and_scan_never_run_setup_py`, over a fixture
whose `setup.py` would write a marker file beside itself if it ever ran. The test asserts
the marker does not exist.

### G2 — Extraction cannot escape its directory

Every archive entry is validated before anything is written. Rejected: absolute paths, any
`..` component, symlinks, hardlinks, and device or FIFO entries. Extraction targets a fresh
temporary directory, removed when the tree is dropped.

A rejected entry rejects **the whole archive**, not just that entry. A partially extracted
hostile archive is not something later stages should be asked to reason about, and "we
skipped the bad file and analysed the rest" is how a scanner ends up reporting *clean* on a
package built to be half-processed.

The temporary root is deleted on drop only when phylaxis created it. When the user points
the tool at a directory they already own, that flag is false and nothing is ever removed — a
scanner must be structurally incapable of deleting a source tree because a value went out of
scope.

*Enforced at:* `parse::extract::validate_entry`. *Proven by:* `parse::extract::tests::*` and
`e2e_safety.rs`, over `fixtures/malicious/tar_slip.tar.gz`, which contains `../../evil.py`,
`/abs/evil.py`, and a symlink to `/etc/passwd`.

### G3 — Nothing inside a package can cause network traffic

The network is reachable only from the `fetch` crate, only when the `network` feature is
compiled in — off by default — and only to hosts in `OFFICIAL_HOSTS` (`pypi.org`,
`files.pythonhosted.org`) over `https`.

The strongest part of this guarantee is structural rather than defensive: **no crate other
than `fetch` links an HTTP client at all.** `reqwest` is an optional dependency of one crate
that the analysis path does not depend on. No amount of bad code in `parse`, `graph` or
`rules` could produce a request, because there is nothing there to produce one with. That is
enforced by `Cargo.toml`, and a violation would show up as a dependency-graph change rather
than a subtle logic error.

What crosses into `fetch` is a `PackageRef` — a name and a version — never a URL. A string
found inside a package cannot become a request target, because there is no path by which a
package's contents reach the fetcher at all.

`is_official_index` additionally rejects any URL whose authority contains userinfo, even
though `https://evil.invalid:443@pypi.org` resolves per RFC 3986 to the legitimate host
`pypi.org`. PyPI's JSON API never emits credentials, so the shape is anomalous by
definition; and accepting it would mean betting that the HTTP client splits the authority at
exactly the same byte this function does. HTTP clients have historically disagreed about
that, and a disagreement is a request to a host nobody approved.

*Proven by:* `fetch::tests::official_index_gate`, which includes the userinfo-confusion cases
in both directions, and `network_is_unreachable_without_the_feature`.

### G4 — Resource use is bounded, and failure is closed

| Limit | Default | Behaviour on breach |
|---|---|---|
| `max_entries` | 20 000 | archive rejected |
| `max_total_bytes` | 256 MiB | archive rejected |
| `max_file_bytes` | 16 MiB | archive rejected |
| literal-folding depth | 8 | folding returns `None` |
| literal-folding output | 1 MiB | folding returns `None` |

Every limit fails **closed**: the package is skipped with a recorded reason, never partially
analysed and never reported clean by default. A skipped package appears in the report as
skipped, so a decompression bomb cannot launder itself into a clean verdict.

Literal folding — the deobfuscation step that resolves `exec(b64decode("..."))` — is pure and
total. It evaluates a closed set of side-effect-free decoders over literal-only expressions.
It never calls out, never allocates past its bound, and returns `None` on anything it does
not fully understand. It is constant *folding*, not evaluation: there is no path by which
attacker-chosen code selects what runs.

### G5 — The same input yields the same verdict

Files are processed in canonical order, graph indices are stable, the report uses ordered
maps, and no timestamp appears in the report body. Scanning the same file twice produces
byte-identical output.

This is a security property, not a nicety. A finding that cannot be reproduced cannot be
cited in an incident report, and a verdict that varies between runs cannot be used as a CI
gate.

*Proven by:* `e2e_scan.rs::scan_is_byte_deterministic`.

### G6 — Only Python source is written to disk

The extraction root contains `.py` and `pyproject.toml` files and nothing else. Every other
member of the archive — a bundled native binary, a nested archive, a data blob — has its path
and declared size recorded and its bytes discarded unread (ADR-020).

This one is worth separating from G1. G1 says phylaxis has no primitive that could execute a
package's code. G6 says the bytes that would need such a primitive are not even present. The
difference matters because G1 is a statement about which code paths exist, and you check it by
reading the source and trusting the reader; G6 is a statement about a directory, and you check
it by listing the directory.

What is *not* discarded is the knowledge that the file exists. `ExtractedTree::contains_path`
answers whether the distribution ships a given path, across both analysed files and the
manifest, because a package running a binary it carries and a package running one it downloads
are different findings and that predicate is what separates them.

*Enforced at:* `parse::extract::extract_sdist` and `load_directory`.
*Proven by:* `parse::extract::tests::only_python_source_reaches_the_extraction_root`, which
walks the extraction root and asserts the name of every file in it, and
`::load_directory_records_non_source_members_without_reading_them`.

## What is not guaranteed

- **The tool's own dependencies are inside its trust boundary.** phylaxis parses hostile
  input with `tar`, `flate2` and `tree-sitter`. A memory-safety bug in one of those is a bug
  in phylaxis. Rust removes the largest class of such bugs, and the limits in G4 bound the
  damage from a resource-consumption bug, but this is a real residual risk. Running batch
  scans of untrusted corpora inside a container is sensible defence in depth.
- **Compiled extensions are not analysed.** A `.so` or `.pyd` inside a distribution is out of
  scope. Such a package is reported as skipped, not as clean.
- **Detection is not completeness.** A rule catalogue finds what it was written to find. A
  clean verdict means "no rule matched", not "this package is safe". The reachability
  requirement raises precision; it does not make the catalogue exhaustive.
- **There is no sandbox around phylaxis itself.** It does not need one to be correct, but it
  is not a substitute for one when scanning at scale.

## Implementation status

The guarantees above are the specification, and the tests named under each are written. Not
all of them pass yet. This table is the truth as of the last run.

| Guarantee | Specified | Tests written | Passing |
|---|---|---|---|
| G1 no execution | yes | yes | not yet — the fixture exists (T-02); the test drives `scan_one`, which is T-12 |
| G2 no escape | yes | yes | **yes** at the unit level — `validate_entry` and the `tar_slip` archive; the end-to-end test waits on T-12 |
| G3 network gate | yes | yes | **yes**, except `PackageRef::parse` (T-14) |
| G4 bounded resources | yes | yes | extraction **yes** (entry count, per-file and total bytes, both from the header and from the bytes read); literal folding not yet (T-08) |
| G5 determinism | yes | yes | not yet (T-12) |
| G6 only source on disk | yes | yes | **yes** (T-03 + ADR-020) |

Nothing in this document may be softened to make a test pass. If an implementation cannot
meet a guarantee, the guarantee changes here first, by a recorded decision in `DECISIONS.md`,
and the reason is written down.
