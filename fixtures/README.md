# fixtures

Minimal hand-written sample packages used by the integration tests. One technique per
fixture, so a failing test points at one rule rather than at a pile of behaviour.

- `benign/` — packages that must **not** be flagged. These are the false-positive guard:
  every one exercises a pattern that looks suspicious in isolation and is legitimate in
  context.
- `malicious/` — packages that **must** be flagged, each carrying exactly one technique from
  the Backstabber attack tree (Ohm et al., 2020).

These are fixtures, not corpora. The labelled evaluation sets (Datadog, Backstabber) are
downloaded separately and never committed — see `.gitignore`.

## Safety

**Every payload here is inert by construction, and nothing in this directory is ever
executed.** The analyser reads source text; it does not import, `exec`, or subprocess
anything it scans. Three conventions keep the files harmless even if somebody does run one
by hand:

- **Every host is under `.invalid`** (RFC 2606) or in a documentation-reserved IP range
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, RFC 5737). None of them can resolve
  or route, so no fixture can reach anything real.
- **Every encoded payload decodes to a `print`.** The base64 and `chr`-join blobs in
  `b64_exec`, `chr_join_exec` and `setup_py_exec_b64` decode to `print("inert …")` and
  nothing else. They are there to be *folded* — a pure string operation (ADR-018) — not run.
- **Every credential-shaped literal is obviously fake**, and no real key material, token or
  hostname appears anywhere in the tree.

`malicious/tar_slip.tar.gz` is the one genuinely hostile artefact: it contains entries that
escape the extraction root. It exists to be **rejected**, and must only ever be opened by
code that validates entry paths before writing. See `docs/SAFETY.md`.

## Building the archives

Most fixtures are plain directories, scanned in place. Three artefacts are built:

```sh
./pack.sh           # write them
./pack.sh --check   # build twice, compare digests, write nothing
```

| artefact | why it exists |
|---|---|
| `benign/setup_py_plain.tar.gz` | the well-formed sdist: entry limits, canonical ordering, top-level-directory stripping |
| `malicious/tar_slip.tar.gz` | three escape vectors in one archive — `../../evil.py`, `/abs/evil.py`, and a symlink to `/etc/passwd` |
| `benign/wheel_only-1.0-py3-none-any.whl` | a wheel, so the scanner can be shown reporting `NotAnSdist` rather than reading it (invariant 2) |

The build is reproducible: entries sorted by name, `mtime` pinned to a constant, uid/gid 0
with empty owner names, fixed modes, and a gzip header carrying neither a timestamp nor an
original filename. `--check` is what proves it. Rebuilding must never produce a diff, so a
changed archive in `git status` means a fixture's *contents* changed.

`pack.sh` is a POSIX wrapper around `pack.py`; the work is in Python because the flags that
make GNU tar deterministic do not exist in the bsdtar macOS ships, and because `tar(1)`
refuses to write the hostile entries at all — it strips a leading `/` and rejects `..`.

## Index

Every rule in `docs/RULES.md` names a positive and a negative fixture; this is that mapping
from the fixture side.

### malicious

| fixture | rule | shape |
|---|---|---|
| `env_exfil_setup/` | PHX-EXF-001 | `Environment` → `NetworkEgress` at `setup.py` module level (install root) |
| `env_exfil_runtime/` | PHX-EXF-001 | the same path behind a function call — runtime phase, must score lower |
| `ssh_key_exfil/` | PHX-EXF-002 | `~/.ssh/id_rsa` → network, on import |
| `hostname_beacon_setup/` | PHX-EXF-003 | four `SystemIdentity` sources → network at install |
| `clipboard_stealer/` | PHX-EXF-004 | `pyperclip.paste()` → network (phase-2 rule) |
| `urlopen_exec/` | PHX-DRP-001 | response body → `exec` |
| `download_and_run/` | PHX-DRP-002 | response → file → `chmod` → `subprocess`; taint passes through the *filename* |
| `curl_pipe_sh_setup/` | PHX-DRP-003 | `curl … \| sh` literal → `os.system` |
| `b64_exec/` | PHX-OBF-001 | one decode, then `exec` |
| `chr_join_exec/` | PHX-OBF-001 | two stacked transforms, for the folding depth bound |
| `hidden_import/` | PHX-OBF-002 | decoded literal → `importlib.import_module` |
| `reverse_shell/` | PHX-BKD-001 | socket → `dup2` onto stdio → `pty.spawn` |
| `pth_persistence/` | PHX-PER-001 | response body → a `.pth` file in site-packages |
| `wipe_home/` | PHX-SAB-001 | `rmtree` on a path derived from `~` |
| `setup_py_exfil/` | PHX-INS-001 + EXF-001 | egress inside a `cmdclass` `run()` — the *other* install root |
| `setup_py_exec_b64/` | PHX-INS-002 + OBF-001 | decoded literal executed at install time |
| `setup_py_reads_ssh/` | PHX-INS-003 | a sensitive read at install time with **no sink** |
| `setup_py_marker/` | — | safety fixture: writes `PHYLAXIS_EXECUTED` *if* executed. The marker's absence is the assertion. |

### benign

| fixture | guards against | why it is legitimate |
|---|---|---|
| `env_read_no_egress/` | PHX-EXF-001 | reads configuration; no sink exists in the package |
| `env_and_net_disjoint/` | PHX-EXF-001 | **the ablation pair** — env source and network sink four lines apart, no path between them |
| `ssh_config_local/` | PHX-EXF-002 | reads `~/.ssh/config` to list hosts; nothing is sent |
| `platform_check_local/` | PHX-EXF-003 | `platform.system()` chooses a code path, not a URL |
| `clipboard_local_copy/` | PHX-EXF-004 | writes the clipboard; `copy` is not a source |
| `download_data_file/` | PHX-DRP-001 | response reaches `csv.reader`, not `exec` |
| `download_asset_no_exec/` | PHX-DRP-002 | response is written and left there — no `chmod`, no exec |
| `subprocess_git_version/` | PHX-DRP-003 | argument list, known tool, no URL and no pipeline |
| `b64_decode_print/` | PHX-OBF-001 | decoded literal reaches `print` |
| `import_name_concat/` | PHX-OBF-002 | the module name is concatenated, so it still folds to a readable literal |
| `socket_echo_server/` | PHX-BKD-001 | sockets without the `dup2`-onto-stdio step |
| `bashrc_completion/` | PHX-PER-001 | appends a constant visible in the source — no source, no path |
| `clean_build_dir/` | PHX-SAB-001 | `rmtree` on relative `build/`, which is not a sensitive path |
| `setup_py_plain/` | PHX-INS-001 | a `setup.py` that only calls `setup()` |
| `setup_py_env_cflags/` | PHX-INS-003 | reads `CFLAGS`/`LDFLAGS`/`CC`, which are on the build-variable allow-list |

Two of the "benign" fixtures are **accepted false positives** rather than clean negatives, and
`docs/RULES.md` says so. They are here to pin the accepted level, so that a change which
silently promotes them shows up as a failing test:

| fixture | expected | why it is accepted |
|---|---|---|
| `setup_py_download_data/` | flags at **High**, never Critical | fetching a data file at install time is a real pattern; it is reported, not suppressed. No data rule fires, so the aggregate must not reach Malicious. |
| `setup_py_git_version/` | flags at **Medium** | `git describe` at build time is everywhere. Medium alone never reaches Suspicious; it matters only combined with a data rule (ADR-010 aggregate). |

## The pair worth knowing

`malicious/env_exfil_setup/` and `benign/env_and_net_disjoint/` are the two files the whole
method is argued from. Both read the environment. Both contain a network call. A detector
keyed on co-occurrence cannot separate them; a detector keyed on reachability separates them
on the first pass, because only one of them has a path from the environment read to the
request body. Configurations A and B of the ablation flag both; C and D must flag only the
first. That difference is the measurement.
