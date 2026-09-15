# RULES — the rule catalogue

Ruleset version: **1** (`phylaxis_rules::RULESET_VERSION`). Bump it whenever a row here changes.

Every rule is a **source → sink reachability** requirement over the package graph
(`DECISIONS.md` ADR-004…ADR-009). There are no presence-only rules: install hooks, imports of
`base64`, or a `socket` import on their own never produce a finding. Each rule maps to a
technique in Backstabber's Knife Collection (Ohm et al., 2020) (`⚠ NEEDS VERIFICATION` of the
exact node labels against the paper; the labels below follow the objective categories and the
execution tree of Ohm et al. (2020) as summarised for this project).

## Identifiers

`PHX-<GROUP>-<NNN>`. Groups: `EXF` exfiltration · `DRP` dropper · `OBF` obfuscated payload ·
`BKD` backdoor / reverse shell · `PER` persistence · `SAB` sabotage · `INS` install-phase
capability (control reachability). Numbers are never reused.

## Common vocabulary

**Sources** (`TaintSourceKind`): `Environment`, `SensitiveFile`, `SystemIdentity`, `UserInput`,
`NetworkResponse`, `DecodedLiteral`, `SuspiciousLiteral`, `PhaseRoot`.
**Sinks** (`TaintSinkKind`): `NetworkEgress`, `CodeExecution`, `PersistenceWrite`,
`DestructiveFs`, `ProcessControl`, `DynamicImport`.
**Reachability**: `Data` (path in the data-flow graph) or `Control` (path in the call graph
from a phase root). **Phase weighting** applies to all rules (ADR-008). **Severity**:
Critical 1.0 · High 0.8 · Medium 0.6 · Low 0.4 (ADR-010).

The exact dotted-name patterns live in `crates/rules/src/catalogue.rs` and are the single
source of truth; the tables below describe them.

---

## Catalogue

### PHX-EXF-001 — Environment variables exfiltrated over the network

| | |
|---|---|
| Catches | Reading environment variables (`os.environ`, `os.getenv`, `os.environb`, `dotenv`) and sending the value, or anything derived from it, to a network sink. |
| Technique | Objective: **exfiltration**; execution: any phase (install dominant). |
| Sources → sinks | `Environment` → `NetworkEgress`. Reachability: `Data`. |
| Severity | Critical |
| Expected FPs | Telemetry SDKs that send `CI=true`-style flags; cloud clients that read `AWS_*` variables and legitimately talk to AWS. Mitigation: benign fixtures for both; Runtime phase weight halves the score. |
| Verification | `fixtures/malicious/env_exfil_setup/` (positive, install phase); `fixtures/malicious/env_exfil_runtime/` (positive, runtime, lower score); `fixtures/benign/env_read_no_egress/` (reads env, never sends: **no finding**); `fixtures/benign/env_and_net_disjoint/` (env read and `requests.post` in the same file, no path: **no finding**, the ablation pair). |

### PHX-EXF-002 — Sensitive files exfiltrated over the network

| | |
|---|---|
| Catches | Opening a path from the sensitive list (`~/.ssh/*`, `~/.aws/credentials`, `~/.netrc`, `~/.git-credentials`, `~/.config/gcloud`, browser profile directories, wallet files, `/etc/passwd`, `*.env`) and sending its content or a derivation to the network. |
| Technique | Objective: **exfiltration** (credential theft). |
| Sources → sinks | `SensitiveFile` → `NetworkEgress`. `Data`. |
| Severity | Critical |
| Expected FPs | Backup and sync tools; dotfile managers; SSH clients that legitimately read `~/.ssh/config`. Mitigation: a benign fixture reading `~/.ssh/config` for a local operation only. |
| Verification | `fixtures/malicious/ssh_key_exfil/` (positive); `fixtures/benign/ssh_config_local/` (negative). |

### PHX-EXF-003 — System identity beacon

| | |
|---|---|
| Catches | Collecting hostname, user name, platform, MAC (`uuid.getnode`), public IP, current directory, and sending the tuple to the network: the "who installed me" beacon typical of typosquats and bug-bounty probes. |
| Technique | Objective: **exfiltration** (reconnaissance); execution: install dominant. |
| Sources → sinks | `SystemIdentity` → `NetworkEgress`. `Data`. |
| Severity | High (Medium when only one identity source is on the path) |
| Expected FPs | Crash reporters and analytics (`sentry`, `posthog`) at runtime; build tools reporting platform to a mirror. This rule will have the highest FP rate of the catalogue; it is kept because it is the single most common install-time payload shape. |
| Verification | `fixtures/malicious/hostname_beacon_setup/` (positive); `fixtures/benign/platform_check_local/` (negative: reads `platform.system()` to choose a code path). |

### PHX-EXF-004 — User input capture exfiltrated

| | |
|---|---|
| Catches | Clipboard (`pyperclip`, `tkinter` clipboard), keystrokes (`pynput`, `keyboard`), screenshots (`PIL.ImageGrab`, `mss`) flowing to a network sink. |
| Technique | Objective: **exfiltration** (spyware). |
| Sources → sinks | `UserInput` → `NetworkEgress`. `Data`. |
| Severity | Critical |
| Expected FPs | Remote-desktop and screen-sharing packages. Rare on PyPI; accepted. |
| Verification | `fixtures/malicious/clipboard_stealer/` (positive); `fixtures/benign/clipboard_local_copy/` (negative). **Phase 2 rule**: implement after EXF-001…003. |

### PHX-DRP-001 — Remote code loaded and executed

| | |
|---|---|
| Catches | The body of a network response passed to `exec`, `eval`, `compile`, `marshal.loads`+exec, or written to a file that is then executed. |
| Technique | Objective: **dropper** (second-stage download); execution: install dominant. |
| Sources → sinks | `NetworkResponse` → `CodeExecution`. `Data`. |
| Severity | Critical |
| Expected FPs | Plugin systems that download and import extensions from a *configured* URL; self-updaters. Mitigation: `SuspiciousLiteral` on the URL raises confidence, a URL from configuration lowers it; benign fixture with a self-updater guarded by user confirmation still flags at Medium (documented accepted FP). |
| Verification | `fixtures/malicious/urlopen_exec/` (positive); `fixtures/benign/download_data_file/` (negative: downloads a CSV and parses it, never executes). |

### PHX-DRP-002 — Download, write, execute

| | |
|---|---|
| Catches | Network response written to disk, followed by `chmod`/`subprocess`/`os.system`/`os.startfile` on that path. |
| Technique | Objective: **dropper** (binary payload). |
| Sources → sinks | `NetworkResponse` → (`FileWrite` as a transform) → `CodeExecution`. `Data`, path passes through the file-name symbol. |
| Severity | Critical |
| Expected FPs | Installers that fetch a platform-specific binary (`playwright install`-style). Documented accepted FP at Install phase; these are exactly what an auditor should look at. |
| Verification | `fixtures/malicious/download_and_run/` (positive); `fixtures/benign/download_asset_no_exec/` (negative). |

### PHX-DRP-003 — Shell one-liner or raw endpoint executed

| | |
|---|---|
| Catches | A literal containing a shell pipeline to a fetcher (`curl … | sh`, `wget … -O- | bash`, `powershell -enc …`, `certutil -urlcache`), a raw IP endpoint, or a non-index URL, reaching `subprocess`/`os.system`/`os.popen`. |
| Technique | Objective: **dropper**; execution: install dominant. |
| Sources → sinks | `SuspiciousLiteral` → `CodeExecution`. `Data` (path of length ≥ 1). |
| Severity | Critical |
| Expected FPs | Documentation-generation scripts that shell out to `curl` for a badge; build scripts fetching a toolchain. Low frequency. |
| Verification | `fixtures/malicious/curl_pipe_sh_setup/` (positive); `fixtures/benign/subprocess_git_version/` (negative: `subprocess.run(["git", "describe"])` with a safe literal). |

### PHX-OBF-001 — Decoded literal executed

| | |
|---|---|
| Catches | A string literal decoded by `base64`/hex/`codecs`/`zlib`/`marshal`/reversal/`chr`-join (ADR-018 folding) whose result reaches `exec`, `eval`, `compile` or `subprocess`. |
| Technique | Obfuscation: **encoding** (Backstabber's dominant obfuscation); objective inferred from the decoded payload where folding succeeds. |
| Sources → sinks | `DecodedLiteral` → `CodeExecution`. `Data`. Path is marked `obfuscated`. |
| Severity | Critical |
| Expected FPs | Packages that embed a compressed resource (e.g. a zlib'd template) and *evaluate* it, licence-check stubs. Rare; a benign fixture that decodes a literal and only *prints* it must not flag. |
| Verification | `fixtures/malicious/b64_exec/` (positive); `fixtures/malicious/chr_join_exec/` (positive, folding depth); `fixtures/benign/b64_decode_print/` (negative). |

### PHX-OBF-002 — Decoded literal used as an import name

| | |
|---|---|
| Catches | `__import__(decoded)` / `importlib.import_module(decoded)` where `decoded` is a folded literal, hiding which module is loaded. |
| Technique | Obfuscation: **encoding** of imports. |
| Sources → sinks | `DecodedLiteral` → `DynamicImport`. `Data`. |
| Severity | Medium (Low alone; it mostly raises the score of another finding in the same package) |
| Expected FPs | Compatibility shims that build module names from strings (`"PyQt" + version`): those are *concatenated*, not *decoded*, and do not fold to a `DecodedLiteral`. |
| Verification | `fixtures/malicious/hidden_import/` (positive); `fixtures/benign/import_name_concat/` (negative). |

### PHX-BKD-001 — Reverse shell

| | |
|---|---|
| Catches | A socket connected to a remote endpoint whose file descriptor is duplicated onto stdin/stdout/stderr (`os.dup2`) followed by a shell spawn, or `pty.spawn`/`subprocess` with the socket as stdio. |
| Technique | Objective: **backdoor**. |
| Sources → sinks | `SuspiciousLiteral` or `NetworkResponse` (the socket) → `ProcessControl`. `Data`. |
| Severity | Critical |
| Expected FPs | Terminal multiplexers and remote-shell packages (`paramiko` servers). Very rare; accepted. |
| Verification | `fixtures/malicious/reverse_shell/` (positive); `fixtures/benign/socket_echo_server/` (negative: socket without `dup2`). |

### PHX-PER-001 — Persistence write

| | |
|---|---|
| Catches | Data from a network response or a decoded literal written to a persistence location: shell rc files, `~/.config/autostart`, crontab, `winreg` `Run` keys, site-packages `.pth` files, `sitecustomize.py`. |
| Technique | Execution: **conditional/persistent**; objective typically **backdoor** or **dropper** stage two. |
| Sources → sinks | `NetworkResponse` \| `DecodedLiteral` → `PersistenceWrite`. `Data`. |
| Severity | High |
| Expected FPs | Shell-completion installers that append to `~/.bashrc` with a *literal* known string (not decoded, not downloaded): no path, no finding. Dotfile managers: accepted FP. |
| Verification | `fixtures/malicious/pth_persistence/` (positive); `fixtures/benign/bashrc_completion/` (negative). |

### PHX-SAB-001 — Destructive file-system operation on user data

| | |
|---|---|
| Catches | `shutil.rmtree`, `os.remove`/`os.unlink` in a loop, or `pathlib.Path.unlink` applied to a path derived from the home directory, root, or a sensitive path literal, outside a build directory. |
| Technique | Objective: **sabotage / DoS**. |
| Sources → sinks | `SensitiveFile` \| `SuspiciousLiteral` (path literal `/`, `~`, `C:\\`) → `DestructiveFs`. `Data`. |
| Severity | High |
| Expected FPs | Build clean-up (`rm -rf build/`): the path literal is relative and not on the sensitive list, so no source, no finding. Cache-clearing tools under `~/.cache`: accepted FP at Medium (path under home but under `.cache`, confidence reduced). |
| Verification | `fixtures/malicious/wipe_home/` (positive); `fixtures/benign/clean_build_dir/` (negative). |

### PHX-INS-001 — Install-phase network egress

| | |
|---|---|
| Catches | Any network sink reachable in the call graph from an install root (`setup.py` module level, `cmdclass` `run` methods, in-tree build backend). |
| Technique | Execution: **install**; objective unknown (the rule certifies the phase, the data rules certify the objective). |
| Sources → sinks | `PhaseRoot(Install)` → `NetworkEgress`. Reachability: `Control`. |
| Severity | High |
| Expected FPs | Legacy `setup.py` that pip-installs dependencies via `subprocess` or fetches data files; `setup_requires`. These are real and frequent in old packages; they are reported as an accepted false-positive class rather than suppressed, and the benign fixture keeps the score at High only when combined with a data rule. |
| Verification | `fixtures/malicious/setup_py_exfil/` (positive together with EXF-001); `fixtures/benign/setup_py_plain/` (negative: pure `setup()` call); `fixtures/benign/setup_py_download_data/` (positive at High but *not* Critical: accepted, documented). |

### PHX-INS-002 — Install-phase code execution

| | |
|---|---|
| Catches | `subprocess`, `os.system`, `exec`, `eval`, `ctypes` reachable from an install root. |
| Technique | Execution: **install**. |
| Sources → sinks | `PhaseRoot(Install)` → `CodeExecution`. `Control`. |
| Severity | Medium (High when the callee is `exec`/`eval`) |
| Expected FPs | Very common: `setup.py` running `git describe`, compiling assets, invoking `pip`. Mitigation: Medium alone; the score reaches Malicious only in combination with a data rule (ADR-010 aggregate). |
| Verification | `fixtures/malicious/setup_py_exec_b64/` (positive with OBF-001); `fixtures/benign/setup_py_git_version/` (Medium, accepted). |

### PHX-INS-003 — Install-phase sensitive read

| | |
|---|---|
| Catches | A `SensitiveFile` or `Environment` source reachable from an install root, even without a sink (the read alone at install time is a capability that has no legitimate reason). |
| Technique | Execution: **install**; objective: exfiltration precursor. |
| Sources → sinks | `PhaseRoot(Install)` → definition containing a `SensitiveFile` read. `Control`. |
| Severity | Medium |
| Expected FPs | `setup.py` reading `os.environ` for build flags (`CFLAGS`, `PHYLAXIS_*`). Mitigation: `Environment` reads of names on an allow-list of build variables are not sources for this rule; the allow-list is data in `catalogue.rs`. |
| Verification | `fixtures/malicious/setup_py_reads_ssh/` (positive); `fixtures/benign/setup_py_env_cflags/` (negative). |

---

## Rule invariants (tested in `crates/rules/src/catalogue.rs`)

1. Every rule id is unique and matches `PHX-[A-Z]{3}-[0-9]{3}`.
2. Every rule names at least one source kind and one sink kind, a technique, a severity, and a
   reachability kind.
3. `Control` rules use `PhaseRoot` as their only source kind; `Data` rules never use it.
4. Every rule names a positive and a negative fixture path; the integration test asserts the
   positive fixture yields that rule id and the negative fixture yields no finding at or above
   Suspicious (or the documented accepted level).
5. The catalogue is a `const`/static table: no I/O, no configuration file, no environment.

## Coverage against the taxonomy

| Backstabber dimension | Covered by |
|---|---|
| Objective: exfiltration | EXF-001…004, INS-003 |
| Objective: dropper | DRP-001…003 |
| Objective: backdoor | BKD-001, PER-001 |
| Objective: denial of service | SAB-001 |
| Objective: financial gain (mining, wallet theft) | partially via EXF-002 (wallet files) and DRP-002 (miner binary); a dedicated wallet-address rule is deferred (phase 2, `PHX-FIN-001`, request in DECISIONS.md if needed) |
| Execution: install | INS-001…003 plus phase weighting on every rule |
| Execution: runtime (import / call) | phase weighting |
| Execution: conditional | `conditional` attribute on every path |
| Obfuscation: encoding | OBF-001, OBF-002, `obfuscated` attribute |
| Injection tree (typosquatting, account compromise, …) | **out of scope**: not observable from one sdist; stated in 1.5 |
