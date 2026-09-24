//! The rule catalogue as static data. RULES.md is the prose; this file is the truth.
//! Change one, change the other, bump `RULESET_VERSION`.

use phylaxis_core::{
    AttackTechnique, ExecutionPhase, Objective, ReachabilityKind, RuleSpec, RulesetVersion,
    Severity, TaintSinkKind, TaintSourceKind,
};
use phylaxis_graph::reach::{SinkPattern, SourcePattern};
use serde::Serialize;

/// Bumped on any change to this file or to the report schema (ADR-017).
pub const RULESET_VERSION: RulesetVersion = RulesetVersion(1);

// ── Source patterns (ADR-006) ─────────────────────────────────────────────────────────
// Canonical dotted prefixes after import aliasing. `SensitiveFile` patterns are path
// prefixes with `~` meaning the home directory; the matcher normalises `os.path.expanduser`,
// `pathlib.Path.home()` and `os.environ['HOME']` idioms to `~`.
pub const SOURCE_PATTERNS: &[SourcePattern] = &[
    // Environment
    SourcePattern {
        kind: TaintSourceKind::Environment,
        pattern: "os.environ",
    },
    SourcePattern {
        kind: TaintSourceKind::Environment,
        pattern: "os.getenv",
    },
    SourcePattern {
        kind: TaintSourceKind::Environment,
        pattern: "os.environb",
    },
    SourcePattern {
        kind: TaintSourceKind::Environment,
        pattern: "dotenv",
    },
    // Sensitive files (path prefixes)
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.ssh",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.aws",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.netrc",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.git-credentials",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.config/gcloud",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.docker/config.json",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.kube",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.pypirc",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.bash_history",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.mozilla",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.config/google-chrome",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/AppData/Local/Google/Chrome",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/AppData/Roaming/discord",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.electrum",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "~/.bitcoin",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "/etc/passwd",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: "/etc/shadow",
    },
    SourcePattern {
        kind: TaintSourceKind::SensitiveFile,
        pattern: ".env",
    },
    // System identity
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "socket.gethostname",
    },
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "socket.getfqdn",
    },
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "platform",
    },
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "getpass.getuser",
    },
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "os.getlogin",
    },
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "uuid.getnode",
    },
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "os.getcwd",
    },
    SourcePattern {
        kind: TaintSourceKind::SystemIdentity,
        pattern: "os.uname",
    },
    // User input
    SourcePattern {
        kind: TaintSourceKind::UserInput,
        pattern: "pyperclip.paste",
    },
    SourcePattern {
        kind: TaintSourceKind::UserInput,
        pattern: "pynput",
    },
    SourcePattern {
        kind: TaintSourceKind::UserInput,
        pattern: "keyboard",
    },
    SourcePattern {
        kind: TaintSourceKind::UserInput,
        pattern: "PIL.ImageGrab",
    },
    SourcePattern {
        kind: TaintSourceKind::UserInput,
        pattern: "mss",
    },
    // Network response (code sources for droppers)
    SourcePattern {
        kind: TaintSourceKind::NetworkResponse,
        pattern: "urllib.request.urlopen",
    },
    SourcePattern {
        kind: TaintSourceKind::NetworkResponse,
        pattern: "requests.get",
    },
    SourcePattern {
        kind: TaintSourceKind::NetworkResponse,
        pattern: "requests.post",
    },
    SourcePattern {
        kind: TaintSourceKind::NetworkResponse,
        pattern: "http.client",
    },
    SourcePattern {
        kind: TaintSourceKind::NetworkResponse,
        pattern: "socket.socket.recv",
    },
    SourcePattern {
        kind: TaintSourceKind::NetworkResponse,
        pattern: "urllib3",
    },
    SourcePattern {
        kind: TaintSourceKind::NetworkResponse,
        pattern: "httpx",
    },
    // DecodedLiteral and SuspiciousLiteral are structural, not name-based; the pattern field
    // names the matcher. `<fold>` is a `reach::DECODERS` call over constant input; the
    // `<literal:…>` shapes are defined in `reach::literal_matches`.
    SourcePattern {
        kind: TaintSourceKind::DecodedLiteral,
        pattern: "<fold>",
    },
    SourcePattern {
        kind: TaintSourceKind::SuspiciousLiteral,
        pattern: "<literal:url-not-index>",
    },
    SourcePattern {
        kind: TaintSourceKind::SuspiciousLiteral,
        pattern: "<literal:raw-ip>",
    },
    SourcePattern {
        kind: TaintSourceKind::SuspiciousLiteral,
        pattern: "<literal:shell-pipeline>",
    },
    SourcePattern {
        kind: TaintSourceKind::SuspiciousLiteral,
        pattern: "<literal:wallet-address>",
    },
    SourcePattern {
        kind: TaintSourceKind::SuspiciousLiteral,
        pattern: "<literal:home-or-root-path>",
    },
    // Control source
    SourcePattern {
        kind: TaintSourceKind::PhaseRoot,
        pattern: "<phase-root>",
    },
];

// ── Sink patterns (ADR-006) ───────────────────────────────────────────────────────────
pub const SINK_PATTERNS: &[SinkPattern] = &[
    // Network egress
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "socket.socket.connect",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "socket.socket.send",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "socket.socket.sendall",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "socket.create_connection",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "urllib.request.urlopen",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "urllib.request.Request",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "http.client",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "requests",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "urllib3",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "httpx",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "aiohttp",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "smtplib",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "ftplib",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "dns.resolver",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "webbrowser.open",
        arg: None,
    },
    // Code execution
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "exec",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "eval",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "compile",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "subprocess",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "os.system",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "os.popen",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "os.exec",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "os.spawn",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "os.startfile",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "ctypes",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "pty.spawn",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "marshal.loads",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "pickle.loads",
        arg: Some(0),
    },
    // Persistence writes: file APIs whose *path* argument folds to a persistence location
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:~/.bashrc>",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:~/.zshrc>",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:~/.profile>",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:~/.config/autostart>",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:/etc/cron>",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:site-packages/*.pth>",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:sitecustomize.py>",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "winreg.SetValueEx",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::PersistenceWrite,
        pattern: "<write:~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup>",
        arg: None,
    },
    // Destructive FS
    SinkPattern {
        kind: TaintSinkKind::DestructiveFs,
        pattern: "shutil.rmtree",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::DestructiveFs,
        pattern: "os.remove",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::DestructiveFs,
        pattern: "os.unlink",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::DestructiveFs,
        pattern: "pathlib.Path.unlink",
        arg: None,
    },
    SinkPattern {
        kind: TaintSinkKind::DestructiveFs,
        pattern: "os.rmdir",
        arg: Some(0),
    },
    // Process control (reverse shell shape)
    SinkPattern {
        kind: TaintSinkKind::ProcessControl,
        pattern: "os.dup2",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::ProcessControl,
        pattern: "pty.spawn",
        arg: None,
    },
    // Dynamic import
    SinkPattern {
        kind: TaintSinkKind::DynamicImport,
        pattern: "__import__",
        arg: Some(0),
    },
    SinkPattern {
        kind: TaintSinkKind::DynamicImport,
        pattern: "importlib.import_module",
        arg: Some(0),
    },
];

/// Environment variables a `setup.py` may legitimately read (PHX-INS-003 exclusion).
///
/// Not consulted yet, and not needed yet: the engine targets only `SensitiveFile` reads for
/// PHX-INS-003, because the key of `os.environ['CFLAGS']` is not part of the data-flow graph
/// and so an allow-list could not be applied to an `Environment` read. Kept as the data the
/// rule will need once `Environment` joins it.
pub const BUILD_ENV_ALLOWLIST: &[&str] = &[
    "CFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "CC",
    "CXX",
    "CPPFLAGS",
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "PYTHON",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "CI",
    "READTHEDOCS",
    "SETUPTOOLS_SCM_PRETEND_VERSION",
    "PIP_NO_BUILD_ISOLATION",
    "SOURCE_DATE_EPOCH",
    "PYTHONDONTWRITEBYTECODE",
    "DEBUG",
    "VERBOSE",
];

/// Hosts that a URL literal may name without being `SuspiciousLiteral`. Defined beside the
/// matcher in `phylaxis_graph::reach`, so the list and its use cannot drift apart.
pub use phylaxis_graph::reach::OFFICIAL_INDEX_HOSTS;

// ── The rules (RULES.md) ──────────────────────────────────────────────────────────────
const fn tech(
    objective: Objective,
    typical_phase: ExecutionPhase,
    obfuscation: bool,
) -> AttackTechnique {
    AttackTechnique {
        objective,
        typical_phase,
        obfuscation,
    }
}

pub const RULES: &[RuleSpec] = &[
    RuleSpec {
        id: "PHX-EXF-001",
        title: "Environment variables exfiltrated over the network",
        technique: tech(Objective::Exfiltration, ExecutionPhase::Install, false),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::Environment],
        sinks: &[TaintSinkKind::NetworkEgress],
        positive_fixture: "malicious/env_exfil_setup",
        negative_fixture: "benign/env_and_net_disjoint",
        expected_fp: "telemetry SDKs sending CI flags; cloud clients reading AWS_* and talking to AWS",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-EXF-002",
        title: "Sensitive files exfiltrated over the network",
        technique: tech(Objective::Exfiltration, ExecutionPhase::Install, false),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::SensitiveFile],
        sinks: &[TaintSinkKind::NetworkEgress],
        positive_fixture: "malicious/ssh_key_exfil",
        negative_fixture: "benign/ssh_config_local",
        expected_fp: "backup/sync tools; dotfile managers",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-EXF-003",
        title: "System identity beacon",
        technique: tech(Objective::Exfiltration, ExecutionPhase::Install, false),
        severity: Severity::High,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::SystemIdentity],
        sinks: &[TaintSinkKind::NetworkEgress],
        positive_fixture: "malicious/hostname_beacon_setup",
        negative_fixture: "benign/platform_check_local",
        expected_fp: "crash reporters and analytics at runtime; build tools reporting platform",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-EXF-004",
        title: "User input capture exfiltrated",
        technique: tech(Objective::Exfiltration, ExecutionPhase::Runtime, false),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::UserInput],
        sinks: &[TaintSinkKind::NetworkEgress],
        positive_fixture: "malicious/clipboard_stealer",
        negative_fixture: "benign/clipboard_local_copy",
        expected_fp: "remote-desktop and screen-sharing packages",
        phase2: true,
    },
    RuleSpec {
        id: "PHX-DRP-001",
        title: "Remote code loaded and executed",
        technique: tech(Objective::Dropper, ExecutionPhase::Install, false),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::NetworkResponse],
        sinks: &[TaintSinkKind::CodeExecution],
        positive_fixture: "malicious/urlopen_exec",
        negative_fixture: "benign/download_data_file",
        expected_fp: "plugin systems loading extensions from a configured URL; self-updaters",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-DRP-002",
        title: "Download, write, execute",
        technique: tech(Objective::Dropper, ExecutionPhase::Install, false),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::NetworkResponse],
        sinks: &[TaintSinkKind::CodeExecution],
        positive_fixture: "malicious/download_and_run",
        negative_fixture: "benign/download_asset_no_exec",
        expected_fp: "installers fetching a platform-specific binary",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-DRP-003",
        title: "Shell one-liner or raw endpoint executed",
        technique: tech(Objective::Dropper, ExecutionPhase::Install, false),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::SuspiciousLiteral],
        sinks: &[TaintSinkKind::CodeExecution],
        positive_fixture: "malicious/curl_pipe_sh_setup",
        negative_fixture: "benign/subprocess_git_version",
        expected_fp: "doc scripts shelling out to curl for a badge; build scripts fetching a toolchain",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-OBF-001",
        title: "Decoded literal executed",
        technique: tech(Objective::Unknown, ExecutionPhase::Install, true),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::DecodedLiteral],
        sinks: &[TaintSinkKind::CodeExecution],
        positive_fixture: "malicious/b64_exec",
        negative_fixture: "benign/b64_decode_print",
        expected_fp: "packages evaluating an embedded compressed template; licence-check stubs",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-OBF-002",
        title: "Decoded literal used as an import name",
        technique: tech(Objective::Unknown, ExecutionPhase::Import, true),
        severity: Severity::Medium,
        reachability: ReachabilityKind::Data,
        sources: &[TaintSourceKind::DecodedLiteral],
        sinks: &[TaintSinkKind::DynamicImport],
        positive_fixture: "malicious/hidden_import",
        negative_fixture: "benign/import_name_concat",
        expected_fp: "none expected: concatenated names do not fold to DecodedLiteral",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-BKD-001",
        title: "Reverse shell",
        technique: tech(Objective::Backdoor, ExecutionPhase::Runtime, false),
        severity: Severity::Critical,
        reachability: ReachabilityKind::Data,
        sources: &[
            TaintSourceKind::SuspiciousLiteral,
            TaintSourceKind::NetworkResponse,
        ],
        sinks: &[TaintSinkKind::ProcessControl],
        positive_fixture: "malicious/reverse_shell",
        negative_fixture: "benign/socket_echo_server",
        expected_fp: "terminal multiplexers; remote-shell servers",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-PER-001",
        title: "Persistence write",
        technique: tech(Objective::Backdoor, ExecutionPhase::Install, false),
        severity: Severity::High,
        reachability: ReachabilityKind::Data,
        sources: &[
            TaintSourceKind::NetworkResponse,
            TaintSourceKind::DecodedLiteral,
        ],
        sinks: &[TaintSinkKind::PersistenceWrite],
        positive_fixture: "malicious/pth_persistence",
        negative_fixture: "benign/bashrc_completion",
        expected_fp: "dotfile managers",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-SAB-001",
        title: "Destructive file-system operation on user data",
        technique: tech(Objective::DenialOfService, ExecutionPhase::Install, false),
        severity: Severity::High,
        reachability: ReachabilityKind::Data,
        sources: &[
            TaintSourceKind::SensitiveFile,
            TaintSourceKind::SuspiciousLiteral,
        ],
        sinks: &[TaintSinkKind::DestructiveFs],
        positive_fixture: "malicious/wipe_home",
        negative_fixture: "benign/clean_build_dir",
        expected_fp: "cache-clearing tools under ~/.cache (Medium, reduced confidence)",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-INS-001",
        title: "Install-phase network egress",
        technique: tech(Objective::Unknown, ExecutionPhase::Install, false),
        severity: Severity::High,
        reachability: ReachabilityKind::Control,
        sources: &[TaintSourceKind::PhaseRoot],
        sinks: &[TaintSinkKind::NetworkEgress],
        positive_fixture: "malicious/setup_py_exfil",
        negative_fixture: "benign/setup_py_plain",
        expected_fp: "legacy setup.py installing deps or fetching data files (accepted class, benign/setup_py_download_data)",
        phase2: false,
    },
    RuleSpec {
        id: "PHX-INS-002",
        title: "Install-phase code execution",
        technique: tech(Objective::Unknown, ExecutionPhase::Install, false),
        severity: Severity::Medium,
        reachability: ReachabilityKind::Control,
        sources: &[TaintSourceKind::PhaseRoot],
        sinks: &[TaintSinkKind::CodeExecution],
        positive_fixture: "malicious/setup_py_exec_b64",
        negative_fixture: "benign/setup_py_plain",
        expected_fp: "setup.py running git describe, compiling assets, invoking pip (Medium, accepted: benign/setup_py_git_version)",
        phase2: false,
    },
    // The target of this rule is a read, not a sink call (RULES.md): the engine recognises it
    // by id and targets definitions containing a `SensitiveFile` read. `sinks` is not
    // consulted for it and is filled only to satisfy the catalogue invariants. Open request
    // in DECISIONS.md.
    RuleSpec {
        id: "PHX-INS-003",
        title: "Install-phase sensitive read",
        technique: tech(Objective::Exfiltration, ExecutionPhase::Install, false),
        severity: Severity::Medium,
        reachability: ReachabilityKind::Control,
        sources: &[TaintSourceKind::PhaseRoot],
        sinks: &[
            TaintSinkKind::NetworkEgress,
            TaintSinkKind::CodeExecution,
            TaintSinkKind::PersistenceWrite,
        ],
        positive_fixture: "malicious/setup_py_reads_ssh",
        negative_fixture: "benign/setup_py_env_cflags",
        expected_fp: "setup.py reading build variables: not a target, only SensitiveFile reads are",
        phase2: false,
    },
];

/// The catalogue.
pub fn catalogue() -> &'static [RuleSpec] {
    RULES
}

pub fn find_rule(id: &str) -> Option<&'static RuleSpec> {
    RULES.iter().find(|r| r.id == id)
}

/// The serialisable projection of a rule for `phylaxis rules --json` and
/// `phylaxis.rules()` (ADR-013). Fixture and FP fields are deliberately omitted: they
/// are development metadata, not API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleSummary {
    pub id: &'static str,
    pub title: &'static str,
    pub objective: Objective,
    pub typical_phase: ExecutionPhase,
    pub obfuscation: bool,
    pub severity: Severity,
    pub reachability: ReachabilityKind,
    pub sources: &'static [TaintSourceKind],
    pub sinks: &'static [TaintSinkKind],
    pub phase2: bool,
}

pub fn summaries() -> Vec<RuleSummary> {
    RULES
        .iter()
        .map(|r| RuleSummary {
            id: r.id,
            title: r.title,
            objective: r.technique.objective,
            typical_phase: r.technique.typical_phase,
            obfuscation: r.technique.obfuscation,
            severity: r.severity,
            reachability: r.reachability,
            sources: r.sources,
            sinks: r.sinks,
            phase2: r.phase2,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::RuleId;
    use std::collections::BTreeSet;

    // RULES.md "Rule invariants" 1–3, executable.
    #[test]
    fn ids_are_unique_and_well_formed() {
        let mut seen = BTreeSet::new();
        for r in RULES {
            assert!(RuleId::parse(r.id).is_ok(), "{} is not a valid id", r.id);
            assert!(seen.insert(r.id), "duplicate id {}", r.id);
        }
        assert_eq!(
            RULES.len(),
            15,
            "RULES.md lists 15 rules; keep the two in sync"
        );
    }

    #[test]
    fn every_rule_has_sources_sinks_and_fixtures() {
        for r in RULES {
            assert!(!r.sources.is_empty(), "{}: no sources", r.id);
            assert!(!r.sinks.is_empty(), "{}: no sinks", r.id);
            assert!(
                !r.positive_fixture.is_empty() && !r.negative_fixture.is_empty(),
                "{}: fixtures",
                r.id
            );
            assert!(
                r.positive_fixture.starts_with("malicious/"),
                "{}: positive fixture must be malicious/",
                r.id
            );
            assert!(
                r.negative_fixture.starts_with("benign/"),
                "{}: negative fixture must be benign/",
                r.id
            );
        }
    }

    #[test]
    fn control_rules_use_phase_root_only_and_data_rules_never() {
        for r in RULES {
            match r.reachability {
                ReachabilityKind::Control => {
                    assert_eq!(r.sources, &[TaintSourceKind::PhaseRoot], "{}", r.id)
                }
                ReachabilityKind::Data => {
                    assert!(!r.sources.contains(&TaintSourceKind::PhaseRoot), "{}", r.id)
                }
            }
        }
    }

    #[test]
    fn ruleset_version_is_positive_and_summaries_serialise() {
        const { assert!(RULESET_VERSION.0 >= 1) };
        let json = serde_json::to_string(&summaries()).unwrap();
        assert!(json.contains("PHX-EXF-001"));
        assert!(!json.contains("fixture"), "fixtures are not API");
    }

    // Every source kind and sink kind that a rule names has at least one pattern.
    #[test]
    fn every_kind_used_by_a_rule_has_a_pattern() {
        for r in RULES {
            for k in r.sources {
                assert!(
                    SOURCE_PATTERNS.iter().any(|p| p.kind == *k),
                    "{}: no source pattern for {:?}",
                    r.id,
                    k
                );
            }
            for k in r.sinks {
                assert!(
                    SINK_PATTERNS.iter().any(|p| p.kind == *k),
                    "{}: no sink pattern for {:?}",
                    r.id,
                    k
                );
            }
        }
    }
}
