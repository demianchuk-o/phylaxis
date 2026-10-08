//! DependencyGraph and BlastRadius: the prioritisation tier (T-17, ADR-027). A confirmed
//! finding in a package that half of a project depends on is not the same problem as the same
//! finding in a leaf nobody else imports, and these types are where that difference is
//! measured.
//!
//! The graph is one project's resolved dependency set: a node per package in it, an edge
//! from each package to every other package of the set that it declares as a requirement.
//! Requirements naming packages outside the set are dropped — the set is what is installed.
//! Ranking orders findings; it never adds or removes one.

use std::collections::{BTreeMap, VecDeque};

use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::package::PackageName;

/// Largest graph betweenness is computed for. Brandes' algorithm is O(V·E); a project's
/// dependency set is tens to hundreds of packages, so the cap exists only to keep an
/// accidental whole-index input from turning a ranking into a long computation.
pub const MAX_BETWEENNESS_NODES: usize = 5_000;

/// A declared dependency, kept as the raw requirement string (`requests>=2,<3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub requirement: String,
    /// `true` for `extras` and environment-marker-conditional requirements.
    pub optional: bool,
}

/// Packages and their declared dependencies. Edge direction: dependant → dependency.
#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub graph: DiGraph<PackageName, DependencyEdge>,
    pub by_name: BTreeMap<PackageName, NodeIndex>,
}

/// The package a requirement names, and whether it is optional (an extra or behind an
/// environment marker). `None` for a string that does not start with a valid name.
/// PEP 508: the name comes first and ends at the first character outside its alphabet
/// (`requests[socks]>=2; python_version < "3.12"`, `pkg @ https://…`).
pub fn requirement_name(requirement: &str) -> Option<(PackageName, bool)> {
    let r = requirement.trim();
    let end = r
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(r.len());
    let name = PackageName::normalize(&r[..end]).ok()?;
    Some((name, r.contains(';')))
}

impl DependencyGraph {
    /// Builds the graph of a resolved set: `packages` maps each package to its declared
    /// requirement strings. Nodes are added in name order and edges in (dependant name,
    /// requirement order), so node and edge indices are a function of the input alone. Two
    /// requirements on the same package keep the first; a self-requirement is dropped.
    pub fn from_requirements(packages: &BTreeMap<PackageName, Vec<String>>) -> Self {
        let mut g = Self::default();
        for name in packages.keys() {
            let i = g.graph.add_node(name.clone());
            g.by_name.insert(name.clone(), i);
        }
        for (name, reqs) in packages {
            let from = g.by_name[name];
            for req in reqs {
                let Some((dep, optional)) = requirement_name(req) else {
                    continue;
                };
                let Some(&to) = g.by_name.get(&dep) else {
                    continue;
                };
                if to != from && g.graph.find_edge(from, to).is_none() {
                    g.graph.add_edge(
                        from,
                        to,
                        DependencyEdge {
                            requirement: req.clone(),
                            optional,
                        },
                    );
                }
            }
        }
        g
    }

    pub fn node_of(&self, name: &PackageName) -> Option<NodeIndex> {
        self.by_name.get(name).copied()
    }

    /// Number of packages that transitively depend on `name` (reverse reachability), the
    /// package itself excluded. `None` when `name` is not in the graph.
    pub fn transitive_dependents(&self, name: &PackageName) -> Option<u64> {
        let start = self.node_of(name)?;
        let mut seen = vec![false; self.graph.node_count()];
        seen[start.index()] = true;
        let mut queue = VecDeque::from([start]);
        let mut count = 0u64;
        while let Some(n) = queue.pop_front() {
            for d in self.graph.neighbors_directed(n, Direction::Incoming) {
                if !seen[d.index()] {
                    seen[d.index()] = true;
                    count += 1;
                    queue.push_back(d);
                }
            }
        }
        Some(count)
    }

    /// Betweenness centrality of every node, by index, normalised to [0, 1] for a directed
    /// graph (Brandes 2001, unweighted). `None` above [`MAX_BETWEENNESS_NODES`].
    ///
    /// WHY besides the dependent count: a package can have few dependents and still sit on
    /// most of the chains between the project and its leaves — the narrow waist a compromise
    /// travels through. Dependents measure reach; betweenness measures how central the
    /// package is to the tree's structure.
    pub fn betweenness(&self) -> Option<Vec<f64>> {
        let n = self.graph.node_count();
        if n > MAX_BETWEENNESS_NODES {
            return None;
        }
        let mut cb = vec![0.0f64; n];
        for s in self.graph.node_indices() {
            let mut stack = Vec::with_capacity(n);
            let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
            let mut sigma = vec![0.0f64; n];
            let mut dist = vec![-1i64; n];
            sigma[s.index()] = 1.0;
            dist[s.index()] = 0;
            let mut queue = VecDeque::from([s]);
            while let Some(v) = queue.pop_front() {
                stack.push(v.index());
                for w in self.graph.neighbors_directed(v, Direction::Outgoing) {
                    let (vi, wi) = (v.index(), w.index());
                    if dist[wi] < 0 {
                        dist[wi] = dist[vi] + 1;
                        queue.push_back(w);
                    }
                    if dist[wi] == dist[vi] + 1 {
                        sigma[wi] += sigma[vi];
                        preds[wi].push(vi);
                    }
                }
            }
            let mut delta = vec![0.0f64; n];
            while let Some(w) = stack.pop() {
                for &v in &preds[w] {
                    delta[v] += sigma[v] / sigma[w] * (1.0 + delta[w]);
                }
                if w != s.index() {
                    cb[w] += delta[w];
                }
            }
        }
        if n > 2 {
            let scale = ((n - 1) * (n - 2)) as f64;
            cb.iter_mut().for_each(|c| *c /= scale);
        }
        Some(cb)
    }

    /// The blast radius of `name` within this graph, with its betweenness taken from
    /// `betweenness` (computed once for the graph, by node index) when given.
    pub fn blast_radius(
        &self,
        name: &PackageName,
        betweenness: Option<&[f64]>,
    ) -> Option<BlastRadius> {
        let node = self.node_of(name)?;
        let transitive = self.transitive_dependents(name)?;
        let others = self.graph.node_count().saturating_sub(1);
        Some(BlastRadius {
            package: name.clone(),
            transitive_dependents: transitive,
            share: if others == 0 {
                0.0
            } else {
                transitive as f64 / others as f64
            },
            direct_dependents: self
                .graph
                .neighbors_directed(node, Direction::Incoming)
                .count() as u32,
            betweenness: betweenness.and_then(|b| b.get(node.index()).copied()),
        })
    }
}

/// The impact of a flagged package: how much of the project's dependency tree depends on it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadius {
    pub package: PackageName,
    pub transitive_dependents: u64,
    /// `transitive_dependents` over the number of *other* packages in the graph.
    pub share: f64,
    pub direct_dependents: u32,
    /// Betweenness centrality if computed; `None` when the graph is too large for it.
    pub betweenness: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> PackageName {
        PackageName::normalize(s).unwrap()
    }

    fn graph(edges: &[(&str, &[&str])]) -> DependencyGraph {
        let map = edges
            .iter()
            .map(|(p, deps)| (n(p), deps.iter().map(|d| d.to_string()).collect()))
            .collect();
        DependencyGraph::from_requirements(&map)
    }

    #[test]
    fn requirement_names_follow_pep_508() {
        assert_eq!(
            requirement_name("Requests[socks]>=2,<3"),
            Some((n("requests"), false))
        );
        assert_eq!(
            requirement_name("rich ; extra == \"cli\""),
            Some((n("rich"), true))
        );
        assert_eq!(
            requirement_name("pkg @ https://h.invalid/p.tar.gz"),
            Some((n("pkg"), false))
        );
        assert_eq!(
            requirement_name("Typing_Extensions"),
            Some((n("typing-extensions"), false))
        );
        assert_eq!(requirement_name(">=2"), None);
    }

    // app → web → {http, json}; http → json; cli → http. `json` is under everything.
    fn project() -> DependencyGraph {
        graph(&[
            ("app", &["web>=1", "cli"]),
            ("web", &["http", "json", "outside-the-set"]),
            ("http", &["json"]),
            ("cli", &["http; python_version < \"3.12\""]),
            ("json", &[]),
        ])
    }

    #[test]
    fn transitive_dependents_count_everything_above_a_package() {
        let g = project();
        assert_eq!(g.transitive_dependents(&n("json")), Some(4));
        assert_eq!(g.transitive_dependents(&n("http")), Some(3));
        assert_eq!(g.transitive_dependents(&n("app")), Some(0));
        assert_eq!(g.transitive_dependents(&n("not-here")), None);
    }

    #[test]
    fn requirements_outside_the_set_and_self_requirements_add_no_edge() {
        let g = graph(&[("a", &["a", "b", "b>=2", "zzz"]), ("b", &[])]);
        assert_eq!(g.graph.edge_count(), 1);
    }

    #[test]
    fn blast_radius_reports_share_and_direct_dependents() {
        let g = project();
        let b = g.blast_radius(&n("http"), None).unwrap();
        assert_eq!(b.transitive_dependents, 3);
        assert_eq!(b.direct_dependents, 2);
        assert!((b.share - 0.75).abs() < 1e-12);
        assert_eq!(b.betweenness, None);
    }

    // On a chain a → b → c, only b lies between two others: one pair (a, c) of the
    // (n-1)(n-2) = 2 ordered pairs that exclude b.
    #[test]
    fn betweenness_on_a_chain() {
        let g = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &[])]);
        let bc = g.betweenness().unwrap();
        let at = |s: &str| bc[g.node_of(&n(s)).unwrap().index()];
        assert!((at("b") - 0.5).abs() < 1e-12);
        assert_eq!(at("a"), 0.0);
        assert_eq!(at("c"), 0.0);
    }

    #[test]
    fn construction_is_independent_of_input_order() {
        let a = graph(&[("x", &["y"]), ("y", &["z"]), ("z", &[])]);
        let b = graph(&[("z", &[]), ("y", &["z"]), ("x", &["y"])]);
        let names = |g: &DependencyGraph| {
            g.graph
                .node_indices()
                .map(|i| g.graph[i].as_str().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&a), names(&b));
    }
}
