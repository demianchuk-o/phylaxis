//! DependencyGraph and BlastRadius: the prioritisation tier (tier 2 of the architecture,
//! phase 3). A confirmed finding in a package that 40 000 projects depend on is not the same
//! problem as the same finding in a package nobody installs, and these types are where that
//! difference will be measured. They exist now so the report schema does not have to change
//! when the tier lands; construction is a phase-3 task (T-17).

use std::collections::BTreeMap;

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::package::PackageName;

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

impl DependencyGraph {
    pub fn node_of(&self, name: &PackageName) -> Option<NodeIndex> {
        self.by_name.get(name).copied()
    }

    /// Number of packages that transitively depend on `name` (reverse reachability).
    pub fn transitive_dependents(&self, name: &PackageName) -> Option<u64> {
        let _ = name;
        todo!("reverse BFS over incoming edges; phase 3 (T-17)")
    }
}

/// The impact of a flagged package: how much of the ecosystem it can reach.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadius {
    pub package: PackageName,
    pub transitive_dependents: u64,
    /// `transitive_dependents / total_packages`.
    pub share: f64,
    pub direct_dependents: u32,
    /// Betweenness centrality if computed; `None` when the graph is too large for it.
    pub betweenness: Option<f64>,
}
