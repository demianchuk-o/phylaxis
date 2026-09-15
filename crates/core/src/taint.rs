//! TaintSource [9] and TaintSink [10]: where paths start and end (DECISIONS.md, ADR-006).

use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

use crate::path::Location;
use crate::symbols::QualifiedName;

/// What kind of data (or control) a source yields. See RULES.md "Common vocabulary".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSourceKind {
    Environment,
    SensitiveFile,
    SystemIdentity,
    UserInput,
    NetworkResponse,
    DecodedLiteral,
    SuspiciousLiteral,
    /// The synthetic install or import entry point: a source of *control*, used only by
    /// control-reachability rules (ADR-008).
    PhaseRoot,
}

/// What a sink consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSinkKind {
    NetworkEgress,
    CodeExecution,
    PersistenceWrite,
    DestructiveFs,
    ProcessControl,
    DynamicImport,
}

/// [9] A matched source occurrence in one package graph. `node` is the data-flow node
/// carrying the source's *result* (for `PhaseRoot`, the call-graph node of the root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSource {
    pub kind: TaintSourceKind,
    /// The catalogue pattern that matched (`os.environ`, `~/.ssh`).
    pub pattern: QualifiedName,
    pub location: Location,
    pub node: NodeIndex,
}

/// [10] A matched sink occurrence. `node` is the data-flow node of the dangerous
/// *argument*; `definition` is the call-graph node of the definition containing the call,
/// which is what control reachability targets and what phase weighting reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSink {
    pub kind: TaintSinkKind,
    pub pattern: QualifiedName,
    pub location: Location,
    pub node: NodeIndex,
    pub definition: NodeIndex,
}
