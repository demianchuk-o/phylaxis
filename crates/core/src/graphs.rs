//! CallGraph [6], DataFlowGraph [7], PackageGraph [8] and Confidence.
//!
//! Both graphs wrap `petgraph::graph::DiGraph` (DECISIONS.md, ADR-015) and index into the
//! shared [`SymbolTable`]. Node and edge indices are assigned in canonical order (files
//! sorted by path, then source order) so that reports are byte-deterministic (ADR-004).

use std::collections::BTreeMap;

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::ast::Span;
use crate::ids::{AstNodeId, FileId, SymbolId};
use crate::symbols::{QualifiedName, SymbolTable};
use crate::taxonomy::PhaseMap;

/// How sure the resolver is that an edge is real (ADR-005, ADR-007). A path inherits the
/// minimum confidence of its edges and the score multiplies by `weight()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A dynamic construct: `getattr` with a non-literal, `globals()[...]()`.
    Dynamic,
    /// Receiver type unknown; resolved to every definition with that name.
    Ambiguous,
    /// Lexically resolved to exactly one definition or one canonical external name.
    Resolved,
}

impl Confidence {
    /// WHY these numbers: ADR-007. They order, they do not measure; they are fixed before
    /// evaluation and any change is a new ADR.
    pub fn weight(self) -> f64 {
        match self {
            Confidence::Resolved => 1.0,
            Confidence::Ambiguous => 0.6,
            Confidence::Dynamic => 0.4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallNodeKind {
    /// A `def`, method or lambda defined in the package.
    Definition,
    /// The synthetic `<module>` node of one file: module-level code.
    ModuleRoot,
    /// A canonical external name (`requests.post`) called but not defined here.
    External,
    /// The `<dynamic>` node: callee unknown even by name.
    Dynamic,
}

/// A node of the call graph: a callable definition or an external target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallNode {
    pub symbol: SymbolId,
    pub kind: CallNodeKind,
    pub name: QualifiedName,
    pub file: Option<FileId>,
}

/// An edge of the call graph: one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    pub file: FileId,
    pub site: Span,
    pub ast_node: AstNodeId,
    pub confidence: Confidence,
    /// Set when the call site is a dynamic construct (ADR-005 step 7); rules may treat it
    /// as an obfuscation signal.
    pub dynamic_dispatch: bool,
}

/// [6] Definitions and the call sites between them.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    pub graph: DiGraph<CallNode, CallEdge>,
    pub by_symbol: BTreeMap<SymbolId, NodeIndex>,
}

impl CallGraph {
    pub fn node_of(&self, symbol: SymbolId) -> Option<NodeIndex> {
        self.by_symbol.get(&symbol).copied()
    }

    /// Adds a node, keeping the symbol index in sync. Idempotent per symbol.
    pub fn add_node(&mut self, node: CallNode) -> NodeIndex {
        if let Some(idx) = self.by_symbol.get(&node.symbol) {
            return *idx;
        }
        let symbol = node.symbol;
        let idx = self.graph.add_node(node);
        self.by_symbol.insert(symbol, idx);
        idx
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowNodeKind {
    /// A binding of a variable (assignment target, loop variable, `with … as`).
    Definition,
    /// A read of a variable.
    Use,
    Parameter,
    ReturnValue,
    /// The value produced by a call expression.
    CallResult,
    /// A literal (string, number, container display).
    Literal,
}

/// A node of the data-flow graph: one occurrence of a symbol or value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowNode {
    pub kind: FlowNodeKind,
    pub file: FileId,
    pub span: Span,
    pub ast_node: AstNodeId,
    /// The variable or callee symbol, when there is one.
    pub symbol: Option<SymbolId>,
    /// The definition (call-graph symbol) whose body contains this occurrence.
    pub owner: SymbolId,
    /// Human-readable label for evidence rendering (`token`, `requests.post(...)`).
    pub label: String,
}

/// Why taint flows along an edge (DECISIONS.md, ADR-006).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowEdgeKind {
    /// `x = y`, loop targets, `with … as x`.
    Assign,
    /// Actual argument to formal parameter, following a call-graph edge.
    Argument,
    /// Callee return value to the call expression's result.
    Return,
    /// A taint-preserving transform call; `obfuscating` marks encoders/encryptors.
    Transform {
        callee: QualifiedName,
        obfuscating: bool,
    },
    /// Element into container, container into element access.
    Container,
    /// `obj.attr` reads through the object.
    Attribute,
}

/// An edge of the data-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEdge {
    pub kind: FlowEdgeKind,
    pub span: Span,
    pub confidence: Confidence,
}

/// [7] Symbol occurrences and the taint-carrying transfers between them.
#[derive(Debug, Clone, Default)]
pub struct DataFlowGraph {
    pub graph: DiGraph<FlowNode, FlowEdge>,
}

/// [8] Everything the rule engine queries for one distribution.
#[derive(Debug, Clone, Default)]
pub struct PackageGraph {
    pub symbols: SymbolTable,
    pub call_graph: CallGraph,
    pub dfg: DataFlowGraph,
    pub phases: PhaseMap,
}

impl PackageGraph {
    /// The file a data-flow node belongs to.
    pub fn file_of_flow_node(&self, node: NodeIndex) -> Option<FileId> {
        self.dfg.graph.node_weight(node).map(|n| n.file)
    }

    /// The definition (call-graph symbol) whose body contains a data-flow node. Used by the
    /// definition-level co-occurrence configuration of the ablation (EVALUATION.md §6, B).
    pub fn owner_of_flow_node(&self, node: NodeIndex) -> Option<SymbolId> {
        self.dfg.graph.node_weight(node).map(|n| n.owner)
    }

    pub fn file_path(&self, file: FileId) -> Option<&str> {
        self.symbols.file_paths.get(&file).map(String::as_str)
    }
}
