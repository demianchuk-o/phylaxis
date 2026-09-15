//! Domain types, attack taxonomy and shared configuration.
//!
//! This crate is the domain model: one definition per concept, shared by every other crate,
//! so that "call graph" or "finding" means exactly one thing across the workspace. It has no
//! I/O and depends only on `serde`, `thiserror` and `petgraph` (DECISIONS.md, ADR-015).
//!
//! The model lands in blocks, and this module list grows with them. Landed so far — identity
//! and inputs, the shape of parsed source, and the signal itself in type form: when code
//! runs, the two graphs a path is found in, where a path starts and ends, and the shape of
//! the evidence it produces. The bracketed numbers are stable entity ids used when the model
//! is written up outside the code.
//! - `ids`       FileId, AstNodeId, SymbolId — the arena indices every table is addressed by
//! - `package`   Package [1], Distribution [2], Sha256Digest
//! - `source`    SourceFile [3], ProjectMeta
//! - `ast`       Ast, AstNode [4], Span
//! - `symbols`   Symbol, SymbolTable [5], QualifiedName
//! - `taxonomy`  AttackTechnique [12], ExecutionPhase, PhaseMap [13]
//! - `graphs`    CallGraph [6], DataFlowGraph [7], PackageGraph [8], Confidence
//! - `taint`     TaintSource [9], TaintSink [10]
//! - `path`      ReachabilityPath [11], PathStep, Location
//! - `error`     CoreError

pub mod ast;
pub mod error;
pub mod graphs;
pub mod ids;
pub mod package;
pub mod path;
pub mod source;
pub mod symbols;
pub mod taint;
pub mod taxonomy;

pub use ast::{Ast, AstKind, AstNode, Span};
pub use error::CoreError;
pub use graphs::{
    CallEdge, CallGraph, CallNode, CallNodeKind, Confidence, DataFlowGraph, FlowEdge, FlowEdgeKind,
    FlowNode, FlowNodeKind, PackageGraph,
};
pub use ids::{AstNodeId, FileId, SymbolId};
pub use package::{Distribution, DistributionKind, Package, PackageName, Sha256Digest};
pub use path::{Location, PathStep, PathStepKind, ReachabilityKind, ReachabilityPath};
pub use source::{ProjectMeta, SourceFile, SourceKind};
pub use symbols::{ImportAlias, QualifiedName, Symbol, SymbolKind, SymbolTable};
pub use taint::{TaintSink, TaintSinkKind, TaintSource, TaintSourceKind};
pub use taxonomy::{
    AttackTechnique, ExecutionPhase, Objective, PhaseMap, PhaseRoot, PhaseRootKind,
};

#[cfg(test)]
mod tests {
    // WHY: the published domain model is referred to by name in the design documents.
    // Renaming one of these types is a decision, not a refactor, so this test names them and
    // stops compiling if any disappears. It is a drift guard, not a behaviour test. The list
    // grows to all 27 entities as the remaining blocks land.
    #[test]
    fn domain_model_names_exist() {
        use std::any::type_name;
        let names = [
            type_name::<crate::Package>(),
            type_name::<crate::Distribution>(),
            type_name::<crate::SourceFile>(),
            type_name::<crate::AstNode>(),
            type_name::<crate::Symbol>(),
            type_name::<crate::SymbolTable>(),
            type_name::<crate::CallGraph>(),
            type_name::<crate::DataFlowGraph>(),
            type_name::<crate::PackageGraph>(),
            type_name::<crate::TaintSource>(),
            type_name::<crate::TaintSink>(),
            type_name::<crate::ReachabilityPath>(),
            type_name::<crate::AttackTechnique>(),
            type_name::<crate::ExecutionPhase>(),
            type_name::<crate::PhaseMap>(),
        ];
        assert_eq!(names.len(), 15);
    }
}
