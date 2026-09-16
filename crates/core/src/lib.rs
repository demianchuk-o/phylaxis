//! Domain types, attack taxonomy and shared configuration.
//!
//! This crate is the domain model: one definition per concept, shared by every other crate,
//! so that "call graph" or "finding" means exactly one thing across the workspace. It has no
//! I/O and depends only on `serde`, `thiserror` and `petgraph` (DECISIONS.md, ADR-015).
//!
//! Module map (the bracketed numbers are stable entity ids used when the model is written up
//! outside the code):
//! - `package`   Package [1], Distribution [2], Sha256Digest
//! - `source`    SourceFile [3], ProjectMeta
//! - `ast`       Ast, AstNode [4], Span
//! - `symbols`   Symbol, SymbolTable [5], QualifiedName
//! - `graphs`    CallGraph [6], DataFlowGraph [7], PackageGraph [8], Confidence
//! - `taint`     TaintSource [9], TaintSink [10]
//! - `path`      ReachabilityPath [11], PathStep, Location
//! - `taxonomy`  AttackTechnique [12], ExecutionPhase, PhaseMap [13]
//! - `rule`      RuleSpec [14], RuleId
//! - `finding`   Finding [15], Evidence [16], Severity, RiskScore, Verdict [17]
//! - `deps`      DependencyGraph, BlastRadius [18]
//! - `cache_key` CacheKey [19], RulesetVersion [20]
//! - `report`    ScanReport [21], AnalysisMode [22]
//! - `config`    ScanOptions, ExtractOptions
//! - `error`     CoreError

pub mod ast;
pub mod cache_key;
pub mod config;
pub mod deps;
pub mod error;
pub mod finding;
pub mod graphs;
pub mod ids;
pub mod package;
pub mod path;
pub mod report;
pub mod rule;
pub mod source;
pub mod symbols;
pub mod taint;
pub mod taxonomy;

pub use ast::{Ast, AstKind, AstNode, Span};
pub use cache_key::{CacheKey, RulesetVersion};
pub use config::{ExtractOptions, ScanOptions};
pub use deps::{BlastRadius, DependencyEdge, DependencyGraph};
pub use error::CoreError;
pub use finding::{
    Evidence, Finding, MALICIOUS_THRESHOLD, RiskScore, SUSPICIOUS_THRESHOLD, Severity, Snippet,
    Verdict,
};
pub use graphs::{
    CallEdge, CallGraph, CallNode, CallNodeKind, Confidence, DataFlowGraph, FlowEdge, FlowEdgeKind,
    FlowNode, FlowNodeKind, PackageGraph,
};
pub use ids::{AstNodeId, FileId, SymbolId};
pub use package::{Distribution, DistributionKind, Package, PackageName, Sha256Digest};
pub use path::{Location, PathStep, PathStepKind, ReachabilityKind, ReachabilityPath};
pub use report::{AnalysisMode, SCHEMA_VERSION, ScanReport, ScanStats, SkipReason};
pub use rule::{RuleId, RuleSpec};
pub use source::{ProjectMeta, SourceFile, SourceKind};
pub use symbols::{ImportAlias, QualifiedName, Symbol, SymbolKind, SymbolTable};
pub use taint::{TaintSink, TaintSinkKind, TaintSource, TaintSourceKind};
pub use taxonomy::{
    AttackTechnique, ExecutionPhase, Objective, PhaseMap, PhaseRoot, PhaseRootKind,
};

#[cfg(test)]
mod tests {
    // WHY: these 27 types are the published domain model, referred to by name in the design
    // documents. Renaming one is a decision, not a refactor, so this test names them all and
    // stops compiling if any disappears. It is a drift guard, not a behaviour test.
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
            type_name::<crate::RuleSpec>(),
            type_name::<crate::Finding>(),
            type_name::<crate::Evidence>(),
            type_name::<crate::Severity>(),
            type_name::<crate::RiskScore>(),
            type_name::<crate::Verdict>(),
            type_name::<crate::DependencyGraph>(),
            type_name::<crate::BlastRadius>(),
            type_name::<crate::CacheKey>(),
            type_name::<crate::RulesetVersion>(),
            type_name::<crate::ScanReport>(),
            type_name::<crate::AnalysisMode>(),
        ];
        assert_eq!(names.len(), 27);
    }
}
