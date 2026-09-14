//! Domain types, attack taxonomy and shared configuration.
//!
//! This crate is the domain model: one definition per concept, shared by every other crate,
//! so that "call graph" or "finding" means exactly one thing across the workspace. It has no
//! I/O and depends only on `serde`, `thiserror` and `petgraph` (DECISIONS.md, ADR-015).
//!
//! The model lands in blocks, and this module list grows with them. Landed so far — identity
//! and inputs: what a package, a distribution and a source file *are*. The bracketed numbers
//! are stable entity ids used when the model is written up outside the code.
//! - `ids`       FileId, AstNodeId, SymbolId — the arena indices every table is addressed by
//! - `package`   Package [1], Distribution [2], Sha256Digest
//! - `source`    SourceFile [3], ProjectMeta
//! - `error`     CoreError

pub mod error;
pub mod ids;
pub mod package;
pub mod source;

pub use error::CoreError;
pub use ids::{AstNodeId, FileId, SymbolId};
pub use package::{Distribution, DistributionKind, Package, PackageName, Sha256Digest};
pub use source::{ProjectMeta, SourceFile, SourceKind};

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
        ];
        assert_eq!(names.len(), 3);
    }
}
