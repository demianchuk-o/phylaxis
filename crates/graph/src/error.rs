//! Errors of graph construction. Malformed input is tolerated wherever possible (an
//! `Error` AST node is data, not a failure); these are for invariant violations and
//! resource limits.

use phylaxis_core::{FileId, SymbolId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("no AST for file {0:?}")]
    UnknownFile(FileId),

    #[error("symbol {0:?} is not in the table")]
    UnknownSymbol(SymbolId),

    /// The AST violates a lowering postcondition (e.g. a `Call` without a `function`
    /// field). Indicates a parser bug, not a bad package.
    #[error("malformed AST in file {file:?}: {reason}")]
    MalformedAst { file: FileId, reason: String },

    /// A construction limit was hit (node count, path depth, fold size). The scan
    /// continues with what was built; the limit is recorded in stats.
    #[error("limit exceeded: {what} > {limit}")]
    Limit { what: &'static str, limit: usize },
}
