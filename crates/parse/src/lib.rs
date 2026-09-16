//! Safe sdist extraction and tree-sitter parsing of Python source.
//!
//! This is the only crate that touches the file system, archives and the parser. It
//! produces `phylaxis_core::SourceFile` and `phylaxis_core::Ast`; nothing downstream
//! knows about tar, gzip or tree-sitter (DECISIONS.md, ADR-014).
//!
//! SAFETY INVARIANT (CLAUDE.md #5): this crate READS. It never runs `setup.py`, never
//! imports a module, never invokes `pip`, never spawns a process. There is no code path
//! for any of that here, and none may ever be added.
//!
//! The crate lands in blocks. Extraction and hashing are here; the tree-sitter lowering
//! (`python`, `pyproject`) arrives with T-04.

pub mod digest;
pub mod error;
pub mod extract;

pub use digest::{sha256_of_bytes, sha256_of_file};
pub use error::ParseError;
pub use extract::{
    EntryKind, ExtractedTree, ManifestEntry, extract_sdist, load_directory, validate_entry,
};
