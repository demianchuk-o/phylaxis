//! Safe sdist extraction and tree-sitter parsing of Python source.
//!
//! This is the only crate that touches the file system, archives and the parser. It
//! produces `phylaxis_core::SourceFile` and `phylaxis_core::Ast`; nothing downstream
//! knows about tar, gzip or tree-sitter (DECISIONS.md, ADR-014).
//!
//! SAFETY INVARIANT (CLAUDE.md #5): this crate READS. It never runs `setup.py`, never
//! imports a module, never invokes `pip`, never spawns a process. There is no code path
//! for any of that here, and none may ever be added.

pub mod digest;
pub mod error;
pub mod extract;
pub mod layout;
pub mod pyproject;
pub mod python;

pub use digest::{sha256_of_bytes, sha256_of_file};
pub use error::ParseError;
pub use extract::{
    EntryKind, ExtractedTree, ManifestEntry, extract_sdist, load_directory, validate_entry,
};
pub use layout::discover_top_level_modules;
pub use pyproject::parse_pyproject;
pub use python::{parse_all, parse_python};
