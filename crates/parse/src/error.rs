//! Errors of extraction and parsing. Every rejection an untrusted archive can trigger is
//! its own variant so that the coverage table (RESULTS.md R0) can count them.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    /// An entry whose path would escape the extraction root (`..` component).
    #[error("archive entry `{entry}` escapes the extraction root (path traversal)")]
    PathTraversal { entry: String },

    /// An entry with an absolute path.
    #[error("archive entry `{entry}` has an absolute path")]
    AbsolutePath { entry: String },

    /// A symlink or hardlink entry. Rejected outright: a link can point anywhere.
    #[error("archive entry `{entry}` is a link ({kind}); links are not extracted")]
    LinkEntry { entry: String, kind: &'static str },

    /// A device, FIFO or other special entry.
    #[error("archive entry `{entry}` has unsupported type {kind}")]
    UnsupportedEntry { entry: String, kind: String },

    #[error("archive has more than {limit} entries")]
    TooManyEntries { limit: u32 },

    #[error("archive exceeds {limit} bytes ({what})")]
    TooLarge { limit: u64, what: &'static str },

    /// The file is not a gzip-compressed tar archive with a single top-level directory.
    #[error("`{path}` is not an sdist: {reason}")]
    NotAnSdist { path: PathBuf, reason: String },

    #[error("archive is corrupt: {0}")]
    Archive(String),

    #[error("I/O error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// tree-sitter could not be initialised with the Python grammar. Not a per-file
    /// error: per-file syntax errors are `Error` nodes in the AST, never a failure.
    #[error("parser initialisation failed: {0}")]
    Grammar(String),

    /// `pyproject.toml` present but unreadable as TOML. Non-fatal for the scan: the
    /// caller records it and proceeds without build-backend metadata.
    #[error("pyproject.toml could not be parsed: {0}")]
    Pyproject(String),
}
