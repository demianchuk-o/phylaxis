//! Errors raised by the domain model itself (construction invariants). Errors of the
//! pipeline stages live in their own crates.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    /// A finding was constructed without a well-formed path (DECISIONS.md, ADR-009).
    #[error("a finding must present a path from a source to a sink: {0}")]
    MalformedPath(&'static str),

    /// A rule identifier that does not match `PHX-[A-Z]{3}-[0-9]{3}`.
    #[error("invalid rule id `{0}`")]
    InvalidRuleId(String),

    /// A sha256 hex string of the wrong length or alphabet.
    #[error("invalid sha256 hex digest `{0}`")]
    InvalidDigest(String),

    /// A package name that cannot be normalised under PyPI rules.
    #[error("invalid package name `{0}`")]
    InvalidPackageName(String),

    /// A cache key byte slice of the wrong length.
    #[error("cache key must be exactly {expected} bytes, got {actual}")]
    InvalidCacheKeyLength { expected: usize, actual: usize },
}
