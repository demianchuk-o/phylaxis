//! CacheKey [19] and RulesetVersion [20] (invariant 6; DECISIONS.md, ADR-017).

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::package::Sha256Digest;

/// Monotonic counter bumped whenever the rule catalogue **or** the report schema changes.
/// The current value is `phylaxis_rules::RULESET_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RulesetVersion(pub u32);

/// `sha256(file) ‖ ruleset_version ‖ schema_version` as 40 bytes.
///
/// WHY this exact layout: the digest is the immutable identity of the file on PyPI, the
/// ruleset version is the identity of the computation, and the schema version is the shape
/// the result was written in. A change to any of them must miss. Big-endian for the versions
/// so that keys sort by digest first, which makes "all versions of one file" a contiguous
/// range scan.
///
/// WHY the schema is in the key (ADR-017, amended 2026-10-10): it used to be covered by a
/// convention — bump the ruleset version when the report shape changes — which a person has
/// to remember. `new` now takes it from `SCHEMA_VERSION` itself, so forgetting is impossible:
/// a reshaped report simply stops matching old rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheKey {
    pub digest: Sha256Digest,
    pub ruleset: RulesetVersion,
    pub schema: u32,
}

impl CacheKey {
    pub const LEN: usize = 40;

    /// A key for the report schema this build writes.
    pub fn new(digest: Sha256Digest, ruleset: RulesetVersion) -> Self {
        Self::with_schema(digest, ruleset, crate::report::SCHEMA_VERSION)
    }

    /// A key for an explicit schema version: for tests, and for reading keys back.
    pub fn with_schema(digest: Sha256Digest, ruleset: RulesetVersion, schema: u32) -> Self {
        Self {
            digest,
            ruleset,
            schema,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..32].copy_from_slice(self.digest.as_bytes());
        out[32..36].copy_from_slice(&self.ruleset.0.to_be_bytes());
        out[36..].copy_from_slice(&self.schema.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != Self::LEN {
            return Err(CoreError::InvalidCacheKeyLength {
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[..32]);
        let word = |at: usize| {
            let mut v = [0u8; 4];
            v.copy_from_slice(&bytes[at..at + 4]);
            u32::from_be_bytes(v)
        };
        Ok(Self {
            digest: Sha256Digest(digest),
            ruleset: RulesetVersion(word(32)),
            schema: word(36),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Invariant 6, byte-exact: same digest + same ruleset = same key.
    #[test]
    fn same_digest_same_ruleset_same_key() {
        let d = Sha256Digest([7u8; 32]);
        assert_eq!(
            CacheKey::new(d, RulesetVersion(1)).to_bytes(),
            CacheKey::new(d, RulesetVersion(1)).to_bytes()
        );
    }

    // Invariant 6: a ruleset bump changes the key, so old entries can never be served.
    #[test]
    fn ruleset_bump_changes_key() {
        let d = Sha256Digest([7u8; 32]);
        assert_ne!(
            CacheKey::new(d, RulesetVersion(1)).to_bytes(),
            CacheKey::new(d, RulesetVersion(2)).to_bytes()
        );
    }

    // ADR-017 layout: 40 bytes, digest first, then both versions big-endian.
    #[test]
    fn layout_is_digest_then_big_endian_versions() {
        let d = Sha256Digest([0xAA; 32]);
        let key = CacheKey::with_schema(d, RulesetVersion(0x0102_0304), 0x0506_0708);
        let bytes = key.to_bytes();
        assert_eq!(bytes.len(), 40);
        assert_eq!(&bytes[..32], &[0xAA; 32]);
        assert_eq!(&bytes[32..36], &[1, 2, 3, 4]);
        assert_eq!(&bytes[36..], &[5, 6, 7, 8]);
        assert_eq!(CacheKey::from_bytes(&bytes).unwrap(), key);
        assert!(CacheKey::from_bytes(&bytes[..36]).is_err());
    }

    // ADR-017 amended: a schema change misses without anyone bumping the ruleset, and `new`
    // always writes the current schema.
    #[test]
    fn schema_change_changes_key() {
        let d = Sha256Digest([7u8; 32]);
        let current = CacheKey::new(d, RulesetVersion(1));
        assert_eq!(current.schema, crate::report::SCHEMA_VERSION);
        assert_ne!(
            current.to_bytes(),
            CacheKey::with_schema(d, RulesetVersion(1), crate::report::SCHEMA_VERSION + 1)
                .to_bytes()
        );
    }
}
