//! CacheKey [19] and RulesetVersion [20] (invariant 6; DECISIONS.md, ADR-017).

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::package::Sha256Digest;

/// Monotonic counter bumped whenever the rule catalogue **or** the report schema changes.
/// The current value is `phylaxis_rules::RULESET_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RulesetVersion(pub u32);

/// `sha256(file) ‖ ruleset_version` as 36 bytes.
///
/// WHY this exact layout: the digest is the immutable identity of the file on PyPI, and
/// the ruleset version is the identity of the computation. A change to either must miss.
/// Big-endian for the version so that keys sort by digest first, then by version, which
/// makes "all versions of one file" a contiguous range scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheKey {
    pub digest: Sha256Digest,
    pub ruleset: RulesetVersion,
}

impl CacheKey {
    pub const LEN: usize = 36;

    pub fn new(digest: Sha256Digest, ruleset: RulesetVersion) -> Self {
        Self { digest, ruleset }
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..32].copy_from_slice(self.digest.as_bytes());
        out[32..].copy_from_slice(&self.ruleset.0.to_be_bytes());
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
        let mut v = [0u8; 4];
        v.copy_from_slice(&bytes[32..]);
        Ok(Self {
            digest: Sha256Digest(digest),
            ruleset: RulesetVersion(u32::from_be_bytes(v)),
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

    // ADR-017 layout: 36 bytes, digest first, version big-endian last.
    #[test]
    fn layout_is_digest_then_big_endian_version() {
        let d = Sha256Digest([0xAA; 32]);
        let bytes = CacheKey::new(d, RulesetVersion(0x0102_0304)).to_bytes();
        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[..32], &[0xAA; 32]);
        assert_eq!(&bytes[32..], &[1, 2, 3, 4]);
        assert_eq!(
            CacheKey::from_bytes(&bytes).unwrap(),
            CacheKey::new(d, RulesetVersion(0x0102_0304))
        );
        assert!(CacheKey::from_bytes(&bytes[..35]).is_err());
    }
}
