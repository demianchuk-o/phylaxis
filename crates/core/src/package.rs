//! Package [1] and Distribution [2]: the object of analysis.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// A PyPI project name, normalised per the packaging specification: lower-case, with runs
/// of `-`, `_` and `.` collapsed to a single `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageName(String);

impl PackageName {
    /// Normalises `raw` per PyPI rules. Rejects empty names and names with characters
    /// outside `[A-Za-z0-9._-]`.
    pub fn normalize(raw: &str) -> Result<Self, CoreError> {
        // The alphabet is checked on the RAW input, before collapsing. A name is valid
        // per PEP 508 when it is non-empty, drawn from [A-Za-z0-9._-], and starts and ends
        // on an alphanumeric. Checking first means "bad name" is rejected as illegal
        // rather than silently normalised into something that looks legitimate.
        let ok_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
        let starts_ends_alnum = || {
            raw.starts_with(|c: char| c.is_ascii_alphanumeric())
                && raw.ends_with(|c: char| c.is_ascii_alphanumeric())
        };
        if raw.is_empty() || !raw.chars().all(ok_char) || !starts_ends_alnum() {
            return Err(CoreError::InvalidPackageName(raw.to_owned()));
        }

        // PEP 503: lower-case, and collapse every run of `-`, `_` or `.` to a single `-`.
        // `Friendly_Bard.Tool` and `friendly-bard-tool` are the same project, and the
        // dependency graph and the dataset labels must agree on which.
        let mut out = String::with_capacity(raw.len());
        let mut in_run = false;
        for c in raw.chars() {
            if matches!(c, '-' | '_' | '.') {
                if !in_run {
                    out.push('-');
                    in_run = true;
                }
            } else {
                out.push(c.to_ascii_lowercase());
                in_run = false;
            }
        }
        Ok(Self(out))
    }

    /// Wraps an already-normalised name without checking. For callers that obtained the
    /// name from a trusted, already-normalised source (a manifest written by `normalize`,
    /// a test). Anything from user input goes through `normalize`.
    pub fn from_normalized(s: &str) -> Self {
        Self(s.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// [1] A named project on PyPI with its known versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub name: PackageName,
    pub versions: Vec<String>,
}

/// The kind of a distribution file. Only `Sdist` is analysed (invariant 2); the others
/// still exist as dependency-graph nodes via metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributionKind {
    Sdist,
    Wheel,
    Other,
}

/// A SHA-256 digest of a distribution file. Serialised as 64 lower-case hex characters.
///
/// WHY this is the identity of a distribution: PyPI never reassigns a filename, so the
/// bytes behind a digest are immutable for the life of the index (invariant 6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use fmt::Write as _;
            // Writing into a String cannot fail.
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({})", self.to_hex())
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(CoreError::InvalidDigest(s.to_owned()));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex =
                std::str::from_utf8(chunk).map_err(|_| CoreError::InvalidDigest(s.to_owned()))?;
            out[i] =
                u8::from_str_radix(hex, 16).map_err(|_| CoreError::InvalidDigest(s.to_owned()))?;
        }
        Ok(Self(out))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// [2] One published file of one version of a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distribution {
    pub name: PackageName,
    pub version: String,
    pub filename: String,
    pub kind: DistributionKind,
    pub sha256: Sha256Digest,
    pub size_bytes: u64,
}

impl Distribution {
    /// Parses `name` and `version` out of an sdist filename (`{name}-{version}.tar.gz`,
    /// PEP 625). Returns `None` for anything that is not an sdist filename.
    pub fn parse_sdist_filename(filename: &str) -> Option<(String, String)> {
        // Only `.tar.gz` is an sdist for our purposes (invariant 2). A wheel name also
        // contains `-` separated fields, so the extension check must come FIRST --
        // otherwise `requests-2.31.0-py3-none-any.whl` would parse as a version of `any`.
        let stem = filename.strip_suffix(".tar.gz")?;

        // PEP 625 requires the name field to carry `-` as `_`, so the LAST `-` is the
        // name/version boundary. `rsplit_once` gives exactly that split, and returns None
        // when there is no `-` at all, which is not a valid sdist name.
        let (name, version) = stem.rsplit_once('-')?;
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_owned(), version.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A digest must round-trip through hex so that manifests, cache keys and reports all
    // agree on the identity of a file.
    #[test]
    fn sha256_hex_round_trip() {
        let d = Sha256Digest([0xab; 32]);
        let hex = d.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex.parse::<Sha256Digest>().unwrap(), d);
    }

    #[test]
    fn sha256_rejects_wrong_length_and_alphabet() {
        assert!("abcd".parse::<Sha256Digest>().is_err());
        assert!("zz".repeat(32).parse::<Sha256Digest>().is_err());
    }

    // PEP 503: names differing only in case and separators are the same project. This
    // matters for the dependency graph and for matching dataset labels to files.
    #[test]
    fn package_name_normalises_separators_and_case() {
        let a = PackageName::normalize("Friendly_Bard.Tool").unwrap();
        let b = PackageName::normalize("friendly-bard-tool").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "friendly-bard-tool");
    }

    #[test]
    fn package_name_rejects_empty_and_illegal() {
        assert!(PackageName::normalize("").is_err());
        assert!(PackageName::normalize("bad name").is_err());
    }

    #[test]
    fn sdist_filename_splits_name_and_version() {
        let (n, v) = Distribution::parse_sdist_filename("requests-2.31.0.tar.gz").unwrap();
        assert_eq!((n.as_str(), v.as_str()), ("requests", "2.31.0"));
        assert!(Distribution::parse_sdist_filename("requests-2.31.0-py3-none-any.whl").is_none());
    }
}
