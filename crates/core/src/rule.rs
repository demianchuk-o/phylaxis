//! RuleSpec [14] and RuleId: a rule is data, not code.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::finding::Severity;
use crate::path::ReachabilityKind;
use crate::taint::{TaintSinkKind, TaintSourceKind};
use crate::taxonomy::AttackTechnique;

/// `PHX-<GROUP>-<NNN>`; validated on construction (RULES.md, "Identifiers").
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleId(String);

impl RuleId {
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let ok = s.len() == 11
            && s.starts_with("PHX-")
            && s[4..7].bytes().all(|b| b.is_ascii_uppercase())
            && s.as_bytes()[7] == b'-'
            && s[8..11].bytes().all(|b| b.is_ascii_digit());
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(CoreError::InvalidRuleId(s.to_owned()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// [14] One catalogue entry. Static so that the catalogue can be a `const` table with no
/// I/O (RULES.md, invariant 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSpec {
    pub id: &'static str,
    pub title: &'static str,
    pub technique: AttackTechnique,
    pub severity: Severity,
    pub reachability: ReachabilityKind,
    pub sources: &'static [TaintSourceKind],
    pub sinks: &'static [TaintSinkKind],
    /// Directory under `fixtures/` that must yield this rule.
    pub positive_fixture: &'static str,
    /// Directory under `fixtures/` that must not yield a finding at or above `Suspicious`
    /// (or the documented accepted level).
    pub negative_fixture: &'static str,
    /// The false-positive classes RULES.md documents as expected for this rule.
    pub expected_fp: &'static str,
    /// Rules marked `phase2` are in the catalogue but may be implemented after the MVP set.
    pub phase2: bool,
}

impl RuleSpec {
    pub fn rule_id(&self) -> RuleId {
        // The catalogue test asserts every static id parses, so this cannot fail for
        // catalogue entries; the fallback keeps the function total for hand-built specs.
        RuleId::parse(self.id).unwrap_or_else(|_| RuleId(self.id.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_grammar() {
        assert!(RuleId::parse("PHX-EXF-001").is_ok());
        assert!(RuleId::parse("PHX-exf-001").is_err());
        assert!(RuleId::parse("PHX-EXF-1").is_err());
        assert!(RuleId::parse("GDD-EXF-001").is_err());
        assert!(RuleId::parse("").is_err());
    }
}
