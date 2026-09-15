//! ReachabilityPath [11], PathStep and Location: the shape of evidence
//! (DECISIONS.md, ADR-009).

use serde::{Deserialize, Serialize};

use crate::ast::Span;
use crate::graphs::Confidence;
use crate::ids::FileId;

/// A position in the distribution, with the file path carried along so that evidence
/// renders without a symbol table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub file: FileId,
    pub path: String,
    pub span: Span,
}

/// Which graph the path was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityKind {
    /// A path in the data-flow graph from a source's result to a sink's argument.
    Data,
    /// A path in the call graph from a phase root to the definition containing a sink.
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStepKind {
    Source,
    Transfer,
    Transform,
    Call,
    Return,
    Sink,
}

/// One step of a path, renderable on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathStep {
    pub kind: PathStepKind,
    pub location: Location,
    /// The symbol or callee at this step, as the auditor should read it.
    pub symbol: String,
    /// Optional detail: the transform name, the pattern that matched, the phase root kind.
    pub detail: Option<String>,
}

/// [11] An ordered path from a source to a sink. Well-formedness (non-empty, starts with
/// `Source`, ends with `Sink`) is enforced by `Finding::new`, never assumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityPath {
    pub kind: ReachabilityKind,
    pub steps: Vec<PathStep>,
    /// Minimum confidence over the edges traversed.
    pub confidence: Confidence,
    /// At least one `Transform` step was an encoder/encryptor (ADR-006).
    pub obfuscated: bool,
    /// The sink is guarded by a condition on OS, hostname, environment or time (ADR-008).
    pub conditional: bool,
}

impl ReachabilityPath {
    /// The three structural requirements of ADR-009, as one predicate.
    pub fn is_well_formed(&self) -> bool {
        matches!(
            self.steps.first().map(|s| s.kind),
            Some(PathStepKind::Source)
        ) && matches!(self.steps.last().map(|s| s.kind), Some(PathStepKind::Sink))
    }

    pub fn source(&self) -> Option<&PathStep> {
        self.steps.first()
    }

    pub fn sink(&self) -> Option<&PathStep> {
        self.steps.last()
    }

    /// Number of transform steps: an auditor-readability attribute reported in evidence.
    pub fn transform_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.kind == PathStepKind::Transform)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn loc() -> Location {
        Location {
            file: FileId(0),
            path: "pkg/a.py".into(),
            span: Span::default(),
        }
    }

    pub(crate) fn step(kind: PathStepKind) -> PathStep {
        PathStep {
            kind,
            location: loc(),
            symbol: "x".into(),
            detail: None,
        }
    }

    // ADR-009: a path is a path only if it starts at a source and ends at a sink.
    #[test]
    fn well_formedness_requires_source_first_and_sink_last() {
        let ok = ReachabilityPath {
            kind: ReachabilityKind::Data,
            steps: vec![
                step(PathStepKind::Source),
                step(PathStepKind::Transfer),
                step(PathStepKind::Sink),
            ],
            confidence: Confidence::Resolved,
            obfuscated: false,
            conditional: false,
        };
        assert!(ok.is_well_formed());

        let empty = ReachabilityPath {
            steps: vec![],
            ..ok.clone()
        };
        assert!(!empty.is_well_formed());

        let no_sink = ReachabilityPath {
            steps: vec![step(PathStepKind::Source)],
            ..ok.clone()
        };
        assert!(!no_sink.is_well_formed());

        let reversed = ReachabilityPath {
            steps: vec![step(PathStepKind::Sink), step(PathStepKind::Source)],
            ..ok
        };
        assert!(!reversed.is_well_formed());
    }

    // A one-step path is impossible: a single step cannot be both Source and Sink. The
    // shortest legal path has two steps (SuspiciousLiteral straight into a sink).
    #[test]
    fn two_step_path_is_the_minimum() {
        let two = ReachabilityPath {
            kind: ReachabilityKind::Data,
            steps: vec![step(PathStepKind::Source), step(PathStepKind::Sink)],
            confidence: Confidence::Resolved,
            obfuscated: false,
            conditional: false,
        };
        assert!(two.is_well_formed());
        assert_eq!(two.transform_count(), 0);
    }
}
