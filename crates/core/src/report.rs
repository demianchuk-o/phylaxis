//! ScanReport [21] and AnalysisMode [22]: the one output schema shared by the CLI, the
//! cache and the Python API (DECISIONS.md, ADR-013, ADR-017).
//!
//! DETERMINISM: nothing in this struct may depend on the clock, the machine, or the
//! cache state. Two scans of the same bytes under the same ruleset must serialise to
//! identical JSON (the `scan_is_byte_deterministic` end-to-end contract). Timing lives
//! outside the report, in the CLI.

use serde::{Deserialize, Serialize};

use crate::cache_key::RulesetVersion;
use crate::finding::{Finding, RiskScore, Verdict};
use crate::package::Distribution;

/// Bumped on any change to the JSON shape. Folded into the cache key via the ruleset
/// version convention (ADR-017), emitted here for consumers.
pub const SCHEMA_VERSION: u32 = 1;

/// The decision predicate in use (EVALUATION.md §6). Only the ablation harness changes
/// it; the default is the full method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum AnalysisMode {
    /// Configuration A: a source kind and a sink kind of the rule occur in the same file.
    FileCooccurrence,
    /// Configuration B: both occur inside the same callable definition.
    DefinitionCooccurrence,
    /// Configurations C (`phase_weighting: false`) and D (`true`): a path must exist.
    Reachability { phase_weighting: bool },
}

impl Default for AnalysisMode {
    fn default() -> Self {
        AnalysisMode::Reachability {
            phase_weighting: true,
        }
    }
}

impl AnalysisMode {
    pub fn phase_weighting(self) -> bool {
        match self {
            AnalysisMode::Reachability { phase_weighting } => phase_weighting,
            // Co-occurrence configurations keep phase weighting so that the ablation
            // isolates the predicate, not the weighting (EVALUATION.md §6).
            _ => true,
        }
    }

    /// Short label for tables and CLI flags: `A`, `B`, `C`, `D`.
    pub fn label(self) -> &'static str {
        match self {
            AnalysisMode::FileCooccurrence => "A",
            AnalysisMode::DefinitionCooccurrence => "B",
            AnalysisMode::Reachability {
                phase_weighting: false,
            } => "C",
            AnalysisMode::Reachability {
                phase_weighting: true,
            } => "D",
        }
    }
}

/// Why a distribution produced no analysis. Never silent: the coverage table of the
/// evaluation (RESULTS.md R0) is built from these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason", content = "detail")]
pub enum SkipReason {
    /// A wheel or other non-sdist file (invariant 2).
    NotAnSdist,
    /// Exceeded `ExtractOptions` limits.
    TooLarge,
    /// The archive could not be safely extracted (path traversal, corruption).
    ExtractionFailed(String),
    /// Extraction succeeded but there was nothing to parse.
    NoPythonSources,
}

/// Deterministic counters about the scan. No timing here (see module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub files: u32,
    pub ast_nodes: u64,
    pub parse_errors: u32,
    pub symbols: u32,
    pub call_nodes: u32,
    pub call_edges: u32,
    pub flow_nodes: u32,
    pub flow_edges: u32,
    pub phase_roots: u32,
}

/// [21] The complete result for one distribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub ruleset_version: RulesetVersion,
    pub mode: AnalysisMode,
    /// `None` when a directory (not an sdist) was scanned; such reports are never cached.
    pub distribution: Option<Distribution>,
    /// What was scanned, as given (file name or directory path), for human output.
    pub source: String,
    pub skipped: Option<SkipReason>,
    pub findings: Vec<Finding>,
    pub risk: RiskScore,
    pub verdict: Verdict,
    pub stats: ScanStats,
}

impl ScanReport {
    /// A report for a distribution that was not analysed. Risk 0, verdict Clean, and the
    /// reason recorded; the evaluation counts these separately from true negatives.
    pub fn skipped(
        source: impl Into<String>,
        distribution: Option<Distribution>,
        ruleset: RulesetVersion,
        mode: AnalysisMode,
        reason: SkipReason,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ruleset_version: ruleset,
            mode,
            distribution,
            source: source.into(),
            skipped: Some(reason),
            findings: Vec::new(),
            risk: RiskScore::new(0.0),
            verdict: Verdict::Clean,
            stats: ScanStats::default(),
        }
    }

    /// `true` at the primary operating point of the evaluation (EVALUATION.md §4).
    pub fn is_flagged(&self) -> bool {
        self.verdict >= Verdict::Suspicious
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ADR-013: the same JSON shape crosses the CLI, the cache and the Python boundary, so
    // it must round-trip losslessly.
    #[test]
    fn skipped_report_round_trips_through_json() {
        let r = ScanReport::skipped(
            "foo-1.0-py3-none-any.whl",
            None,
            RulesetVersion(1),
            AnalysisMode::default(),
            SkipReason::NotAnSdist,
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        assert!(!back.is_flagged());
        assert!(json.contains("\"schema_version\":1"));
    }

    #[test]
    fn analysis_mode_labels_match_the_evaluation_protocol() {
        assert_eq!(AnalysisMode::FileCooccurrence.label(), "A");
        assert_eq!(AnalysisMode::DefinitionCooccurrence.label(), "B");
        assert_eq!(
            AnalysisMode::Reachability {
                phase_weighting: false
            }
            .label(),
            "C"
        );
        assert_eq!(AnalysisMode::default().label(), "D");
        assert!(
            !AnalysisMode::Reachability {
                phase_weighting: false
            }
            .phase_weighting()
        );
    }
}
