//! Finding [15], Evidence [16], Severity, RiskScore and Verdict [17]
//! (DECISIONS.md, ADR-009 and ADR-010).

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::graphs::Confidence;
use crate::path::{Location, ReachabilityPath};
use crate::rule::RuleId;
use crate::taxonomy::{AttackTechnique, ExecutionPhase};

/// Ordinal severity of a rule. Ordered so that `max` is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// WHY: ADR-010. Fixed before evaluation.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.6,
            Severity::Low => 0.4,
        }
    }
}

/// `risk >= SUSPICIOUS_THRESHOLD` is the primary "flagged" operating point of the
/// evaluation; `>= MALICIOUS_THRESHOLD` is the strict one (EVALUATION.md §4).
pub const SUSPICIOUS_THRESHOLD: f64 = 0.40;
pub const MALICIOUS_THRESHOLD: f64 = 0.70;

/// ADR-010: multiplier applied when the path is marked obfuscated.
pub const OBFUSCATION_BONUS: f64 = 1.15;
/// ADR-010: per-package bonus for each distinct technique beyond the first.
pub const TECHNIQUE_BONUS: f64 = 0.05;

/// A deterministic score in `[0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RiskScore(f64);

impl RiskScore {
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    pub fn value(self) -> f64 {
        self.0
    }

    /// The per-finding formula of ADR-010:
    /// `severity × phase × confidence × obfuscation_bonus`, clamped.
    pub fn for_finding(
        severity: Severity,
        phase: ExecutionPhase,
        confidence: Confidence,
        obfuscated: bool,
        phase_weighting: bool,
    ) -> Self {
        let phase_w = if phase_weighting { phase.weight() } else { 1.0 };
        let bonus = if obfuscated { OBFUSCATION_BONUS } else { 1.0 };
        Self::new(severity.weight() * phase_w * confidence.weight() * bonus)
    }

    /// The per-package aggregate of ADR-010:
    /// `min(1, max_finding_score + 0.05 × (distinct_techniques − 1))`.
    pub fn aggregate(findings: &[Finding]) -> Self {
        let Some(max) = findings
            .iter()
            .map(|f| f.score.0)
            .fold(None, |m: Option<f64>, s| Some(m.map_or(s, |m| m.max(s))))
        else {
            return Self(0.0);
        };
        let mut techniques: Vec<_> = findings.iter().map(|f| f.technique.objective).collect();
        techniques.sort();
        techniques.dedup();
        let extra = techniques.len().saturating_sub(1) as f64;
        Self::new(max + TECHNIQUE_BONUS * extra)
    }
}

/// The package-level verdict derived from the aggregate score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl From<RiskScore> for Verdict {
    fn from(score: RiskScore) -> Self {
        if score.0 >= MALICIOUS_THRESHOLD {
            Verdict::Malicious
        } else if score.0 >= SUSPICIOUS_THRESHOLD {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        }
    }
}

/// The source lines behind one path step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    pub location: Location,
    pub text: String,
}

/// [16] What the auditor sees: the path, the phase it runs in, and the code behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub path: ReachabilityPath,
    pub phase: ExecutionPhase,
    pub snippets: Vec<Snippet>,
}

/// [15] A rule that fired on a path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule: RuleId,
    pub technique: AttackTechnique,
    pub severity: Severity,
    pub phase: ExecutionPhase,
    pub confidence: Confidence,
    pub score: RiskScore,
    pub message: String,
    pub evidence: Evidence,
}

impl Finding {
    /// The only constructor. Refuses evidence whose path is not well-formed (ADR-009), so
    /// that a finding without a source→sink path cannot exist anywhere downstream.
    pub fn new(
        rule: RuleId,
        technique: AttackTechnique,
        severity: Severity,
        evidence: Evidence,
        message: impl Into<String>,
        phase_weighting: bool,
    ) -> Result<Self, CoreError> {
        if evidence.path.steps.is_empty() {
            return Err(CoreError::MalformedPath("empty path"));
        }
        if !evidence.path.is_well_formed() {
            return Err(CoreError::MalformedPath(
                "path must start at a Source and end at a Sink",
            ));
        }
        let phase = evidence.phase;
        let confidence = evidence.path.confidence;
        let score = RiskScore::for_finding(
            severity,
            phase,
            confidence,
            evidence.path.obfuscated,
            phase_weighting,
        );
        Ok(Self {
            rule,
            technique,
            severity,
            phase,
            confidence,
            score,
            message: message.into(),
            evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Span;
    use crate::ids::FileId;
    use crate::path::{PathStep, PathStepKind, ReachabilityKind};
    use crate::taxonomy::Objective;

    fn step(kind: PathStepKind) -> PathStep {
        PathStep {
            kind,
            location: Location {
                file: FileId(0),
                path: "setup.py".into(),
                span: Span::default(),
            },
            symbol: "x".into(),
            detail: None,
        }
    }

    fn path(steps: Vec<PathStep>, confidence: Confidence, obfuscated: bool) -> ReachabilityPath {
        ReachabilityPath {
            kind: ReachabilityKind::Data,
            steps,
            confidence,
            obfuscated,
            conditional: false,
        }
    }

    fn technique() -> AttackTechnique {
        AttackTechnique {
            objective: Objective::Exfiltration,
            typical_phase: ExecutionPhase::Install,
            obfuscation: false,
        }
    }

    fn finding(
        steps: Vec<PathStep>,
        phase: ExecutionPhase,
        confidence: Confidence,
        obfuscated: bool,
    ) -> Result<Finding, CoreError> {
        Finding::new(
            RuleId::parse("PHX-EXF-001").unwrap(),
            technique(),
            Severity::Critical,
            Evidence {
                path: path(steps, confidence, obfuscated),
                phase,
                snippets: vec![],
            },
            "env → network",
            true,
        )
    }

    // ADR-009, the executable form: a finding cannot exist without a path.
    #[test]
    fn finding_refuses_empty_path() {
        let err =
            finding(vec![], ExecutionPhase::Install, Confidence::Resolved, false).unwrap_err();
        assert!(matches!(err, CoreError::MalformedPath(_)));
    }

    #[test]
    fn finding_refuses_path_not_ending_in_sink() {
        let err = finding(
            vec![step(PathStepKind::Source), step(PathStepKind::Transfer)],
            ExecutionPhase::Install,
            Confidence::Resolved,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::MalformedPath(_)));
    }

    // ADR-010 worked example: Critical × Install × Resolved = 1.0 → Malicious.
    #[test]
    fn score_critical_install_resolved_is_malicious() {
        let f = finding(
            vec![step(PathStepKind::Source), step(PathStepKind::Sink)],
            ExecutionPhase::Install,
            Confidence::Resolved,
            false,
        )
        .unwrap();
        assert_eq!(f.score.value(), 1.0);
        assert_eq!(
            Verdict::from(RiskScore::aggregate(std::slice::from_ref(&f))),
            Verdict::Malicious
        );
    }

    // ADR-010: the same path at runtime with an ambiguous edge is 1.0 × 0.5 × 0.6 = 0.30,
    // below the Suspicious threshold. Phase and confidence are what separate a finding
    // worth an auditor's minute from one that is not.
    #[test]
    fn score_runtime_ambiguous_is_clean() {
        let f = finding(
            vec![step(PathStepKind::Source), step(PathStepKind::Sink)],
            ExecutionPhase::Runtime,
            Confidence::Ambiguous,
            false,
        )
        .unwrap();
        assert!((f.score.value() - 0.30).abs() < 1e-9);
        assert_eq!(Verdict::from(f.score), Verdict::Clean);
    }

    // Obfuscation raises, never lowers, and the score is clamped at 1.0.
    #[test]
    fn obfuscation_bonus_is_clamped() {
        let plain = finding(
            vec![step(PathStepKind::Source), step(PathStepKind::Sink)],
            ExecutionPhase::Import,
            Confidence::Resolved,
            false,
        )
        .unwrap();
        let obf = finding(
            vec![step(PathStepKind::Source), step(PathStepKind::Sink)],
            ExecutionPhase::Import,
            Confidence::Resolved,
            true,
        )
        .unwrap();
        assert!(obf.score > plain.score);
        let top = finding(
            vec![step(PathStepKind::Source), step(PathStepKind::Sink)],
            ExecutionPhase::Install,
            Confidence::Resolved,
            true,
        )
        .unwrap();
        assert_eq!(top.score.value(), 1.0);
    }

    // Aggregate: two findings of the same objective add nothing; a second distinct
    // objective adds 0.05.
    #[test]
    fn aggregate_rewards_distinct_techniques_only() {
        let a = finding(
            vec![step(PathStepKind::Source), step(PathStepKind::Sink)],
            ExecutionPhase::Runtime,
            Confidence::Resolved,
            false,
        )
        .unwrap(); // 0.5
        let mut b = a.clone();
        assert!((RiskScore::aggregate(&[a.clone(), b.clone()]).value() - 0.5).abs() < 1e-9);
        b.technique.objective = Objective::Dropper;
        assert!((RiskScore::aggregate(&[a, b]).value() - 0.55).abs() < 1e-9);
        assert_eq!(RiskScore::aggregate(&[]).value(), 0.0);
    }

    // Verdict thresholds are exactly the documented constants.
    #[test]
    fn verdict_thresholds() {
        assert_eq!(Verdict::from(RiskScore::new(0.39)), Verdict::Clean);
        assert_eq!(Verdict::from(RiskScore::new(0.40)), Verdict::Suspicious);
        assert_eq!(Verdict::from(RiskScore::new(0.69)), Verdict::Suspicious);
        assert_eq!(Verdict::from(RiskScore::new(0.70)), Verdict::Malicious);
    }

    // Ablation configuration C (EVALUATION.md §6): phase weighting off makes the phase
    // multiplier 1.0 and nothing else changes.
    #[test]
    fn phase_weighting_can_be_disabled_for_the_ablation() {
        let with = RiskScore::for_finding(
            Severity::High,
            ExecutionPhase::Runtime,
            Confidence::Resolved,
            false,
            true,
        );
        let without = RiskScore::for_finding(
            Severity::High,
            ExecutionPhase::Runtime,
            Confidence::Resolved,
            false,
            false,
        );
        assert!((with.value() - 0.40).abs() < 1e-9);
        assert!((without.value() - 0.80).abs() < 1e-9);
    }
}
