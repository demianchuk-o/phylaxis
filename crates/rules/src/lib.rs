//! Source/sink/capability catalogue and the rule engine.
//!
//! A rule is data (`RuleSpec`, RULES.md); the engine is one evaluator that asks the graph
//! crate for paths. Nothing here reads files, configuration or the environment: the
//! catalogue is a static table and the ruleset version is a constant (invariant 6).

pub mod catalogue;
pub mod error;

pub use catalogue::{
    RULES, RULESET_VERSION, RuleSummary, SINK_PATTERNS, SOURCE_PATTERNS, catalogue, find_rule,
    summaries,
};
pub use error::RulesError;
