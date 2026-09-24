//! Errors of rule evaluation.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error(transparent)]
    Graph(#[from] phylaxis_graph::GraphError),

    #[error(transparent)]
    Core(#[from] phylaxis_core::CoreError),

    #[error("unknown rule id `{0}`")]
    UnknownRule(String),
}
