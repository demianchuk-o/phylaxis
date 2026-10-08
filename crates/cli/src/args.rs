//! The clap command surface. Kept in its own module so that the binary, the Python
//! console script and the tests all parse the same definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use phylaxis_core::{AnalysisMode, Confidence, ScanOptions};

use crate::output::Format;

#[derive(Debug, Parser)]
#[command(
    name = "phylaxis",
    version,
    about = "Deterministic static analysis of PyPI packages by source-to-sink reachability."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan one or more sdists (`.tar.gz`) or extracted directories.
    Scan(ScanArgs),
    /// Scan a project's dependency set (a directory of sdists) and rank flagged packages
    /// by their blast radius in it (ADR-027).
    Project(ProjectArgs),
    /// Print the rule catalogue.
    Rules {
        #[arg(long)]
        json: bool,
    },
    /// Inspect the result cache.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Number of entries and the ruleset version in use.
    Stats {
        #[arg(long)]
        path: PathBuf,
    },
}

/// The ablation configurations (EVALUATION.md §6) as a CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ModeArg {
    /// A: file-level co-occurrence (baseline).
    A,
    /// B: definition-level co-occurrence.
    B,
    /// C: reachability without phase weighting.
    C,
    /// D: reachability with phase weighting (the full method, default).
    D,
}

impl From<ModeArg> for AnalysisMode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::A => AnalysisMode::FileCooccurrence,
            ModeArg::B => AnalysisMode::DefinitionCooccurrence,
            ModeArg::C => AnalysisMode::Reachability {
                phase_weighting: false,
            },
            ModeArg::D => AnalysisMode::Reachability {
                phase_weighting: true,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConfidenceArg {
    Dynamic,
    Ambiguous,
    Resolved,
}

impl From<ConfidenceArg> for Confidence {
    fn from(c: ConfidenceArg) -> Self {
        match c {
            ConfidenceArg::Dynamic => Confidence::Dynamic,
            ConfidenceArg::Ambiguous => Confidence::Ambiguous,
            ConfidenceArg::Resolved => Confidence::Resolved,
        }
    }
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Paths to scan: sdist files or directories.
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub format: Format,

    /// Analysis configuration (ablation); D is the full method.
    #[arg(long, value_enum, default_value_t = ModeArg::D)]
    pub mode: ModeArg,

    /// Drop findings below this confidence.
    #[arg(long, value_enum)]
    pub min_confidence: Option<ConfidenceArg>,

    /// Worker threads for batch scanning (default: all cores).
    #[arg(long)]
    pub jobs: Option<usize>,

    /// Path of the result cache (redb file). Omit to disable caching.
    #[arg(long)]
    pub cache: Option<PathBuf>,
}

impl ScanArgs {
    pub fn options(&self) -> ScanOptions {
        ScanOptions {
            mode: self.mode.into(),
            min_confidence: self.min_confidence.map(Into::into),
            jobs: self.jobs,
            cache_path: self.cache.clone(),
            extract: Default::default(),
        }
    }
}

#[derive(Debug, Args)]
pub struct ProjectArgs {
    /// Directory holding the project's dependency set as sdists (`.tar.gz`).
    pub dir: PathBuf,

    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub format: Format,

    /// Worker threads for batch scanning (default: all cores).
    #[arg(long)]
    pub jobs: Option<usize>,

    /// Path of the result cache (redb file). Omit to disable caching.
    #[arg(long)]
    pub cache: Option<PathBuf>,
}

impl ProjectArgs {
    /// Always the full method: ranking is a product feature, not an ablation.
    pub fn options(&self) -> ScanOptions {
        ScanOptions {
            jobs: self.jobs,
            cache_path: self.cache.clone(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_args_map_to_options() {
        let cli = Cli::try_parse_from([
            "phylaxis",
            "scan",
            "--mode",
            "c",
            "--min-confidence",
            "resolved",
            "--jobs",
            "4",
            "x.tar.gz",
        ])
        .unwrap();
        let Command::Scan(args) = cli.command else {
            panic!("expected scan")
        };
        let o = args.options();
        assert_eq!(o.mode.label(), "C");
        assert_eq!(o.min_confidence, Some(Confidence::Resolved));
        assert_eq!(o.jobs, Some(4));
        assert!(o.cache_path.is_none());
    }

    #[test]
    fn scan_requires_a_path() {
        assert!(Cli::try_parse_from(["phylaxis", "scan"]).is_err());
    }
}
