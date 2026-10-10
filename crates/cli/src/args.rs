//! The clap command surface. Kept in its own module so that the binary, the Python
//! console script and the tests all parse the same definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use phylaxis_core::{AnalysisMode, CacheRetention, Confidence, ScanOptions};

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
    /// Inspect or empty the result cache.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Number of entries, how many are stale, and the ruleset version in use.
    Stats {
        /// Cache file (default: the per-user cache, see `phylaxis scan --help`).
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Delete the cache file.
    Clear {
        /// Cache file (default: the per-user cache).
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

/// The cache flags shared by `scan` and `project` (ADR-032).
#[derive(Debug, Args)]
pub struct CacheArgs {
    /// Result cache file (redb). Default: `phylaxis/cache.redb` in the per-user cache
    /// directory ($XDG_CACHE_HOME or ~/.cache on Linux, ~/Library/Caches on macOS,
    /// %LOCALAPPDATA% on Windows), or $PHYLAXIS_CACHE_DIR when set.
    #[arg(long, conflicts_with = "no_cache")]
    pub cache: Option<PathBuf>,

    /// Do not read or write any cache.
    #[arg(long)]
    pub no_cache: bool,

    /// Drop cached results not used for this many days; 0 keeps them however old.
    #[arg(long, default_value_t = 30)]
    pub cache_max_age_days: u32,

    /// Keep the cache under this many megabytes, dropping the least recently used results.
    #[arg(long)]
    pub cache_max_mb: Option<u64>,
}

impl CacheArgs {
    pub fn path(&self) -> Option<PathBuf> {
        if self.no_cache {
            return None;
        }
        self.cache.clone().or_else(default_cache_path)
    }

    pub fn retention(&self) -> CacheRetention {
        CacheRetention {
            max_age_days: (self.cache_max_age_days > 0).then_some(self.cache_max_age_days),
            max_bytes: self.cache_max_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
        }
    }
}

/// `phylaxis/cache.redb` under the per-user cache directory, or under `$PHYLAXIS_CACHE_DIR`.
/// `None` when no such directory can be named (no home directory); the scan then runs
/// without a cache rather than failing.
///
/// WHY by hand and not a crate: three environment variables, and a new dependency is a
/// recorded decision for a dozen lines.
pub fn default_cache_path() -> Option<PathBuf> {
    let var = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if let Some(dir) = var("PHYLAXIS_CACHE_DIR") {
        return Some(dir.join("cache.redb"));
    } else if cfg!(windows) {
        var("LOCALAPPDATA")?
    } else if cfg!(target_os = "macos") {
        var("HOME")?.join("Library").join("Caches")
    } else {
        var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|h| h.join(".cache")))?
    };
    Some(base.join("phylaxis").join("cache.redb"))
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

    #[command(flatten)]
    pub cache: CacheArgs,
}

impl ScanArgs {
    pub fn options(&self) -> ScanOptions {
        ScanOptions {
            mode: self.mode.into(),
            min_confidence: self.min_confidence.map(Into::into),
            jobs: self.jobs,
            cache_path: self.cache.path(),
            cache_retention: self.cache.retention(),
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

    #[command(flatten)]
    pub cache: CacheArgs,
}

impl ProjectArgs {
    /// Always the full method: ranking is a product feature, not an ablation.
    pub fn options(&self) -> ScanOptions {
        ScanOptions {
            jobs: self.jobs,
            cache_path: self.cache.path(),
            cache_retention: self.cache.retention(),
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
        assert_eq!(o.cache_retention, CacheRetention::default());
    }

    // ADR-032: a cache by default, `--no-cache` turns it off, `--cache` names another file,
    // and the retention flags reach the options.
    #[test]
    fn cache_flags() {
        let opts = |extra: &[&str]| {
            let mut argv = vec!["phylaxis", "scan"];
            argv.extend_from_slice(extra);
            argv.push("x.tar.gz");
            let Command::Scan(args) = Cli::try_parse_from(argv).unwrap().command else {
                panic!("expected scan")
            };
            args.options()
        };
        assert!(opts(&["--no-cache"]).cache_path.is_none());
        assert_eq!(
            opts(&["--cache", "c.redb"]).cache_path,
            Some(PathBuf::from("c.redb"))
        );
        let o = opts(&["--cache-max-age-days", "0", "--cache-max-mb", "2"]);
        assert_eq!(o.cache_retention.max_age_days, None);
        assert_eq!(o.cache_retention.max_bytes, Some(2 * 1024 * 1024));
        assert!(
            Cli::try_parse_from(["phylaxis", "scan", "--cache", "c", "--no-cache", "x"]).is_err()
        );
    }

    #[test]
    fn scan_requires_a_path() {
        assert!(Cli::try_parse_from(["phylaxis", "scan"]).is_err());
    }
}
