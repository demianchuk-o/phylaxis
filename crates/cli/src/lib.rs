//! Command line orchestration, exposed as a library.
//!
//! WHY a library and not just `main.rs`: the tool ships two ways, as a native binary and
//! as a Python wheel whose console script calls in through PyO3. Both entry points must
//! run the *same* code path, so the real work lives here and `main.rs` is a thin wrapper.
//! `scan::scan_one` / `scan::scan_many` are likewise the only two functions the Python
//! API calls (DECISIONS.md, ADR-013).

pub mod args;
pub mod output;
pub mod scan;

pub use args::{Cli, Command, ScanArgs};
pub use output::Format;
pub use scan::{ScanError, ScanResult, scan_many, scan_one};

use clap::Parser;

/// Process exit codes. `FLAGGED` is what makes the tool usable as a CI gate.
pub mod exit {
    pub const CLEAN: i32 = 0;
    /// At least one scanned distribution reached `Verdict::Suspicious` or above.
    pub const FLAGGED: i32 = 1;
    pub const USAGE: i32 = 2;
    /// A scan could not be completed (I/O, corrupt archive). Findings of other inputs in
    /// the same batch are still printed.
    pub const ERROR: i32 = 3;
}

/// Runs the CLI over `argv` (including argv[0]) and returns a process exit code.
///
/// Returns an exit code rather than calling `std::process::exit`, because the Python
/// binding must be able to return control to the interpreter.
pub fn run(argv: Vec<String>) -> i32 {
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(e) => {
            // `--help` and `--version` arrive here as "errors" with exit code 0.
            let code = e.exit_code();
            let _ = e.print();
            return if code == 0 { exit::CLEAN } else { exit::USAGE };
        }
    };
    dispatch(cli)
}

/// Executes a parsed command. Split from `run` so tests can drive it without argv.
pub fn dispatch(cli: Cli) -> i32 {
    match cli.command {
        Command::Scan(args) => scan_command(&args),
        Command::Rules { json } => {
            if json {
                println!("{}", rules_json());
            } else {
                for r in phylaxis_rules::RULES {
                    println!("{:<12} {:<9} {}", r.id, output::name(&r.severity), r.title);
                }
            }
            exit::CLEAN
        }
        Command::Cache {
            command: args::CacheCommand::Stats { path },
        } => cache_stats(&path),
    }
}

/// Reports go to stdout, one per input in input order: one JSON document per line for
/// `json` (JSON Lines, so a batch pipes straight into `jq` or a harness), blank-line
/// separated blocks for `text`. Failures go to stderr and never stop the batch.
///
/// Exit code: `ERROR` if any input failed, else `FLAGGED` if any report is flagged, else
/// `CLEAN`. WHY error first: with one input unscanned the batch has no complete answer, and
/// a CI gate must not read "the rest were fine" as "clean". Both are non-zero, so a gate
/// fails either way; the distinction is for whoever reads the log.
fn scan_command(args: &ScanArgs) -> i32 {
    let opts = args.options();
    let mut failed = false;
    let mut flagged = false;
    for (path, result) in args.paths.iter().zip(scan_many(&args.paths, &opts)) {
        let report = match result {
            Ok(r) => r.report,
            Err(e) => {
                eprintln!("phylaxis: {}: {e}", path.display());
                failed = true;
                continue;
            }
        };
        match output::render(&report, args.format) {
            // Text already ends in a newline, so `println!` leaves the blank separator line.
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("phylaxis: {}: {e}", path.display());
                failed = true;
                continue;
            }
        }
        flagged |= report.is_flagged();
    }
    if failed {
        exit::ERROR
    } else if flagged {
        exit::FLAGGED
    } else {
        exit::CLEAN
    }
}

/// `cache stats` inspects an existing cache and never creates one: `Cache::open` would
/// create a missing file, and a read-only command that leaves a file behind is a surprise.
fn cache_stats(path: &std::path::Path) -> i32 {
    if !path.is_file() {
        eprintln!("phylaxis: no cache at `{}`", path.display());
        return exit::ERROR;
    }
    match phylaxis_cache::Cache::open(path).and_then(|c| c.stats()) {
        Ok(s) => {
            println!(
                "{}: {} entries, ruleset version {}",
                path.display(),
                s.entries,
                ruleset_version()
            );
            exit::CLEAN
        }
        Err(e) => {
            eprintln!("phylaxis: {}: {e}", path.display());
            exit::ERROR
        }
    }
}

/// The rule catalogue as JSON, for `phylaxis rules --json` and `phylaxis.rules()`.
pub fn rules_json() -> String {
    // Serialising a static table of plain data cannot fail.
    serde_json::to_string(&phylaxis_rules::summaries()).unwrap_or_else(|_| "[]".to_owned())
}

/// The current ruleset version, for `phylaxis.ruleset_version()`.
pub fn ruleset_version() -> u32 {
    phylaxis_rules::RULESET_VERSION.0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both entry points must survive `--help` without touching the scanner.
    #[test]
    fn help_exits_clean() {
        assert_eq!(run(vec!["phylaxis".into(), "--help".into()]), exit::CLEAN);
        assert_eq!(
            run(vec!["phylaxis".into(), "--version".into()]),
            exit::CLEAN
        );
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        assert_eq!(
            run(vec!["phylaxis".into(), "frobnicate".into()]),
            exit::USAGE
        );
        assert_eq!(run(vec!["phylaxis".into()]), exit::USAGE);
    }

    #[test]
    fn rules_json_lists_the_catalogue() {
        let v: serde_json::Value = serde_json::from_str(&rules_json()).unwrap();
        assert_eq!(v.as_array().map(Vec::len), Some(15));
        assert!(ruleset_version() >= 1);
    }
}
