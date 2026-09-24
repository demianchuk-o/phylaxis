//! Scan orchestration: the one pipeline both the CLI and the Python API run
//! (ARCHITECTURE.md stages 1–13; DECISIONS.md, ADR-013).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use phylaxis_cache::{Cache, CacheError};
use phylaxis_core::{
    CacheKey, Distribution, ProjectMeta, SCHEMA_VERSION, ScanOptions, ScanReport, ScanStats,
    SkipReason, SourceKind,
};
use phylaxis_graph::GraphError;
use phylaxis_parse::{ExtractedTree, ParseError};
use phylaxis_rules::{RULESET_VERSION, RulesError};
use rayon::prelude::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("path not found: `{0}`")]
    NotFound(PathBuf),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Rules(#[from] RulesError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// The cache file could not be opened. A string rather than the `CacheError`, because
    /// `scan_many` opens the cache once and must report the failure in every slot.
    #[error("cache `{path}` could not be opened: {reason}")]
    CacheUnavailable { path: PathBuf, reason: String },
}

/// A report plus the two things deliberately kept *out* of the report: timing and cache
/// provenance (the report must stay byte-deterministic, `core::report` docs).
#[derive(Debug)]
pub struct ScanResult {
    pub report: ScanReport,
    pub elapsed: Duration,
    pub from_cache: bool,
}

/// Scans one sdist file or one extracted directory.
///
/// Pipeline: if `path` is a file → sha256 → cache lookup (when `opts.cache_path` is set)
/// → on miss: extract (safe) → parse all (parallel over files) → build package graph →
/// evaluate rules → score → report → cache store. If `path` is a directory → load in
/// place (never deleted, never cached) → the same from "parse all" on.
///
/// Distributions that are not sdists yield `Ok` with `report.skipped = Some(NotAnSdist)`;
/// archives that fail safe extraction yield `Ok` with `skipped = Some(ExtractionFailed)`.
/// Only I/O failures on the input path itself are `Err`. WHY: in a 1 500-package batch
/// every input must produce a row for the coverage table (EVALUATION.md §2).
pub fn scan_one(path: &Path, opts: &ScanOptions) -> Result<ScanResult, ScanError> {
    let cache = open_cache(opts)?;
    scan_with(path, opts, cache.as_ref())
}

/// Scans many inputs in parallel with `rayon`, returning results in input order; each
/// input's failure is its own `Err` and never affects the others. `opts.jobs` sizes a
/// dedicated thread pool for this call; `None` uses the global pool.
///
/// WHY here and not in Python: this is the `rayon` boundary across packages
/// (ARCHITECTURE.md); the Python binding releases the GIL around this call.
pub fn scan_many(paths: &[PathBuf], opts: &ScanOptions) -> Vec<Result<ScanResult, ScanError>> {
    // One cache for the whole batch: redb allows one open handle per file per process, and
    // `Cache` is safe to share across workers.
    let cache = match open_cache(opts) {
        Ok(c) => c,
        Err(e) => {
            let reason = e.to_string();
            let path = opts.cache_path.clone().unwrap_or_default();
            return paths
                .iter()
                .map(|_| {
                    Err(ScanError::CacheUnavailable {
                        path: path.clone(),
                        reason: reason.clone(),
                    })
                })
                .collect();
        }
    };
    let run = || -> Vec<_> {
        // An indexed `par_iter` collects in input order whatever the scheduling was.
        paths
            .par_iter()
            .map(|p| scan_with(p, opts, cache.as_ref()))
            .collect()
    };
    // `install` makes the pool current for everything underneath, including `parse_all`'s
    // own `par_iter`, so `--jobs` bounds the whole scan and not only the outer loop. A
    // pool that fails to build falls back to the global one rather than failing the batch.
    match opts
        .jobs
        .map(|n| rayon::ThreadPoolBuilder::new().num_threads(n).build())
    {
        Some(Ok(pool)) => pool.install(run),
        _ => run(),
    }
}

/// The cache is consulted only for the options its key describes.
///
/// WHY: the key is (sha256, ruleset version) (ADR-017), and says nothing about the analysis
/// mode, the confidence filter or the extraction limits. A report produced under mode A and
/// stored under that key would be served back to a later default scan as if it were mode D.
/// So a non-default scan neither reads nor writes the cache. The ablation runs are one pass
/// per configuration, so they lose nothing by it.
fn cacheable(opts: &ScanOptions) -> bool {
    let d = ScanOptions::default();
    opts.mode == d.mode && opts.min_confidence == d.min_confidence && opts.extract == d.extract
}

fn open_cache(opts: &ScanOptions) -> Result<Option<Cache>, ScanError> {
    match &opts.cache_path {
        Some(p) if cacheable(opts) => {
            Cache::open(p)
                .map(Some)
                .map_err(|e| ScanError::CacheUnavailable {
                    path: p.clone(),
                    reason: e.to_string(),
                })
        }
        _ => Ok(None),
    }
}

fn scan_with(
    path: &Path,
    opts: &ScanOptions,
    cache: Option<&Cache>,
) -> Result<ScanResult, ScanError> {
    let started = Instant::now();
    let done = |report: ScanReport, from_cache: bool| ScanResult {
        report,
        elapsed: started.elapsed(),
        from_cache,
    };

    let meta = std::fs::metadata(path).map_err(|_| ScanError::NotFound(path.to_owned()))?;
    if meta.is_dir() {
        let tree = phylaxis_parse::load_directory(path, &opts.extract)?;
        return Ok(done(
            analyse(path.display().to_string(), tree, opts)?,
            false,
        ));
    }

    // A file. The source is its name, not the path it was given: the same bytes scanned
    // from two places must render the same report, including when it comes from the cache.
    let source = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    if !source.ends_with(".tar.gz") {
        return Ok(done(
            skipped(source, None, opts, SkipReason::NotAnSdist),
            false,
        ));
    }

    // Hash before extracting, so that a hit costs one read of the file and nothing else.
    let key = CacheKey::new(phylaxis_parse::sha256_of_file(path)?, RULESET_VERSION);
    if let Some(c) = cache {
        if let Some(report) = c.get(&key)? {
            return Ok(done(report, true));
        }
    }

    let report = match phylaxis_parse::extract_sdist(path, &opts.extract) {
        Ok(tree) => analyse(source, tree, opts)?,
        Err(e) => match skip_reason(e) {
            Ok(reason) => skipped(source, None, opts, reason),
            Err(e) => return Err(e.into()),
        },
    };
    if let Some(c) = cache {
        // `AlreadyPresent` means a concurrent worker scanned the same bytes first; both
        // reports are identical by determinism, so there is nothing to reconcile.
        c.put(&key, &report)?;
    }
    Ok(done(report, false))
}

/// Which extraction failures are a row in the coverage table and which are an error.
/// Anything the archive's author controls is a row; the machine failing is an error.
fn skip_reason(e: ParseError) -> Result<SkipReason, ParseError> {
    match e {
        ParseError::NotAnSdist { .. } => Ok(SkipReason::NotAnSdist),
        ParseError::TooManyEntries { .. } | ParseError::TooLarge { .. } => Ok(SkipReason::TooLarge),
        ParseError::PathTraversal { .. }
        | ParseError::AbsolutePath { .. }
        | ParseError::LinkEntry { .. }
        | ParseError::UnsupportedEntry { .. }
        | ParseError::Archive(_) => Ok(SkipReason::ExtractionFailed(e.to_string())),
        other => Err(other),
    }
}

fn skipped(
    source: String,
    distribution: Option<Distribution>,
    opts: &ScanOptions,
    reason: SkipReason,
) -> ScanReport {
    ScanReport::skipped(source, distribution, RULESET_VERSION, opts.mode, reason)
}

/// Stages 5–13 on a tree that is already on disk. `tree` is dropped at the end, which
/// removes it if it was extracted into a temporary directory.
fn analyse(
    source: String,
    tree: ExtractedTree,
    opts: &ScanOptions,
) -> Result<ScanReport, ScanError> {
    let distribution = tree.distribution.clone();
    // `pyproject.toml` is read for its metadata, never parsed as Python.
    let python: Vec<_> = tree
        .files
        .iter()
        .filter(|f| f.kind != SourceKind::PyprojectToml)
        .cloned()
        .collect();
    if python.is_empty() {
        return Ok(skipped(
            source,
            distribution,
            opts,
            SkipReason::NoPythonSources,
        ));
    }

    let asts = phylaxis_parse::parse_all(&python)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let meta = project_meta(&tree);
    let pg = phylaxis_graph::build_package_graph(&asts, &meta)?;
    let findings = phylaxis_rules::evaluate(&pg, opts)?;
    let (risk, verdict) = phylaxis_rules::score_package(&findings);

    let stats = ScanStats {
        files: tree.files.len() as u32,
        ast_nodes: asts.iter().map(|a| a.nodes.len() as u64).sum(),
        parse_errors: asts.iter().map(|a| a.error_count).sum(),
        symbols: pg.symbols.symbols.len() as u32,
        call_nodes: pg.call_graph.graph.node_count() as u32,
        call_edges: pg.call_graph.graph.edge_count() as u32,
        flow_nodes: pg.dfg.graph.node_count() as u32,
        flow_edges: pg.dfg.graph.edge_count() as u32,
        phase_roots: pg.phases.roots.len() as u32,
    };
    Ok(ScanReport {
        schema_version: SCHEMA_VERSION,
        ruleset_version: RULESET_VERSION,
        mode: opts.mode,
        distribution,
        source,
        skipped: None,
        findings,
        risk,
        verdict,
        stats,
    })
}

/// `ProjectMeta` from the tree: the build backend from a root `pyproject.toml`, the
/// top-level modules from the file list (ADR-021). An unreadable `pyproject.toml` is not a
/// failure; the scan proceeds without backend metadata, which only removes a phase root.
fn project_meta(tree: &ExtractedTree) -> ProjectMeta {
    let mut meta = tree
        .files
        .iter()
        .find(|f| f.rel_path == "pyproject.toml")
        .and_then(|f| phylaxis_parse::parse_pyproject(f).ok())
        .unwrap_or_default();
    meta.top_level_modules =
        phylaxis_parse::discover_top_level_modules(tree.files.iter().map(|f| f.rel_path.as_str()));
    meta
}
