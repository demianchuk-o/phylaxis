//! `phylaxis project`: scan a project's resolved dependency set and rank what is flagged by
//! its blast radius in that set (T-17, ADR-027).
//!
//! The input is a directory of sdists — the packages a project installs. phylaxis does not
//! resolve dependencies itself: resolving means running pip, and a `setup.py` project's
//! requirements are only knowable by executing it. Each sdist's dependencies are read from
//! its `PKG-INFO`, in memory, after the same archive validation as extraction
//! (`parse::read_sdist_metadata`). A package without `PKG-INFO` is a node with unknown
//! dependencies and is listed as such, never treated as having none.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use phylaxis_core::{
    BlastRadius, DependencyGraph, Distribution, PackageName, ScanOptions, ScanReport, Verdict,
};
use serde::Serialize;

use crate::scan::scan_many;

/// One package of the set and what the scan said about it.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectPackage {
    pub file: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub verdict: Option<Verdict>,
    pub risk: Option<f64>,
    /// `false` when the sdist has no `PKG-INFO`: its edges are missing from the graph.
    pub dependencies_known: bool,
    /// Why the package has no verdict: a scan error or a refused archive.
    pub problem: Option<String>,
}

/// A flagged package with its place in the project's dependency tree.
#[derive(Debug, Clone, Serialize)]
pub struct RankedFinding {
    pub file: String,
    pub name: String,
    pub version: Option<String>,
    pub verdict: Verdict,
    pub risk: f64,
    pub blast_radius: BlastRadius,
}

/// The whole result. `ranked` is ordered by transitive dependents, then risk, then name.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectReport {
    pub packages: Vec<ProjectPackage>,
    pub dependency_edges: usize,
    pub ranked: Vec<RankedFinding>,
}

/// The sdists directly inside `dir`, in name order.
pub fn sdists_in(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.to_string_lossy().ends_with(".tar.gz"))
        .collect();
    out.sort();
    Ok(out)
}

/// Scans `paths` with `opts` and ranks the flagged ones by blast radius.
pub fn project_report(paths: &[PathBuf], opts: &ScanOptions) -> ProjectReport {
    let results = scan_many(paths, opts);
    let mut packages = Vec::with_capacity(paths.len());
    let mut reports: Vec<Option<ScanReport>> = Vec::with_capacity(paths.len());
    let mut requirements: BTreeMap<PackageName, Vec<String>> = BTreeMap::new();
    let mut names: Vec<Option<PackageName>> = Vec::with_capacity(paths.len());

    for (path, result) in paths.iter().zip(results) {
        let file = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let meta = phylaxis_parse::read_sdist_metadata(path, &opts.extract).unwrap_or_default();
        let from_file = Distribution::parse_sdist_filename(&file);
        let raw_name = meta
            .name
            .clone()
            .or_else(|| from_file.as_ref().map(|(n, _)| n.clone()));
        let version = meta
            .version
            .clone()
            .or_else(|| from_file.as_ref().map(|(_, v)| v.clone()));
        let name = raw_name
            .as_deref()
            .and_then(|n| PackageName::normalize(n).ok());
        // Two files of one project: the first in name order speaks for it.
        if let Some(n) = &name {
            requirements
                .entry(n.clone())
                .or_insert_with(|| meta.requires_dist.clone());
        }
        let (report, problem) = match result {
            Ok(r) => {
                let problem = r
                    .report
                    .skipped
                    .as_ref()
                    .map(|s| crate::output::skip_text(s).to_string());
                (Some(r.report), problem)
            }
            Err(e) => (None, Some(e.to_string())),
        };
        packages.push(ProjectPackage {
            file,
            name: raw_name,
            version,
            verdict: report.as_ref().map(|r| r.verdict),
            risk: report.as_ref().map(|r| r.risk.value()),
            dependencies_known: meta.has_pkg_info,
            problem,
        });
        reports.push(report);
        names.push(name);
    }

    let graph = DependencyGraph::from_requirements(&requirements);
    let betweenness = graph.betweenness();
    let mut ranked: Vec<RankedFinding> = packages
        .iter()
        .zip(&reports)
        .zip(&names)
        .filter_map(|((p, r), n)| {
            let r = r.as_ref().filter(|r| r.is_flagged())?;
            let n = n.as_ref()?;
            Some(RankedFinding {
                file: p.file.clone(),
                name: n.as_str().to_owned(),
                version: p.version.clone(),
                verdict: r.verdict,
                risk: r.risk.value(),
                blast_radius: graph.blast_radius(n, betweenness.as_deref())?,
            })
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.blast_radius
            .transitive_dependents
            .cmp(&a.blast_radius.transitive_dependents)
            .then(b.risk.total_cmp(&a.risk))
            .then(a.name.cmp(&b.name))
    });

    ProjectReport {
        packages,
        dependency_edges: graph.graph.edge_count(),
        ranked,
    }
}

/// A plain-text rendering: the ranked findings, then the packages whose dependencies are
/// unknown or that were not scanned.
pub fn render_text(r: &ProjectReport) -> String {
    let mut s = format!(
        "{} packages, {} dependency edges, {} flagged\n",
        r.packages.len(),
        r.dependency_edges,
        r.ranked.len()
    );
    for f in &r.ranked {
        s.push_str(&format!(
            "  {:<32} {:<10} risk {:.2}  dependents {} ({:.0}%), direct {}, betweenness {}\n",
            format!("{} {}", f.name, f.version.as_deref().unwrap_or("")),
            format!("{:?}", f.verdict).to_lowercase(),
            f.risk,
            f.blast_radius.transitive_dependents,
            f.blast_radius.share * 100.0,
            f.blast_radius.direct_dependents,
            f.blast_radius
                .betweenness
                .map(|b| format!("{b:.3}"))
                .unwrap_or_else(|| "n/a".into()),
        ));
    }
    for p in r
        .packages
        .iter()
        .filter(|p| !p.dependencies_known || p.problem.is_some())
    {
        let why = p
            .problem
            .clone()
            .unwrap_or_else(|| "no PKG-INFO: dependencies unknown".into());
        s.push_str(&format!("  note: {}: {why}\n", p.file));
    }
    s
}
