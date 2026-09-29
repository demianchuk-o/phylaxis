//! Python bindings for phylaxis.
//!
//! Deliberately thin: this crate only marshals between Python and the Rust entry points
//! in `phylaxis_cli`. No analysis logic belongs here, ever (DECISIONS.md, ADR-013): the
//! CLI and the Python API must not be able to drift.
//!
//! Data crosses the boundary as JSON strings; the Python shim (`python/phylaxis/__init__.py`)
//! parses them. WHY: one schema for every consumer and no extra dependency.

use std::path::{Path, PathBuf};

use phylaxis_core::ScanOptions;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// The package version, taken from Cargo at compile time so that the Rust crate and the
/// wheel can never disagree about it.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Entry point behind the `phylaxis` console script.
///
/// Takes argv from Python rather than reading `std::env::args`, so that the interpreter
/// stays the owner of process state.
#[pyfunction]
fn cli_main(argv: Vec<String>) -> i32 {
    phylaxis_cli::run(argv)
}

/// `scan_json(path, options_json) -> str`: the `ScanReport` of one sdist or directory as
/// JSON. `options_json` is a JSON object with any subset of `ScanOptions` fields (`{}` for
/// defaults). Raises `ValueError` for malformed options and `RuntimeError` for a scan
/// that cannot run at all (a missing path); out-of-scope inputs are reports with
/// `skipped`, not exceptions.
#[pyfunction]
fn scan_json(py: Python<'_>, path: String, options_json: String) -> PyResult<String> {
    let opts = parse_options(&options_json)?;
    // A single scan can take seconds on a large sdist; other Python threads keep running.
    let result = py.detach(|| phylaxis_cli::scan_one(Path::new(&path), &opts));
    let report = result
        .map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?
        .report;
    phylaxis_cli::output::to_json(&report).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// `scan_many_json(paths, options_json) -> str`: a JSON array, one element per input in
/// input order; each element is either a report object or `{"error": "<message>"}`.
///
/// Releases the GIL for the whole batch (`Python::detach`) so that `rayon` inside
/// `scan_many` gets every core and the calling interpreter stays responsive.
#[pyfunction]
fn scan_many_json(py: Python<'_>, paths: Vec<String>, options_json: String) -> PyResult<String> {
    let opts = parse_options(&options_json)?;
    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    // WHY `detach`: while a thread holds the GIL, no other Python thread runs. `scan_many`
    // is pure Rust on rayon's worker threads and needs nothing from the interpreter, so the
    // GIL is handed back for its whole duration. What must not happen inside the closure is
    // touching any Python object: the closure captures only owned Rust values (`paths`,
    // `opts`), and pyo3 checks that at compile time — a `Py<…>` or `Bound<…>` captured here
    // would not compile.
    let results = py.detach(|| phylaxis_cli::scan_many(&paths, &opts));
    // Each element is already a JSON document, so the array is assembled from the strings
    // rather than parsed and serialised a second time.
    let elements: Vec<String> = results
        .into_iter()
        .map(|r| {
            let rendered = r
                .map_err(|e| e.to_string())
                .and_then(|r| phylaxis_cli::output::to_json(&r.report).map_err(|e| e.to_string()));
            rendered.unwrap_or_else(|message| serde_json::json!({ "error": message }).to_string())
        })
        .collect();
    Ok(format!("[{}]", elements.join(",")))
}

/// `ScanOptions` from the shim's JSON. A malformed or mistyped option is the caller's
/// mistake, hence `ValueError`.
fn parse_options(options_json: &str) -> PyResult<ScanOptions> {
    serde_json::from_str(options_json)
        .map_err(|e| PyValueError::new_err(format!("invalid scan options: {e}")))
}

/// `rules_json() -> str`: the catalogue summaries as a JSON array.
#[pyfunction]
fn rules_json() -> String {
    phylaxis_cli::rules_json()
}

/// `ruleset_version() -> int`.
#[pyfunction]
fn ruleset_version() -> u32 {
    phylaxis_cli::ruleset_version()
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(cli_main, m)?)?;
    m.add_function(wrap_pyfunction!(scan_json, m)?)?;
    m.add_function(wrap_pyfunction!(scan_many_json, m)?)?;
    m.add_function(wrap_pyfunction!(rules_json, m)?)?;
    m.add_function(wrap_pyfunction!(ruleset_version, m)?)?;
    Ok(())
}
