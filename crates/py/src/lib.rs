//! Python bindings for phylaxis.
//!
//! Deliberately thin: this crate only marshals between Python and the Rust
//! entry points. No analysis logic belongs here.
//!
//! The exported API surface is a DESIGN decision, not a scaffolding one -- what
//! `scan()` should accept and return is settled in the architecture session.
//! See `FABLE-BRIEF.md`, section 3.7. Only the plumbing is set up here, proven
//! by an actual wheel build.

use pyo3::prelude::*;

/// The package version, taken from Cargo at compile time so that the Rust crate
/// and the wheel can never disagree about it.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Entry point behind the `phylaxis` console script.
///
/// Takes argv from Python rather than reading `std::env::args`, so that the
/// interpreter stays the owner of process state.
#[pyfunction]
fn cli_main(argv: Vec<String>) -> i32 {
    phylaxis_cli::run(argv)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(cli_main, m)?)?;
    Ok(())
}
