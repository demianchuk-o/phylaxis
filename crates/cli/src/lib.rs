//! Command line orchestration, exposed as a library.
//!
//! WHY a library and not just `main.rs`: the tool ships two ways -- as a native
//! binary and as a Python wheel whose console script calls in through PyO3.
//! Both entry points must run the *same* code path, so the real work lives here
//! and `main.rs` is a thin wrapper. See `crates/py`.
//!
//! The clap command surface and scan orchestration are designed in the
//! architecture session -- see `FABLE-BRIEF.md`, section 5.

/// Runs the CLI over `argv` (including argv[0]) and returns a process exit code.
///
/// Returns an exit code rather than calling `std::process::exit`, because the
/// Python binding must be able to return control to the interpreter.
pub fn run(_argv: Vec<String>) -> i32 {
    println!("phylaxis: scaffold only, no scan implemented yet");
    0
}
