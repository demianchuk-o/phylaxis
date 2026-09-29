# tests/

This workspace is virtual (no root package), so cargo does not compile a root-level `tests/`
directory. End-to-end contracts live in **`crates/cli/tests/e2e_*.rs`**, in the crate that owns
scan orchestration (`docs/DECISIONS.md`, ADR-016). Fixtures stay in `../fixtures/` and are
reached from tests via `CARGO_MANIFEST_DIR/../../fixtures`.

This directory is kept so that the layout in `CLAUDE.md` remains true for humans; nothing
else goes here. The Python evaluation harness lives in `../eval/` (created by the harness
task, T-14), not here, because it is not a cargo test.
