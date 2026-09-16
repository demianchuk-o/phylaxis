//! ScanOptions and ExtractOptions: everything a caller may vary. Anything not here is a
//! constant fixed by DECISIONS.md.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::graphs::Confidence;
use crate::report::AnalysisMode;

/// Limits enforced during extraction. WHY limits at all: an sdist is untrusted input and
/// a decompression bomb must fail closed with `SkipReason::TooLarge`, not exhaust memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractOptions {
    pub max_entries: u32,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            max_entries: 20_000,
            max_total_bytes: 256 * 1024 * 1024,
            max_file_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Options of one scan or batch. Serialisable because the Python API passes them as JSON
/// (ADR-013).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    pub mode: AnalysisMode,
    /// Findings below this confidence are dropped from the report. `None` keeps all,
    /// which is the evaluation default: filtering is the auditor's choice, not the tool's.
    pub min_confidence: Option<Confidence>,
    /// Thread count for `scan_many`. `None` lets `rayon` decide.
    pub jobs: Option<usize>,
    /// Path of the redb cache file. `None` disables caching.
    pub cache_path: Option<PathBuf>,
    pub extract: ExtractOptions,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ADR-013: the Python shim sends options as JSON; missing fields take defaults so that
    // `phylaxis.scan(path)` with no keyword arguments is `{}`.
    #[test]
    fn empty_json_gives_defaults() {
        let o: ScanOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(o, ScanOptions::default());
        assert_eq!(o.mode.label(), "D");
    }

    #[test]
    fn mode_is_selectable_from_json() {
        let o: ScanOptions =
            serde_json::from_str(r#"{"mode":{"mode":"file_cooccurrence"}}"#).unwrap();
        assert_eq!(o.mode, AnalysisMode::FileCooccurrence);
        let o: ScanOptions =
            serde_json::from_str(r#"{"mode":{"mode":"reachability","phase_weighting":false}}"#)
                .unwrap();
        assert_eq!(o.mode.label(), "C");
    }
}
