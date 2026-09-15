//! AttackTechnique [12], ExecutionPhase and PhaseMap [13]: the Backstabber coordinates
//! (invariant 4; DECISIONS.md, ADR-008).
//!
//! The variant names were checked against the source on 2026-09-16: Ohm M., Plate H.,
//! Sykosch A., Meier M. *Backstabber's Knife Collection: A Review of Open Source Software
//! Supply Chain Attacks*, DIMVA 2020, LNCS 12223, pp. 23-43. `Objective` uses that paper's
//! own labels for the primary objective of a payload. `ExecutionPhase` covers two of the
//! three lifecycle phases of its execution attack tree; `Import` is a refinement of the
//! third for Python, and `test cases` is out of scope. Both points are argued in ADR-008.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{FileId, SymbolId};

/// When code can run. Ordered weakest to strongest so that `max` picks the strongest phase
/// when a definition is reachable from several roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    /// Reachable only through an explicit call after import.
    Runtime,
    /// Reachable from module-level code of a package module: runs on `import`.
    /// This work's refinement of the paper's `runtime` branch, which names the import
    /// mechanism as its Python example rather than as a phase of its own (ADR-008).
    Import,
    /// Reachable from `setup.py`, a `cmdclass` command, or an in-tree build backend.
    Install,
}

impl ExecutionPhase {
    /// WHY these numbers: ADR-008. They encode the ordering from the taxonomy, are fixed
    /// before evaluation, and change only by a new ADR.
    pub fn weight(self) -> f64 {
        match self {
            ExecutionPhase::Install => 1.0,
            ExecutionPhase::Import => 0.8,
            ExecutionPhase::Runtime => 0.5,
        }
    }
}

/// Where a phase root comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseRootKind {
    /// `<module>` of the top-level `setup.py`.
    SetupPyModule,
    /// `run` of a class used as a `cmdclass` value.
    CmdclassRun,
    /// The module named by `[build-system] build-backend` when `backend-path` is in-tree.
    BuildBackend,
    /// `<module>` of an `__init__.py`.
    InitModule,
    /// `<module>` of a top-level single-file module.
    TopLevelModule,
}

/// An entry point of a phase: a call-graph symbol from which reachability is computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseRoot {
    pub phase: ExecutionPhase,
    pub kind: PhaseRootKind,
    pub symbol: SymbolId,
    pub file: FileId,
}

/// [13] The phase of every callable definition, plus the roots it was computed from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseMap {
    pub roots: Vec<PhaseRoot>,
    pub phase_of: BTreeMap<SymbolId, ExecutionPhase>,
}

impl PhaseMap {
    /// A definition absent from the map is `Runtime`: unreachable from any root means it
    /// only runs when something calls it explicitly.
    pub fn phase_of(&self, symbol: SymbolId) -> ExecutionPhase {
        self.phase_of
            .get(&symbol)
            .copied()
            .unwrap_or(ExecutionPhase::Runtime)
    }

    /// Records `phase` for `symbol`, keeping the strongest phase seen.
    pub fn strengthen(&mut self, symbol: SymbolId, phase: ExecutionPhase) {
        let entry = self.phase_of.entry(symbol).or_insert(phase);
        if phase > *entry {
            *entry = phase;
        }
    }
}

/// The payload's purpose, per the Backstabber objective categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Objective {
    Exfiltration,
    Dropper,
    Backdoor,
    DenialOfService,
    FinancialGain,
    /// The rule certifies a phase or a capability without knowing the purpose
    /// (the `PHX-INS-*` rules).
    Unknown,
}

/// [12] The taxonomy coordinates of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub objective: Objective,
    /// The phase in which this technique is typically observed; the *actual* phase of a
    /// finding comes from the `PhaseMap`.
    pub typical_phase: ExecutionPhase,
    /// Whether the technique is an obfuscation technique in Backstabber's sense
    /// (encoding, encryption) rather than a capability.
    pub obfuscation: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ADR-008: Install outranks Import outranks Runtime, both in ordering and in weight.
    #[test]
    fn phase_ordering_and_weights_agree() {
        assert!(ExecutionPhase::Install > ExecutionPhase::Import);
        assert!(ExecutionPhase::Import > ExecutionPhase::Runtime);
        assert!(ExecutionPhase::Install.weight() > ExecutionPhase::Import.weight());
        assert!(ExecutionPhase::Import.weight() > ExecutionPhase::Runtime.weight());
        assert_eq!(ExecutionPhase::Install.weight(), 1.0);
    }

    // A definition reachable from both an import root and an install root is Install.
    #[test]
    fn strengthen_keeps_the_strongest_phase() {
        let mut m = PhaseMap::default();
        let s = SymbolId(3);
        assert_eq!(m.phase_of(s), ExecutionPhase::Runtime);
        m.strengthen(s, ExecutionPhase::Import);
        m.strengthen(s, ExecutionPhase::Install);
        m.strengthen(s, ExecutionPhase::Import);
        assert_eq!(m.phase_of(s), ExecutionPhase::Install);
    }
}
