//! Index newtypes. Every graph and table in the model is arena-shaped (a `Vec` addressed
//! by index), and these newtypes keep the indices from being mixed up.
//!
//! WHY indices and not references: the package graph is built in stages by different
//! crates and crosses a `rayon` boundary; index-shaped data is `Send` and serialisable,
//! reference-shaped data is neither without lifetimes leaking into every signature.
//!
//! This is the *arena + index* pattern, and it is worth understanding because it shows up
//! everywhere in Rust code that builds graphs. The obvious way to write a graph — each node
//! holding a `&Node` pointer to its neighbours — cannot be built at all without either
//! lifetimes that infect every function signature downstream, or reference counting with
//! `Rc<RefCell<..>>` that moves the aliasing check to run time and is not `Send`. The arena
//! sidesteps both: nodes live in one `Vec` that owns them all, and an "edge" is just a `u32`
//! position in that `Vec`. Copying an index is free, it can be sent between threads, and it
//! serialises to JSON as a number.
//!
//! The cost is that the compiler can no longer tell a file index from a symbol index — both
//! are `u32` — so passing the wrong one is a bug it would happily accept. That is what the
//! newtypes below buy back. `FileId(pub u32)` is a distinct type from `SymbolId(pub u32)`
//! even though both are one `u32` at run time, so mixing them up is a compile error and
//! costs nothing at all in the compiled binary.

use serde::{Deserialize, Serialize};

/// Index of a source file within one distribution, in canonical (sorted path) order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileId(pub u32);

/// Index of a node within one file's [`crate::Ast`] arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AstNodeId(pub u32);

/// Index of a symbol within the distribution-wide [`crate::SymbolTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SymbolId(pub u32);
