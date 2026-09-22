//! Which names a distribution makes importable (DECISIONS.md, ADR-021).
//!
//! The symbol stage names a module after its path relative to the distribution root, so it
//! needs to know where that root effectively begins. For most projects it is the archive
//! root itself; for a `src/` layout the packages sit one directory lower, and naming
//! `src/pkg/a.py` the module `src.pkg.a` would resolve every relative import inside it one
//! level too deep.
//!
//! This is decided from the file list and nothing else. `setup.py` cannot be executed
//! (invariant 5) and the declarations that would answer it authoritatively live in
//! `setup.cfg` or `setup.py` as often as in `pyproject.toml`, so a metadata-only answer
//! would be right where it applied and silently absent everywhere else.

use std::collections::BTreeSet;

/// The distribution's importable top-level names, sorted.
///
/// Three rules, in order, and the second is conditional — which is the whole reason this is
/// safe to apply to arbitrary packages:
///
/// 1. `X` for every `X/__init__.py` at the root. These are the distribution's own packages.
/// 2. **Only if rule 1 found nothing**, `X` for every `C/X/__init__.py`. A root with no
///    package at all is the `src/` layout's signature, and `C` is then a container
///    directory rather than a package.
/// 3. `X` for every root-level `X.py` except `setup.py`, which is the single-module
///    distribution.
///
/// WHY rule 2 is conditional. Unconditionally treating any non-package root directory as a
/// container would promote `tests/helpers/__init__.py` to the top-level name `helpers`, and
/// then `tests/helpers/util.py` would be named `helpers.util` — a wrong name, quietly. The
/// condition removes that entirely: a project with `tests/` also has its own package at the
/// root, so rule 1 fires and rule 2 never runs. The cases where rule 2 does run are the ones
/// where the root holds no packages, which is what a container layout *is*.
///
/// The residual failure is a miss, never a wrong name. A distribution that ships both a root
/// package and a `src/` tree keeps `src.` in the second one's module names, and a PEP 420
/// namespace package — no `__init__.py` anywhere — is not detected at all. Both lose call
/// edges; neither invents one.
pub fn discover_top_level_modules<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    // Collected because the rules need more than one pass, and rule 2 depends on rule 1's
    // outcome over the whole list rather than on any single path.
    let paths: Vec<&str> = paths.into_iter().collect();
    let mut names: BTreeSet<String> = BTreeSet::new();

    // Rule 1 — packages at the distribution root.
    for path in &paths {
        if let Some(name) = path.strip_suffix("/__init__.py")
            && !name.contains('/')
        {
            names.insert(name.to_owned());
        }
    }

    // Rule 2 — packages one level down, only when the root has none of its own. The
    // "container has no `__init__.py`" test is implied: if it had one, rule 1 would have
    // found it and this branch would not run.
    if names.is_empty() {
        for path in &paths {
            let Some(rest) = path.strip_suffix("/__init__.py") else {
                continue;
            };
            let mut parts = rest.split('/');
            if let (Some(_container), Some(package), None) =
                (parts.next(), parts.next(), parts.next())
            {
                names.insert(package.to_owned());
            }
        }
    }

    // Rule 3 — the single-module distribution. `setup.py` is build machinery, not something
    // an installing project can import.
    for path in &paths {
        if !path.contains('/')
            && *path != "setup.py"
            && let Some(stem) = path.strip_suffix(".py")
        {
            names.insert(stem.to_owned());
        }
    }

    names.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ordinary layout: the package sits at the root and is found by rule 1.
    #[test]
    fn root_packages_are_the_top_level_names() {
        let names = discover_top_level_modules([
            "setup.py",
            "pkg/__init__.py",
            "pkg/a.py",
            "pkg/sub/__init__.py",
        ]);
        assert_eq!(names, vec!["pkg".to_owned()]);
    }

    // The src layout: no package at the root, so `src/` is a container.
    #[test]
    fn a_container_directory_is_seen_through_when_the_root_has_no_package() {
        let names = discover_top_level_modules([
            "setup.py",
            "src/pkg/__init__.py",
            "src/pkg/a.py",
            "src/other/__init__.py",
        ]);
        assert_eq!(names, vec!["other".to_owned(), "pkg".to_owned()]);
    }

    // The case rule 2's condition exists for: a normal project with a test package must not
    // have `tests/` seen through, or `tests/helpers/util.py` becomes `helpers.util`.
    #[test]
    fn a_test_package_is_not_mistaken_for_a_container() {
        let names = discover_top_level_modules([
            "setup.py",
            "pkg/__init__.py",
            "tests/__init__.py",
            "tests/helpers/__init__.py",
            "tests/helpers/util.py",
        ]);
        assert_eq!(names, vec!["pkg".to_owned(), "tests".to_owned()]);
        assert!(!names.contains(&"helpers".to_owned()));
    }

    // A single-module distribution, and `setup.py` is never importable.
    #[test]
    fn a_root_module_counts_but_setup_py_does_not() {
        let names = discover_top_level_modules(["setup.py", "sixish.py", "pyproject.toml"]);
        assert_eq!(names, vec!["sixish".to_owned()]);
    }

    // A namespace package has no `__init__.py`, so nothing is discovered. Documented as a
    // miss: the module keeps its `src.` prefix rather than being given a guessed name.
    #[test]
    fn a_namespace_package_is_a_miss_not_a_guess() {
        let names = discover_top_level_modules(["src/pkg/a.py", "src/pkg/b.py"]);
        assert!(names.is_empty());
    }

    // Nothing at all is a legal answer, and the symbol stage reads it as "take every path as
    // written".
    #[test]
    fn an_empty_distribution_yields_no_names() {
        assert!(discover_top_level_modules([]).is_empty());
        assert!(discover_top_level_modules(["README.md", "LICENSE"]).is_empty());
    }
}
