//! Safe extraction of an sdist into a fresh temporary directory.
//!
//! SAFETY INVARIANT (CLAUDE.md #5, tar-slip / zip-slip): every entry path is validated
//! by [`validate_entry`] before anything is written. Absolute paths, `..` components,
//! symlinks, hardlinks and special entries are rejected, and the whole archive is
//! rejected with them, because a partially extracted hostile archive is not something a
//! later stage should reason about. Limits from `ExtractOptions` fail closed.
//!
//! # The two passes
//!
//! [`extract_sdist`] reads the archive **twice**: the first pass validates every entry and
//! enforces every limit, the second pass writes. The extraction directory is not even
//! created until the first pass has finished without an error.
//!
//! The cheaper design — validate each entry immediately before writing it — is safe against
//! traversal but leaves a hostile archive's *innocent* entries on disk once a later entry is
//! rejected. Deleting the directory afterwards mostly recovers from that, but "mostly" is the
//! wrong word in the one place in this program where an attacker chooses the input. Two
//! passes buy a guarantee that can be stated in one sentence and needs no cleanup path to be
//! true: **no file is created until the entire archive has been found clean.** The cost is
//! decompressing an sdist twice, which is a few milliseconds on inputs of this size.
//!
//! # What reaches the disk (ADR-020)
//!
//! Only `.py` and `pyproject.toml`. Every other member — bundled binaries, nested archives,
//! data files, documentation — has its path and declared size recorded in
//! [`ExtractedTree::manifest`] and its bytes discarded unread.
//!
//! The analyser never opens those files anyway (invariant 2), so writing them bought nothing;
//! not writing them turns a claim about code paths into a property of the disk that a test can
//! check by walking the extraction root. The manifest is kept because **existence is signal**:
//! `subprocess.run(["./vendor/helper.bin"])` is a package running a payload it ships when that
//! path is in the distribution, and a download-and-execute shape when it is not. Same line,
//! different finding, and the discriminator is a fact about a file nothing needs to read.

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use phylaxis_core::{Distribution, DistributionKind, ExtractOptions, SourceFile};
use tar::EntryType;

use crate::digest::sha256_of_file;
use crate::error::ParseError;

/// What kind of archive entry is being validated. Mirrors the tar entry types the
/// analyser is willing to see; everything else is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    Other,
}

/// A member of the distribution that is not analysed: anything that is not `.py` or
/// `pyproject.toml` (ADR-020). The bytes are discarded; the path and size are kept, because a
/// rule may need to know that the distribution *ships* a given file without ever reading it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestEntry {
    /// Relative to the distribution root, forward slashes, same convention as `SourceFile`.
    pub rel_path: String,
    /// For an archive member this is the size declared in the tar header — the archive's
    /// claim, not a measurement, because the body is never read. For a directory member it is
    /// the size on disk. The distinction matters if a rule ever reasons about the number:
    /// an attacker controls the header, and nothing here verifies it.
    pub size_bytes: u64,
}

/// The files of one distribution on disk, in canonical order.
///
/// `root` is a fresh temporary directory when created by [`extract_sdist`] and is removed
/// on drop; it is the caller's own directory when created by [`load_directory`], and is
/// then never removed. WHY the flag: deleting a user's source tree because a struct went
/// out of scope is exactly the kind of accident a scanner must be incapable of.
#[derive(Debug)]
pub struct ExtractedTree {
    pub root: PathBuf,
    /// Sorted by `rel_path`; `FileId`s are positions in this vector (ADR-004 determinism).
    pub files: Vec<SourceFile>,
    /// Members that were seen but not written, sorted by `rel_path` (ADR-020).
    pub manifest: Vec<ManifestEntry>,
    /// Parsed from the archive name and contents; `None` for directories.
    pub distribution: Option<Distribution>,
    owned_temp: bool,
}

impl ExtractedTree {
    /// Constructor for the two producers in this module (public so that the CLI can wrap
    /// a directory it already owns; `owned_temp` must then be `false`).
    pub fn new(
        root: PathBuf,
        files: Vec<SourceFile>,
        manifest: Vec<ManifestEntry>,
        distribution: Option<Distribution>,
        owned_temp: bool,
    ) -> Self {
        Self {
            root,
            files,
            manifest,
            distribution,
            owned_temp,
        }
    }

    pub fn is_temporary(&self) -> bool {
        self.owned_temp
    }

    /// Whether the distribution ships `rel_path`, whether or not it was analysed.
    ///
    /// This is the question a rule asks about `subprocess.run(["./vendor/helper.bin"])`: a
    /// package executing a file it carries is a different finding from one executing a file
    /// it must fetch first, and only this predicate separates them.
    pub fn contains_path(&self, rel_path: &str) -> bool {
        self.files.iter().any(|f| f.rel_path == rel_path)
            || self.manifest.iter().any(|m| m.rel_path == rel_path)
    }
}

impl Drop for ExtractedTree {
    fn drop(&mut self) {
        if self.owned_temp {
            // Best effort: a leaked temp dir is a nuisance, a panic in drop is worse.
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

/// Rejects any entry that could write outside the extraction root or that is not a plain
/// file or directory. `entry_path` is the path exactly as stored in the archive.
///
/// Contract:
/// - absolute paths (`/x`, `C:\x`, `\\x`) → `AbsolutePath`;
/// - any `..` component, anywhere → `PathTraversal`;
/// - `Symlink` / `Hardlink` → `LinkEntry`; `Other` → `UnsupportedEntry`;
/// - a leading `./` is tolerated and normalised by the caller; an empty path is traversal.
///
/// WHY this works on the raw string instead of `Path`: an archive entry path is a string
/// chosen by whoever built the archive, and it means the same thing wherever the archive is
/// opened. `Path`'s answers are host-specific and would make the guard platform-dependent in
/// exactly the direction that loses — on Unix, `Path::new("C:\\evil.py")` is one innocent
/// relative filename and `is_absolute()` is false; on Windows, `Path::new("/etc/passwd")` has
/// no prefix and `is_absolute()` is *also* false. A scanner that runs on a developer's laptop
/// and a Linux evaluation machine cannot have a guard that disagrees between them, so the
/// checks below are syntactic, cover both separators and both absolute-path syntaxes, and
/// give the same answer everywhere.
pub fn validate_entry(entry_path: &Path, kind: EntryKind) -> Result<(), ParseError> {
    let raw = entry_path.to_string_lossy();
    let entry = raw.as_ref();

    // Absolute, in any syntax a tar header might carry.
    //   /etc/passwd            POSIX absolute
    //   \\server\share\evil    UNC, and any backslash-rooted path
    //   C:\Windows\evil.py     drive-absolute
    //   C:evil.py              drive-*relative*, which resolves against that drive's current
    //                          directory and is therefore just as much not-ours
    let drive_prefixed = {
        let b = entry.as_bytes();
        b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    };
    if entry.starts_with('/') || entry.starts_with('\\') || drive_prefixed {
        return Err(ParseError::AbsolutePath {
            entry: entry.to_owned(),
        });
    }

    // `..` anywhere, on either separator. Splitting the raw string is deliberate: on Unix a
    // `Path` would not treat `\` as a separator, so `pkg\..\..\evil.py` would look like a
    // single innocent filename and walk straight past a component-based check.
    let mut components = 0usize;
    for part in entry.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(ParseError::PathTraversal {
                entry: entry.to_owned(),
            });
        }
        components += 1;
    }

    // An entry naming nothing at all. A directory entry may legitimately normalise to
    // nothing -- GNU tar writes `./` as the first member of an archive built from `.`, and
    // that member is the root, which already exists and is never written. A *file* that
    // names nothing has no meaning and is treated as hostile rather than skipped.
    if components == 0 && kind != EntryKind::Directory {
        return Err(ParseError::PathTraversal {
            entry: entry.to_owned(),
        });
    }

    // The path is in-bounds; now the entry type. A link is refused whatever its own path
    // says, because the danger is its target and the target is not this string.
    match kind {
        EntryKind::File | EntryKind::Directory => Ok(()),
        EntryKind::Symlink => Err(ParseError::LinkEntry {
            entry: entry.to_owned(),
            kind: "symlink",
        }),
        EntryKind::Hardlink => Err(ParseError::LinkEntry {
            entry: entry.to_owned(),
            kind: "hardlink",
        }),
        EntryKind::Other => Err(ParseError::UnsupportedEntry {
            entry: entry.to_owned(),
            kind: "special entry (device, FIFO or socket)".to_owned(),
        }),
    }
}

/// The entry path with `.` and empty components dropped and separators normalised to `/`.
/// Only ever called on a path [`validate_entry`] has already accepted, so it cannot contain
/// `..` and cannot be absolute.
fn normalize_entry(entry: &str) -> String {
    entry
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Maps a tar entry type onto what the analyser is willing to see. `None` means the entry is
/// archive metadata rather than a member: GNU long-name records and pax extended headers are
/// how ordinary `tar` stores a path longer than 100 bytes, so refusing them would reject a
/// large share of real sdists. The `tar` crate consumes them and applies them to the entry
/// that follows, so skipping them here loses nothing -- the *resulting* path is still
/// validated, which is the only thing that matters.
fn entry_kind(t: EntryType) -> Option<EntryKind> {
    if t.is_pax_global_extensions() || t.is_pax_local_extensions() || t.is_gnu_longname() {
        return None;
    }
    if t.is_gnu_longlink() {
        // A long link *name* still describes a link, and links are refused.
        return Some(EntryKind::Symlink);
    }
    Some(if t.is_dir() {
        EntryKind::Directory
    } else if t.is_symlink() {
        EntryKind::Symlink
    } else if t.is_hard_link() {
        EntryKind::Hardlink
    } else if t.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    })
}

fn open_archive(path: &Path) -> Result<tar::Archive<GzDecoder<BufReader<File>>>, ParseError> {
    let file = File::open(path).map_err(|source| ParseError::Io {
        path: path.to_owned(),
        source,
    })?;
    Ok(tar::Archive::new(GzDecoder::new(BufReader::new(file))))
}

/// Pass one. Validates every entry and enforces every limit, writing nothing. Returns the
/// normalised path of every member, which is all pass two needs from it -- the sizes were
/// checked here and are re-checked against the bytes actually read, never carried forward.
fn validate_archive(sdist_path: &Path, opts: &ExtractOptions) -> Result<Vec<String>, ParseError> {
    let mut archive = open_archive(sdist_path)?;
    let entries = archive
        .entries()
        .map_err(|e| ParseError::Archive(e.to_string()))?;

    let mut members = Vec::new();
    let mut count: u32 = 0;
    let mut total: u64 = 0;

    for entry in entries {
        let entry = entry.map_err(|e| ParseError::Archive(e.to_string()))?;
        let header = entry.header();

        let Some(kind) = entry_kind(header.entry_type()) else {
            continue; // archive metadata, not a member
        };

        let path = entry
            .path()
            .map_err(|e| ParseError::Archive(e.to_string()))?
            .into_owned();
        validate_entry(&path, kind)?;

        // Counted before the limit check so that `max_entries: 1` rejects the *second*
        // entry rather than allowing it.
        count += 1;
        if count > opts.max_entries {
            return Err(ParseError::TooManyEntries {
                limit: opts.max_entries,
            });
        }

        let size = header
            .size()
            .map_err(|e| ParseError::Archive(e.to_string()))?;
        if size > opts.max_file_bytes {
            return Err(ParseError::TooLarge {
                limit: opts.max_file_bytes,
                what: "one file",
            });
        }
        total = total.saturating_add(size);
        if total > opts.max_total_bytes {
            return Err(ParseError::TooLarge {
                limit: opts.max_total_bytes,
                what: "total uncompressed bytes",
            });
        }

        // The size is read from the header before the body is touched, and returning here
        // drops the iterator, so a decompression bomb is abandoned rather than streamed.
        let rel_path = normalize_entry(&path.to_string_lossy());
        if rel_path.is_empty() {
            continue; // the `./` root member
        }
        members.push(rel_path);
    }

    Ok(members)
}

/// The single top-level directory an sdist is required to have (`{name}-{version}/`).
/// Returns the prefix to strip.
fn single_top_level(members: &[String], path: &Path) -> Result<String, ParseError> {
    let mut top: Option<&str> = None;
    for m in members {
        let first = m.split('/').next().unwrap_or("");
        match top {
            None => top = Some(first),
            Some(t) if t == first => {}
            Some(t) => {
                return Err(ParseError::NotAnSdist {
                    path: path.to_owned(),
                    reason: format!(
                        "expected one top-level directory, found at least two: `{t}` and `{first}`"
                    ),
                });
            }
        }
    }
    match top {
        Some(t) if !t.is_empty() => Ok(t.to_owned()),
        _ => Err(ParseError::NotAnSdist {
            path: path.to_owned(),
            reason: "archive contains no entries".to_owned(),
        }),
    }
}

/// Creates a fresh directory under the system temp directory.
///
/// WHY `create_dir` and not `create_dir_all`: `create_dir` fails if the path already exists,
/// and that failure is the point. The system temp directory is world-writable on Unix, so a
/// local attacker who can guess the name can pre-create it -- as a symlink to somewhere else.
/// Refusing to reuse an existing directory means the extraction root is always one this
/// process just made.
fn fresh_temp_dir() -> Result<PathBuf, ParseError> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let base = std::env::temp_dir();
    for _ in 0..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("phylaxis-{}-{}-{}", std::process::id(), n, nanos));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ParseError::Io {
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(ParseError::Io {
        path: base,
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create a fresh extraction directory",
        ),
    })
}

/// Extracts `sdist_path` (a `.tar.gz`) into a fresh temporary directory, validating every
/// entry first, enforcing `opts` limits, and collecting the source files in canonical order.
///
/// The sdist's single top-level directory (`{name}-{version}/`) is stripped, so
/// `rel_path`s in the result start at the distribution root (`setup.py`, `pkg/…`).
///
/// Preconditions: `sdist_path` exists and is readable. Postconditions on `Ok`: no file was
/// written outside the returned `root`; no entry was executed or interpreted in any way.
pub fn extract_sdist(
    sdist_path: &Path,
    opts: &ExtractOptions,
) -> Result<ExtractedTree, ParseError> {
    // WHY validate-then-write and not the tar crate's own unpack: the crate's protections
    // are good but implicit; an explicit validation pass is what the safety test pins.
    let members = validate_archive(sdist_path, opts)?;
    let top = single_top_level(&members, sdist_path)?;

    // Nothing above this line touched the file system. From here the archive is known clean.
    let root = fresh_temp_dir()?;
    let tree_root = root.clone();
    // Own the directory immediately, so that an error below still removes it.
    let mut tree = ExtractedTree::new(tree_root, Vec::new(), Vec::new(), None, true);

    let mut archive = open_archive(sdist_path)?;
    let entries = archive
        .entries()
        .map_err(|e| ParseError::Archive(e.to_string()))?;

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifest: Vec<ManifestEntry> = Vec::new();
    for entry in entries {
        let mut entry = entry.map_err(|e| ParseError::Archive(e.to_string()))?;
        let Some(kind) = entry_kind(entry.header().entry_type()) else {
            continue;
        };
        let path = entry
            .path()
            .map_err(|e| ParseError::Archive(e.to_string()))?
            .into_owned();

        // Re-validated rather than trusted from pass one. The two passes read the same
        // bytes, so this can only fail if the file changed underneath us -- which is
        // precisely when we want to stop.
        validate_entry(&path, kind)?;

        let normalized = normalize_entry(&path.to_string_lossy());
        let Some(rel) = strip_top_level(&normalized, &top) else {
            continue;
        };
        if kind == EntryKind::Directory || rel.is_empty() {
            continue;
        }

        // ADR-020. A member the analyser will never open is recorded and dropped here: its
        // body is not read and nothing is written for it. The loop must still reach the next
        // header, which `tar`'s iterator handles by skipping the body it already knows the
        // length of, so this costs nothing and keeps the extraction root free of everything
        // that is not Python text.
        if SourceFile::classify(&rel).is_none() {
            let size_bytes = entry
                .header()
                .size()
                .map_err(|e| ParseError::Archive(e.to_string()))?;
            manifest.push(ManifestEntry {
                rel_path: rel,
                size_bytes,
            });
            continue;
        }

        let dest = safe_join(&root, &rel)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|source| ParseError::Io {
                path: parent.to_owned(),
                source,
            })?;
        }

        // `take` bounds the read at the per-file limit even if the header lied about the
        // size: the limit is enforced on bytes actually produced, not on a claim.
        let mut bytes = Vec::new();
        let mut limited = entry.by_ref().take(opts.max_file_bytes.saturating_add(1));
        limited
            .read_to_end(&mut bytes)
            .map_err(|source| ParseError::Io {
                path: dest.clone(),
                source,
            })?;
        if bytes.len() as u64 > opts.max_file_bytes {
            return Err(ParseError::TooLarge {
                limit: opts.max_file_bytes,
                what: "one file",
            });
        }

        let mut out = File::create(&dest).map_err(|source| ParseError::Io {
            path: dest.clone(),
            source,
        })?;
        out.write_all(&bytes).map_err(|source| ParseError::Io {
            path: dest.clone(),
            source,
        })?;

        files.push((rel, bytes));
    }

    manifest.sort();
    manifest.dedup();
    tree.manifest = manifest;
    tree.files = collect_sources(files);
    tree.distribution = describe_distribution(sdist_path)?;
    Ok(tree)
}

/// Drops the archive's single top-level directory from a normalised entry path. Returns
/// `None` for an entry that is not under it, which pass one has already made impossible.
fn strip_top_level(normalized: &str, top: &str) -> Option<String> {
    if normalized == top {
        return Some(String::new());
    }
    normalized
        .strip_prefix(top)
        .and_then(|rest| rest.strip_prefix('/'))
        .map(|rest| rest.to_owned())
}

/// Joins a validated relative path onto the root and restates the invariant on the result.
///
/// This cannot fail given a path [`validate_entry`] accepted, and that is the point of
/// keeping it: the check is one line, it runs on the value actually about to be written
/// rather than on the string that was inspected earlier, and if a future change to
/// validation ever lets something through, the write still does not happen.
fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, ParseError> {
    let dest = root.join(rel);
    if !dest.starts_with(root) {
        return Err(ParseError::PathTraversal {
            entry: rel.to_owned(),
        });
    }
    Ok(dest)
}

/// Sorts by path and assigns `FileId`s as positions, which is what makes every downstream
/// table and every serialised report byte-identical across runs (ADR-004).
fn collect_sources(mut files: Vec<(String, Vec<u8>)>) -> Vec<SourceFile> {
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files.dedup_by(|a, b| a.0 == b.0);
    files
        .into_iter()
        .enumerate()
        .filter_map(|(i, (rel_path, bytes))| {
            SourceFile::classify(&rel_path).map(|kind| SourceFile {
                id: phylaxis_core::FileId(i as u32),
                rel_path,
                kind,
                bytes,
            })
        })
        .collect()
}

/// Identity of the archive: name and version from the filename (PEP 625), digest and size
/// from the bytes. `None` when the filename is not a well-formed sdist name -- a fixture or
/// a hand-renamed file is still analysable, it just has no cacheable identity (ADR-017).
fn describe_distribution(sdist_path: &Path) -> Result<Option<Distribution>, ParseError> {
    let filename = match sdist_path.file_name().map(|f| f.to_string_lossy()) {
        Some(f) => f.into_owned(),
        None => return Ok(None),
    };
    let Some((raw_name, version)) = Distribution::parse_sdist_filename(&filename) else {
        return Ok(None);
    };
    let Ok(name) = phylaxis_core::PackageName::normalize(&raw_name) else {
        return Ok(None);
    };
    let sha256 = sha256_of_file(sdist_path)?;
    let size_bytes = fs::metadata(sdist_path)
        .map(|m| m.len())
        .map_err(|source| ParseError::Io {
            path: sdist_path.to_owned(),
            source,
        })?;
    Ok(Some(Distribution {
        name,
        version,
        filename,
        kind: DistributionKind::Sdist,
        sha256,
        size_bytes,
    }))
}

/// Loads an already-extracted distribution from `dir` without copying. The returned tree
/// does not own `dir` and never deletes it. Directories are never cached (ADR-017).
pub fn load_directory(dir: &Path, opts: &ExtractOptions) -> Result<ExtractedTree, ParseError> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifest: Vec<ManifestEntry> = Vec::new();
    let mut count: u32 = 0;
    let mut total: u64 = 0;

    // `follow_links(false)` is the whole safety story here: a symlink inside the caller's
    // tree pointing at `/etc/passwd` would otherwise be walked into and read as if it were
    // part of the package. Links are skipped, exactly as they are refused in an archive.
    let walker = walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name();
    for entry in walker {
        let entry = entry.map_err(|e| ParseError::Io {
            path: e.path().unwrap_or(dir).to_owned(),
            source: e
                .into_io_error()
                .unwrap_or_else(|| std::io::Error::other("directory walk failed")),
        })?;
        let file_type = entry.file_type();
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }

        let rel = entry
            .path()
            .strip_prefix(dir)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if rel.is_empty() {
            continue;
        }

        count += 1;
        if count > opts.max_entries {
            return Err(ParseError::TooManyEntries {
                limit: opts.max_entries,
            });
        }

        let meta = entry.metadata().map_err(|e| ParseError::Io {
            path: entry.path().to_owned(),
            source: e
                .into_io_error()
                .unwrap_or_else(|| std::io::Error::other("metadata failed")),
        })?;
        if meta.len() > opts.max_file_bytes {
            return Err(ParseError::TooLarge {
                limit: opts.max_file_bytes,
                what: "one file",
            });
        }
        total = total.saturating_add(meta.len());
        if total > opts.max_total_bytes {
            return Err(ParseError::TooLarge {
                limit: opts.max_total_bytes,
                what: "total uncompressed bytes",
            });
        }

        // ADR-020, the directory half: a non-source file is recorded and left alone. Here
        // the size really is measured rather than claimed -- there is no attacker-written
        // header in the way -- but nothing reads the contents either way.
        if SourceFile::classify(&rel).is_none() {
            manifest.push(ManifestEntry {
                rel_path: rel,
                size_bytes: meta.len(),
            });
            continue;
        }

        let bytes = fs::read(entry.path()).map_err(|source| ParseError::Io {
            path: entry.path().to_owned(),
            source,
        })?;
        files.push((rel, bytes));
    }

    manifest.sort();
    manifest.dedup();

    // `owned_temp: false` -- this tree is the caller's and is never removed on drop.
    Ok(ExtractedTree::new(
        dir.to_owned(),
        collect_sources(files),
        manifest,
        None,
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // SAFETY, first tier of the test contracts: no entry may escape the extraction root.
    #[test]
    fn rejects_parent_directory_components() {
        assert!(matches!(
            validate_entry(Path::new("../../evil.py"), EntryKind::File),
            Err(ParseError::PathTraversal { .. })
        ));
        assert!(matches!(
            validate_entry(Path::new("pkg/../../evil.py"), EntryKind::File),
            Err(ParseError::PathTraversal { .. })
        ));
        assert!(matches!(
            validate_entry(Path::new(""), EntryKind::File),
            Err(ParseError::PathTraversal { .. })
        ));
    }

    #[test]
    fn rejects_absolute_paths_on_every_platform_syntax() {
        for p in [
            "/etc/passwd",
            "C:\\Windows\\evil.py",
            "\\\\server\\share\\evil.py",
        ] {
            assert!(
                matches!(
                    validate_entry(Path::new(p), EntryKind::File),
                    Err(ParseError::AbsolutePath { .. })
                ),
                "{p} must be rejected as absolute"
            );
        }
    }

    // A symlink to /etc/passwd followed by a regular entry writing through it is the
    // classic tar-slip; links are rejected outright rather than resolved.
    #[test]
    fn rejects_links_and_special_entries() {
        assert!(matches!(
            validate_entry(Path::new("pkg/link.py"), EntryKind::Symlink),
            Err(ParseError::LinkEntry { .. })
        ));
        assert!(matches!(
            validate_entry(Path::new("pkg/hard.py"), EntryKind::Hardlink),
            Err(ParseError::LinkEntry { .. })
        ));
        assert!(matches!(
            validate_entry(Path::new("pkg/dev"), EntryKind::Other),
            Err(ParseError::UnsupportedEntry { .. })
        ));
    }

    #[test]
    fn accepts_plain_relative_files_and_dirs() {
        assert!(validate_entry(Path::new("pkg-1.0/setup.py"), EntryKind::File).is_ok());
        assert!(validate_entry(Path::new("pkg-1.0/pkg/"), EntryKind::Directory).is_ok());
        assert!(validate_entry(Path::new("./pkg-1.0/pkg/a.py"), EntryKind::File).is_ok());
    }

    // The guard must give the same answer on every host. A backslash is a separator in a
    // tar entry regardless of what the running platform thinks, so `..` behind one is still
    // traversal -- on Unix a component-based check would see one innocent filename.
    #[test]
    fn traversal_is_caught_behind_backslashes_too() {
        for p in [
            "pkg\\..\\..\\evil.py",
            "pkg/..\\evil.py",
            "a\\b\\..\\..\\..\\evil.py",
        ] {
            assert!(
                matches!(
                    validate_entry(Path::new(p), EntryKind::File),
                    Err(ParseError::PathTraversal { .. })
                ),
                "{p} must be rejected as traversal"
            );
        }
    }

    // A drive-relative path (`C:evil.py`) resolves against that drive's current directory,
    // which is no more ours than `C:\evil.py` is.
    #[test]
    fn rejects_drive_relative_paths() {
        assert!(matches!(
            validate_entry(Path::new("C:evil.py"), EntryKind::File),
            Err(ParseError::AbsolutePath { .. })
        ));
    }

    // GNU tar writes `./` as the first member of an archive built from `.`. It names the
    // root, which already exists, so it is accepted as a directory and skipped -- rejecting
    // it would refuse a large share of real sdists.
    #[test]
    fn tolerates_the_dot_root_directory_member() {
        assert!(validate_entry(Path::new("./"), EntryKind::Directory).is_ok());
        assert!(validate_entry(Path::new("."), EntryKind::Directory).is_ok());
        assert!(matches!(
            validate_entry(Path::new("./"), EntryKind::File),
            Err(ParseError::PathTraversal { .. })
        ));
    }

    // The whole archive is rejected, not just the bad entry, and nothing is left behind.
    // Fixture: fixtures/malicious/tar_slip.tar.gz — built by T-02 with entries
    // `../../evil.py`, `/abs/evil.py` and a symlink to /etc/passwd (see `fixtures/README.md`).
    #[test]
    fn tar_slip_archive_is_rejected_whole() {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/malicious/tar_slip.tar.gz");
        let result = extract_sdist(&fixture, &ExtractOptions::default());
        assert!(matches!(
            result,
            Err(ParseError::PathTraversal { .. })
                | Err(ParseError::AbsolutePath { .. })
                | Err(ParseError::LinkEntry { .. })
        ));
    }

    // Limits fail closed: an archive with more entries than allowed is TooManyEntries.
    // Fixture: fixtures/benign/setup_py_plain.tar.gz has a handful of entries; with the
    // limit set to 1 it must be rejected, proving the limit is enforced before writing.
    #[test]
    fn entry_limit_is_enforced() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/benign/setup_py_plain.tar.gz");
        let opts = ExtractOptions {
            max_entries: 1,
            ..ExtractOptions::default()
        };
        assert!(matches!(
            extract_sdist(&fixture, &opts),
            Err(ParseError::TooManyEntries { limit: 1 })
        ));
    }

    // Canonical order: rel_paths sorted, FileId(i) == position i, top-level dir stripped.
    #[test]
    fn extracted_files_are_sorted_and_rooted_at_the_distribution() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/benign/setup_py_plain.tar.gz");
        let tree = extract_sdist(&fixture, &ExtractOptions::default()).unwrap();
        assert!(tree.is_temporary());
        let paths: Vec<&str> = tree.files.iter().map(|f| f.rel_path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        assert!(
            paths.contains(&"setup.py"),
            "top-level directory must be stripped: {paths:?}"
        );
        for (i, f) in tree.files.iter().enumerate() {
            assert_eq!(f.id.0 as usize, i);
        }
    }

    // A rejected archive must leave nothing on disk at all. The two-pass design makes this
    // structural rather than a cleanup path: the extraction directory is never created.
    #[test]
    fn a_rejected_archive_creates_no_extraction_directory() {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/malicious/tar_slip.tar.gz");
        let before = temp_children();
        assert!(extract_sdist(&fixture, &ExtractOptions::default()).is_err());
        let after = temp_children();
        assert_eq!(
            before, after,
            "a rejected archive must not leave an extraction directory behind"
        );
    }

    // ...and an accepted one cleans up after itself when the tree is dropped.
    #[test]
    fn the_extraction_directory_is_removed_on_drop() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/benign/setup_py_plain.tar.gz");
        let tree = extract_sdist(&fixture, &ExtractOptions::default()).unwrap();
        let root = tree.root.clone();
        assert!(root.exists());
        drop(tree);
        assert!(!root.exists(), "the temporary root outlived its tree");
    }

    fn temp_children() -> Vec<std::ffi::OsString> {
        let mut v: Vec<_> = fs::read_dir(std::env::temp_dir())
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .filter(|n| n.to_string_lossy().starts_with("phylaxis-"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    // ADR-020: the extraction root holds Python text and nothing else. This is the point of
    // the narrowing -- it turns "we never open a non-Python file", which is a claim about code
    // paths, into a property of the disk that a test can check by walking it.
    #[test]
    fn only_python_source_reaches_the_extraction_root() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/benign/setup_py_plain.tar.gz");
        let tree = extract_sdist(&fixture, &ExtractOptions::default()).unwrap();

        let mut written = 0usize;
        for entry in walkdir::WalkDir::new(&tree.root).follow_links(false) {
            let entry = entry.unwrap();
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                name.ends_with(".py") || name == "pyproject.toml",
                "non-source file reached the extraction root: {name}"
            );
            written += 1;
        }
        assert!(written > 0, "nothing was extracted at all");

        // README.md ships in the fixture. It must be known about and must not be on disk.
        assert!(
            tree.manifest.iter().any(|m| m.rel_path == "README.md"),
            "manifest: {:?}",
            tree.manifest
        );
        assert!(!tree.root.join("README.md").exists());
    }

    // The predicate a rule asks about `subprocess.run(["./vendor/helper.bin"])`: does the
    // distribution ship this path, whether or not we analysed it?
    #[test]
    fn contains_path_spans_both_analysed_and_recorded_members() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/benign/setup_py_plain.tar.gz");
        let tree = extract_sdist(&fixture, &ExtractOptions::default()).unwrap();
        assert!(tree.contains_path("setup.py"), "an analysed member");
        assert!(tree.contains_path("README.md"), "a recorded member");
        assert!(
            !tree.contains_path("vendor/helper.bin"),
            "a member that is absent"
        );
    }

    // The same narrowing on the directory path, over a fixture that ships a C source file.
    #[test]
    fn load_directory_records_non_source_members_without_reading_them() {
        let dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/benign/setup_py_env_cflags");
        let tree = load_directory(&dir, &ExtractOptions::default()).unwrap();
        assert!(tree.files.iter().any(|f| f.rel_path == "setup.py"));
        assert!(
            tree.manifest.iter().any(|m| m.rel_path == "src/speedups.c"),
            "manifest: {:?}",
            tree.manifest
        );
        assert!(tree.contains_path("src/speedups.c"));
        assert!(!tree.files.iter().any(|f| f.rel_path == "src/speedups.c"));
    }

    // A directory tree is loaded in place and is NOT owned: dropping must not delete it.
    #[test]
    fn load_directory_never_owns_the_callers_tree() {
        let dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/benign/setup_py_plain");
        let tree = load_directory(&dir, &ExtractOptions::default()).unwrap();
        assert!(!tree.is_temporary());
        assert!(tree.distribution.is_none());
        drop(tree);
        assert!(
            dir.join("setup.py").exists(),
            "load_directory must never delete the source tree"
        );
    }
}
