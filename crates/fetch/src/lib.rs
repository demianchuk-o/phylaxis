//! Optional PyPI package downloader. Network access is feature-gated.
//!
//! SAFETY INVARIANT (CLAUDE.md #5): this is the ONLY crate that may open a socket, only
//! when the `network` feature is enabled, and only to the official index hosts named in
//! `OFFICIAL_HOSTS`. A `PackageRef` is a name and a version, never a URL, so nothing read
//! from a package can ever become a download target. Without the feature, `reqwest` and
//! `tokio` are not even linked.

use std::path::{Path, PathBuf};

use phylaxis_core::PackageName;
use thiserror::Error;

/// The only hosts this crate will ever talk to.
pub const OFFICIAL_HOSTS: &[&str] = &["pypi.org", "files.pythonhosted.org"];

/// The JSON API endpoint pattern (name, version) used to locate the sdist URL, which must
/// itself be on an official host before it is followed.
pub const PYPI_JSON_API: &str = "https://pypi.org/pypi/{name}/{version}/json";

#[derive(Debug, Error)]
pub enum FetchError {
    /// Built without the `network` feature.
    #[error("network access is disabled in this build (enable the `network` feature)")]
    NetworkDisabled,
    /// A URL that is not on an official host was about to be followed. Never happens by
    /// design; kept as a variant so that the gate is a checked path, not an assumption.
    #[error("refusing to fetch from non-official host: {url}")]
    NotOfficialIndex { url: String },
    #[error("`{name}=={version}` has no sdist on PyPI")]
    NoSdist { name: String, version: String },
    #[error("package not found: `{name}=={version}`")]
    NotFound { name: String, version: String },
    #[error("invalid package reference `{0}`: expected `name==version`")]
    InvalidRef(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("I/O error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A package to download: a name and an exact version. Deliberately not a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub name: PackageName,
    pub version: String,
}

impl PackageRef {
    /// Parses `name==version`. Anything containing `://`, `/` or whitespace is rejected:
    /// references are never URLs or paths.
    ///
    /// WHY an allow-list for the version and not a check for bad shapes: the version is
    /// pasted into the JSON API URL. PEP 440 versions are drawn from `[A-Za-z0-9.+!_-]`, so
    /// anything else (`/`, `?`, `#`, `%`, `@`, whitespace) is refused before a URL exists,
    /// and the name has already been through `PackageName::normalize`'s own alphabet.
    pub fn parse(s: &str) -> Result<Self, FetchError> {
        let invalid = || FetchError::InvalidRef(s.to_owned());
        let (name, version) = s.split_once("==").ok_or_else(invalid)?;
        let version_ok = !version.is_empty()
            && version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '!' | '_' | '-'));
        if !version_ok {
            return Err(invalid());
        }
        let name = PackageName::normalize(name).map_err(|_| invalid())?;
        Ok(Self {
            name,
            version: version.to_owned(),
        })
    }
}

/// `true` iff `url` is `https://` and its host is one of `OFFICIAL_HOSTS`.
///
/// WHY this rejects userinfo outright instead of parsing past it: in
/// `https://evil.invalid:443@pypi.org` the real host *is* `pypi.org` (RFC 3986 reads
/// `evil.invalid:443` as user:password), so a parser that resolves the authority
/// correctly would allow it. We reject it anyway. Two reasons. The URLs this gate sees
/// come from PyPI's own JSON API, which never emits credentials, so userinfo is by
/// definition anomalous here — fail closed. And accepting it would mean betting that
/// `reqwest`'s URL parser splits the authority at exactly the same byte this function
/// does; HTTP clients have historically disagreed about that, and a disagreement here is
/// a request to a host we did not approve. Refusing the whole shape costs nothing real
/// and removes the bet.
pub fn is_official_index(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = authority.split(':').next().unwrap_or(authority); // no port tricks
    OFFICIAL_HOSTS.contains(&host)
}

/// Whether this build can download at all.
pub fn network_available() -> bool {
    cfg!(feature = "network")
}

/// Downloads the sdist of `pkg` into `dest_dir` and returns its path. Resolves the file
/// URL through the JSON API, verifies the URL is official, streams the file, and returns
/// only after the bytes are on disk. Nothing is extracted or executed here.
///
/// Four checks stand between PyPI's answer and the disk, because that answer is data from
/// the network like any other:
/// - every URL, and every redirect, must pass [`is_official_index`];
/// - the file name must be a plain `.tar.gz` sdist name with no path in it, so the JSON
///   cannot choose where the file lands;
/// - the body is capped at [`MAX_SDIST_BYTES`] while it streams;
/// - the bytes must hash to the sha256 PyPI published, or the partial file is deleted.
#[cfg(feature = "network")]
pub fn download_sdist(pkg: &PackageRef, dest_dir: &Path) -> Result<PathBuf, FetchError> {
    // A private single-threaded runtime per call keeps async inside this crate: callers
    // stay synchronous, and CPU analysis never runs on an async executor. One runtime per
    // download costs microseconds against a network round trip.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| FetchError::Http(e.to_string()))?;
    runtime.block_on(network::download(pkg, dest_dir))
}

/// The largest sdist this crate will write. Well above any real source distribution; a
/// bound so that a hostile or broken response cannot fill the disk.
pub const MAX_SDIST_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(feature = "network")]
mod network {
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use super::{FetchError, MAX_SDIST_BYTES, PYPI_JSON_API, PackageRef, is_official_index};

    fn http(e: reqwest::Error) -> FetchError {
        FetchError::Http(e.to_string())
    }

    pub(super) async fn download(pkg: &PackageRef, dest_dir: &Path) -> Result<PathBuf, FetchError> {
        // Redirects are followed only onto official hosts. PyPI redirects a non-canonical
        // project name to the canonical one, so refusing all redirects would break real
        // lookups; following any would let a redirect pick the host.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 || !is_official_index(attempt.url().as_str()) {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .user_agent(concat!("phylaxis/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(http)?;

        let api = PYPI_JSON_API
            .replace("{name}", pkg.name.as_str())
            .replace("{version}", &pkg.version);
        let not_found = || FetchError::NotFound {
            name: pkg.name.as_str().to_owned(),
            version: pkg.version.clone(),
        };
        let response = get(&client, &api).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(not_found());
        }
        let meta: serde_json::Value = response
            .error_for_status()
            .map_err(http)?
            .json()
            .await
            .map_err(http)?;

        let (url, filename, sha256) = pick_sdist(&meta).ok_or_else(|| FetchError::NoSdist {
            name: pkg.name.as_str().to_owned(),
            version: pkg.version.clone(),
        })?;
        if !is_plain_sdist_name(&filename) {
            return Err(FetchError::Http(format!(
                "unsafe sdist file name `{filename}`"
            )));
        }

        let target = dest_dir.join(&filename);
        let partial = dest_dir.join(format!("{filename}.part"));
        let io = |path: &Path| {
            let path = path.to_owned();
            move |source| FetchError::Io { path, source }
        };
        let result = async {
            let mut response = get(&client, &url).await?.error_for_status().map_err(http)?;
            let mut file = std::fs::File::create(&partial).map_err(io(&partial))?;
            let mut hasher = Sha256::new();
            let mut written: u64 = 0;
            while let Some(chunk) = response.chunk().await.map_err(http)? {
                written += chunk.len() as u64;
                if written > MAX_SDIST_BYTES {
                    return Err(FetchError::Http(format!(
                        "sdist larger than {MAX_SDIST_BYTES} bytes"
                    )));
                }
                hasher.update(&chunk);
                file.write_all(&chunk).map_err(io(&partial))?;
            }
            file.sync_all().map_err(io(&partial))?;
            let actual: String = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if !actual.eq_ignore_ascii_case(&sha256) {
                return Err(FetchError::Http(format!(
                    "sha256 mismatch for `{filename}`: PyPI says {sha256}, got {actual}"
                )));
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            let _ = std::fs::remove_file(&partial);
            return Err(e);
        }
        std::fs::rename(&partial, &target).map_err(io(&target))?;
        Ok(target)
    }

    /// A GET that has passed the host gate first, so the gate is a checked path on every
    /// request, not an assumption about where PyPI's JSON points.
    async fn get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response, FetchError> {
        if !is_official_index(url) {
            return Err(FetchError::NotOfficialIndex {
                url: url.to_owned(),
            });
        }
        client.get(url).send().await.map_err(http)
    }

    /// The first `.tar.gz` sdist in the release's `urls`, as `(url, filename, sha256)`.
    fn pick_sdist(meta: &serde_json::Value) -> Option<(String, String, String)> {
        meta.get("urls")?.as_array()?.iter().find_map(|u| {
            let s = |k: &str| u.get(k).and_then(|v| v.as_str()).map(str::to_owned);
            let filename = s("filename")?;
            if s("packagetype")? != "sdist" || !filename.ends_with(".tar.gz") {
                return None;
            }
            let sha256 = u.get("digests")?.get("sha256")?.as_str()?.to_owned();
            Some((s("url")?, filename, sha256))
        })
    }

    pub(super) fn is_plain_sdist_name(filename: &str) -> bool {
        phylaxis_core::Distribution::parse_sdist_filename(filename).is_some()
            && !filename.starts_with('.')
            && !filename.contains(['/', '\\', ':', '\0'])
            && !filename.contains("..")
    }
}

/// Without the feature there is nothing to call: every request fails closed.
#[cfg(not(feature = "network"))]
pub fn download_sdist(pkg: &PackageRef, dest_dir: &Path) -> Result<PathBuf, FetchError> {
    let _ = (pkg, dest_dir);
    Err(FetchError::NetworkDisabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SAFETY, first tier: the gate accepts only https on the two official hosts.
    #[test]
    fn official_index_gate() {
        assert!(is_official_index(
            "https://pypi.org/pypi/requests/2.31.0/json"
        ));
        assert!(is_official_index(
            "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz"
        ));
        assert!(!is_official_index("http://pypi.org/simple/")); // plaintext
        assert!(!is_official_index("https://pypi.org.evil.invalid/x"));
        assert!(!is_official_index("https://evil.invalid/pypi.org/"));
        assert!(!is_official_index("https://pypi.org@evil.invalid/"));
        assert!(!is_official_index("https://evil.invalid:443@pypi.org")); // userinfo confusion
        assert!(!is_official_index("file:///etc/passwd"));
    }

    // SAFETY: a reference is never a URL or a path, so package contents cannot steer a
    // download.
    #[test]
    fn package_ref_rejects_urls_and_paths() {
        assert!(PackageRef::parse("https://evil.invalid/x.tar.gz").is_err());
        assert!(PackageRef::parse("../x==1.0").is_err());
        assert!(PackageRef::parse("requests").is_err());
        let r = PackageRef::parse("Requests==2.31.0").unwrap();
        assert_eq!(r.name.as_str(), "requests");
        assert_eq!(r.version, "2.31.0");
    }

    // The version is pasted into a URL, so its alphabet is closed.
    #[test]
    fn package_ref_version_alphabet_is_closed() {
        assert!(PackageRef::parse("requests==2.31.0/../x").is_err());
        assert!(PackageRef::parse("requests==2.31.0?x=1").is_err());
        assert!(PackageRef::parse("requests==2.31.0 ").is_err());
        assert!(PackageRef::parse("requests===2.31.0").is_err());
        assert!(PackageRef::parse("requests==").is_err());
        assert!(PackageRef::parse("==1.0").is_err());
        assert!(PackageRef::parse("torch==2.1.0+cu118").is_ok());
        assert!(PackageRef::parse("pkg==1!2.0rc1.post3.dev4").is_ok());
    }

    // SAFETY: PyPI's JSON cannot choose where the file lands.
    #[cfg(feature = "network")]
    #[test]
    fn sdist_file_name_cannot_carry_a_path() {
        use super::network::is_plain_sdist_name;
        assert!(is_plain_sdist_name("requests-2.31.0.tar.gz"));
        assert!(!is_plain_sdist_name("../requests-2.31.0.tar.gz"));
        assert!(!is_plain_sdist_name("a/requests-2.31.0.tar.gz"));
        assert!(!is_plain_sdist_name("a\\requests-2.31.0.tar.gz"));
        assert!(!is_plain_sdist_name("C:requests-2.31.0.tar.gz"));
        assert!(!is_plain_sdist_name(".requests-2.31.0.tar.gz"));
        assert!(!is_plain_sdist_name("requests-2.31.0-py3-none-any.whl"));
    }

    // Live check against PyPI, opt-in: `cargo test -p phylaxis-fetch --features network
    // -- --ignored`. Not part of the suite, which never touches the network.
    #[cfg(feature = "network")]
    #[test]
    #[ignore = "needs the network"]
    fn downloads_a_real_sdist_and_verifies_it() {
        let dir = std::env::temp_dir().join(format!("phylaxis-fetch-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let r = PackageRef::parse("six==1.16.0").unwrap();
        let path = download_sdist(&r, &dir).unwrap();
        assert_eq!(path.file_name().unwrap(), "six-1.16.0.tar.gz");
        assert!(std::fs::metadata(&path).unwrap().len() > 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // SAFETY: without the feature the network is unreachable, by construction.
    #[cfg(not(feature = "network"))]
    #[test]
    fn network_is_unreachable_without_the_feature() {
        assert!(!network_available());
        let r = PackageRef {
            name: PackageName::from_normalized("requests"),
            version: "2.31.0".into(),
        };
        assert!(matches!(
            download_sdist(&r, Path::new(".")),
            Err(FetchError::NetworkDisabled)
        ));
    }
}
