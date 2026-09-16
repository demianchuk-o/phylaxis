//! SHA-256 of a distribution file: the immutable identity behind the cache key
//! (invariant 6; DECISIONS.md, ADR-017).

use std::io::Read;
use std::path::Path;

use phylaxis_core::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::error::ParseError;

pub fn sha256_of_bytes(bytes: &[u8]) -> Sha256Digest {
    let out = Sha256::digest(bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Sha256Digest(arr)
}

/// Streams the file; never loads a multi-hundred-megabyte sdist into memory just to hash it.
///
/// WHY the whole file and not a prefix: this digest is the cache key and the identity of the
/// artefact (invariant 6). A prefix would let two distributions sharing a header collide, and
/// a collision here does not mean a slow lookup -- it means serving one package's verdict for
/// another's bytes.
pub fn sha256_of_file(path: &Path) -> Result<Sha256Digest, ParseError> {
    let file = std::fs::File::open(path).map_err(|source| ParseError::Io {
        path: path.to_owned(),
        source,
    })?;
    // An explicit chunk loop rather than `io::copy`: `Sha256` only implements `io::Write`
    // when `sha2`'s `std` feature is on, and a hash function is not worth a feature flag.
    // 64 KiB is large enough that the syscall cost disappears and small enough to stay off
    // the stack-sized end of the allocator.
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|source| ParseError::Io {
            path: path.to_owned(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(Sha256Digest(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The well-known digest of the empty input pins the algorithm and the encoding.
    #[test]
    fn sha256_of_empty_input_is_the_known_constant() {
        assert_eq!(
            sha256_of_bytes(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc() {
        assert_eq!(
            sha256_of_bytes(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
