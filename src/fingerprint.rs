//! Policy fingerprinting — so that a change to the gate's own configuration
//! is *visible* rather than silent.
//!
//! Why this exists: policy rules gate **shell commands**. An agent's
//! file-writing tool (Claude Code's `Write`/`Edit`, Cursor's edit apply)
//! never reaches the hook at all — the Claude Code hook is registered with
//! `"matcher": "Bash"` — so no deny rule can stop `.termaxa/policy.yaml`
//! being rewritten that way. Blocking it is out of reach. Noticing it is not.
//!
//! Where the baseline lives is load-bearing: the per-project state dir under
//! `$TERMAXA_HOME` (`~/.termaxa/projects/<key>/`), deliberately NOT inside
//! `.termaxa/`. A baseline that lives in the directory it protects is erased
//! by the same clobber it exists to catch.
//!
//! Honesty rules, same as `doctor`'s: this reports that the bytes differ from
//! the ones `termaxa init` last recorded. It does not claim to know who
//! changed them or why, and it cannot see a change made before the first
//! baseline was recorded.
//!
//! SHA-256 is implemented here rather than pulled in as a dependency: the
//! crate has seven, and this is ~70 lines with published test vectors. A
//! fingerprint people paste into an issue should be a real digest — the
//! existing `fnv1a_hex8` in `paths.rs` is the right tool for a directory key
//! and the wrong one for "did my security policy change".

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What `termaxa init` recorded, and when.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub sha256: String,
    pub recorded: String,
}

/// The baseline lives in the state dir, outside the project.
pub fn baseline_file(state_dir: &Path) -> PathBuf {
    state_dir.join("policy.fingerprint")
}

/// Fingerprint a file. `None` if it cannot be read — absence is reported by
/// the caller, never guessed at.
pub fn of_file(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|b| sha256_hex(&b))
}

pub fn read_baseline(state_dir: &Path) -> Option<Baseline> {
    let raw = std::fs::read_to_string(baseline_file(state_dir)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Record (or re-record) the baseline. Only ever called from `init` —
/// `doctor` observes and must not create state.
pub fn record(state_dir: &Path, sha256: &str) -> Result<()> {
    let (_ms, ts) = crate::audit::now();
    let baseline = Baseline {
        sha256: sha256.to_string(),
        recorded: ts,
    };
    if let Some(parent) = baseline_file(state_dir).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        baseline_file(state_dir),
        serde_json::to_string_pretty(&baseline)?,
    )?;
    Ok(())
}

/// Display form: enough to compare by eye, short enough to sit in a report.
pub fn short(sha256: &str) -> String {
    sha256.chars().take(12).collect()
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), no dependencies
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pad: 0x80, zeroes to 56 mod 64, then the length in bits, big-endian.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let b = &chunk[i * 4..i * 4 + 4];
            *word = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }

    h.iter().map(|x| format!("{:08x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_published_vectors() {
        // FIPS 180-4 / NIST examples.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Multi-block, exercises the length field past one chunk.
        assert_eq!(
            sha256_hex(&[b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        // 55/56/57 bytes: the padding boundaries, where an off-by-one in the
        // "zeroes to 56 mod 64" loop would show up.
        assert_ne!(sha256_hex(&[b'x'; 55]), sha256_hex(&[b'x'; 56]));
        assert_ne!(sha256_hex(&[b'x'; 56]), sha256_hex(&[b'x'; 57]));
    }

    #[test]
    fn one_changed_byte_changes_the_fingerprint() {
        let before = sha256_hex(b"version: 1\ndefault: ask\n");
        let after = sha256_hex(b"version: 1\ndefault: allow\n");
        assert_ne!(before, after);
        assert_eq!(short(&before).len(), 12);
    }

    #[test]
    fn baseline_roundtrips_through_the_state_dir() {
        let dir = std::env::temp_dir().join(format!("tmx-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(
            read_baseline(&dir).is_none(),
            "no baseline yet must read as absent, not as a match"
        );

        record(&dir, "deadbeef").unwrap();
        let got = read_baseline(&dir).expect("baseline should read back");
        assert_eq!(got.sha256, "deadbeef");
        assert!(!got.recorded.is_empty(), "a baseline records when, too");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_baseline_does_not_live_in_the_directory_it_protects() {
        // The whole point: a clobber of `.termaxa/` must not take the
        // evidence with it.
        let state = Path::new("/home/u/.termaxa/projects/proj-abc12345");
        let f = baseline_file(state);
        assert!(f.starts_with(state));
        assert!(
            !f.to_string_lossy().contains("/proj/.termaxa/"),
            "baseline must not sit next to policy.yaml: {}",
            f.display()
        );
    }

    #[test]
    fn of_file_reports_absence_rather_than_guessing() {
        let missing = std::env::temp_dir().join("tmx-fp-definitely-not-here.yaml");
        let _ = std::fs::remove_file(&missing);
        assert!(of_file(&missing).is_none());
    }
}
