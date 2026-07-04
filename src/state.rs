use std::path::{Path, PathBuf};

/// Home-directory state resolution (v0.8).
///
/// The scar this heals: runtime state (audit log, backups) used to live in
/// `<repo>/.aegis/`, inside the repository it was protecting — and a
/// `git reset --hard` across the right commits ate the audit log. Twice,
/// in one live session.
///
/// The split, by design:
///   - `policy.yaml` STAYS in-repo: it is policy-as-code, reviewable in PRs,
///     versioned with the project it governs.
///   - logs + backups MOVE to `~/.aegis/projects/<key>/`: evidence lives
///     with the user, outside the reach of any git operation, by
///     construction rather than by discipline.
///
/// Resolution order for the base: $AEGIS_HOME, else $HOME, else
/// %USERPROFILE% (Windows), else fall back to the legacy in-repo location
/// so Aegis still works in home-less environments (containers, CI).
pub fn home_base() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("AEGIS_HOME") {
        if !h.trim().is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    if home.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".aegis"))
}

/// The project root is the parent of its `.aegis/` directory.
pub fn project_root(aegis_dir: &Path) -> PathBuf {
    aegis_dir.parent().unwrap_or(aegis_dir).to_path_buf()
}

/// Where this project's runtime state lives.
/// Key = sanitized folder name + short hash of the full canonical path:
/// human-navigable, collision-proof, stable across runs.
pub fn state_dir(aegis_dir: &Path) -> PathBuf {
    let Some(base) = home_base() else {
        return aegis_dir.to_path_buf(); // legacy fallback: in-repo
    };
    let root = project_root(aegis_dir);
    let canon = root.canonicalize().unwrap_or_else(|_| root.clone());
    let name: String = canon
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".into())
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let key = format!("{}-{:08x}", name, fnv1a(canon.to_string_lossy().as_bytes()));
    base.join("projects").join(key)
}

/// FNV-1a, 32-bit — tiny, dependency-free, stable.
fn fnv1a(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_and_sanitized() {
        std::env::set_var("AEGIS_HOME", "/tmp/aegis-home-test");
        let a = state_dir(Path::new("/tmp/some project!/.aegis"));
        let b = state_dir(Path::new("/tmp/some project!/.aegis"));
        assert_eq!(a, b, "same input, same key");
        let name = a.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("some-project--"), "sanitized: {}", name);
        assert!(!name.contains(' ') && !name.contains('!'));
        std::env::remove_var("AEGIS_HOME");
    }

    #[test]
    fn different_paths_different_keys() {
        std::env::set_var("AEGIS_HOME", "/tmp/aegis-home-test");
        let a = state_dir(Path::new("/tmp/proj-a/app/.aegis"));
        let b = state_dir(Path::new("/tmp/proj-b/app/.aegis"));
        assert_ne!(a, b, "same folder name, different path, different key");
        std::env::remove_var("AEGIS_HOME");
    }

    #[test]
    fn fnv_known_value() {
        assert_eq!(fnv1a(b""), 0x811c_9dc5);
    }
}
