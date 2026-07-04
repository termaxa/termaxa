use crate::policy::Policy;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Where things live — the v0.8 split, written in scar tissue.
///
/// Field report, v0.6: `.aegis/` lived inside the governed repo, so a
/// `git reset --hard` reverted the policy and ATE THE AUDIT LOG — twice.
/// Runtime state has no business living inside the repo it protects.
///
///   - `policy.yaml`  → stays in-repo (`<project>/.aegis/`): it is
///     configuration, reviewable in PRs, policy-as-code.
///   - logs + backups → `~/.aegis/projects/<name>-<hash8>/`: runtime state,
///     outside every repo, untouchable by any git operation BY CONSTRUCTION.
pub struct Paths {
    /// The in-repo `.aegis/` directory (holds policy.yaml).
    pub project_dir: PathBuf,
    /// Home-directory state root for this project (holds logs/, backups/).
    pub state_dir: PathBuf,
}

impl Paths {
    pub fn policy_file(&self) -> PathBuf {
        self.project_dir.join("policy.yaml")
    }
}

/// Resolve paths for the current project, creating state dirs and running
/// one-time migration of any legacy in-repo state.
pub fn resolve() -> Result<Paths> {
    let cwd = std::env::current_dir()?;
    let Some(policy_file) = Policy::find_policy_file(&cwd) else {
        bail!("no .aegis/policy.yaml found in this directory or any parent — run `aegis init` first");
    };
    let project_dir = policy_file.parent().unwrap().to_path_buf();
    let project_root = project_dir.parent().unwrap_or(&project_dir).to_path_buf();

    let state_dir = state_dir_for(&project_root)?;
    fs::create_dir_all(state_dir.join("logs"))?;
    fs::create_dir_all(state_dir.join("backups"))?;

    migrate_legacy_state(&project_dir, &state_dir)?;

    Ok(Paths { project_dir, state_dir })
}

/// `$AEGIS_HOME` (tests, custom setups) or `~/.aegis`.
fn home_base() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("AEGIS_HOME") {
        if !custom.trim().is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }
    let home = std::env::var("USERPROFILE") // Windows
        .or_else(|_| std::env::var("HOME")) // Unix
        .context("cannot locate home directory (USERPROFILE/HOME unset)")?;
    Ok(PathBuf::from(home).join(".aegis"))
}

fn state_dir_for(project_root: &Path) -> Result<PathBuf> {
    let canonical = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
    let name = canonical
        .file_name()
        .map(|n| sanitize(&n.to_string_lossy()))
        .unwrap_or_else(|| "project".into());
    let key = format!("{}-{}", name, fnv1a_hex8(&canonical.to_string_lossy()));
    Ok(home_base()?.join("projects").join(key))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// FNV-1a, 64-bit, hex-truncated to 8 chars — stable, dependency-free,
/// collision-resistant enough to disambiguate same-named project folders.
fn fnv1a_hex8(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", (h >> 32) as u32 ^ h as u32)
}

/// One-time migration of pre-v0.8 in-repo state.
///
/// Backup manifest records contain ABSOLUTE paths to their payloads
/// (pg_dump files, saved file copies). Moving payloads without rewriting
/// those paths would make `aegis rollback` a liar — so every string in
/// every record gets the old-prefix → new-prefix rewrite.
fn migrate_legacy_state(project_dir: &Path, state_dir: &Path) -> Result<()> {
    let mut migrated = false;

    // 1. audit log: append old lines to the home log, remove the original.
    let old_log = project_dir.join("logs").join("audit.jsonl");
    if old_log.is_file() {
        let content = fs::read_to_string(&old_log)?;
        let new_log = state_dir.join("logs").join("audit.jsonl");
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&new_log)?;
        use std::io::Write;
        f.write_all(content.as_bytes())?;
        fs::remove_file(&old_log)?;
        let _ = fs::remove_dir(project_dir.join("logs")); // only if now empty
        migrated = true;
    }

    // 2. backups: move payloads, rewrite manifest paths.
    let old_backups = project_dir.join("backups");
    if old_backups.is_dir() {
        let new_backups = state_dir.join("backups");
        let old_prefix = old_backups.to_string_lossy().to_string();
        let new_prefix = new_backups.to_string_lossy().to_string();

        for entry in fs::read_dir(&old_backups)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "manifest.jsonl" {
                continue; // handled below
            }
            move_path(&entry.path(), &new_backups.join(&name))?;
        }

        let old_manifest = old_backups.join("manifest.jsonl");
        if old_manifest.is_file() {
            let new_manifest = new_backups.join("manifest.jsonl");
            let mut out = String::new();
            for line in fs::read_to_string(&old_manifest)?.lines() {
                match serde_json::from_str::<serde_json::Value>(line) {
                    Ok(mut v) => {
                        rewrite_strings(&mut v, &old_prefix, &new_prefix);
                        out.push_str(&serde_json::to_string(&v)?);
                        out.push('\n');
                    }
                    Err(_) => {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
            }
            use std::io::Write;
            let mut f = fs::OpenOptions::new().create(true).append(true).open(&new_manifest)?;
            f.write_all(out.as_bytes())?;
            fs::remove_file(&old_manifest)?;
        }
        let _ = fs::remove_dir(&old_backups);
        migrated = true;
    }

    if migrated {
        eprintln!("aegis: migrated legacy in-repo state to {}", state_dir.display());
    }
    Ok(())
}

/// Recursively rewrite a path prefix in every string of a JSON value.
fn rewrite_strings(v: &mut serde_json::Value, old: &str, new: &str) {
    match v {
        serde_json::Value::String(s) => {
            if s.starts_with(old) {
                *s = format!("{}{}", new, &s[old.len()..]);
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| rewrite_strings(x, old, new)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| rewrite_strings(x, old, new)),
        _ => {}
    }
}

/// rename, falling back to copy+delete (cross-device / cross-drive safe).
fn move_path(src: &Path, dst: &Path) -> Result<()> {
    if fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    copy_recursive(src, dst)?;
    if src.is_dir() {
        fs::remove_dir_all(src)?;
    } else {
        fs::remove_file(src)?;
    }
    Ok(())
}

fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    if src.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_distinguishes() {
        assert_eq!(fnv1a_hex8("/a/b/project"), fnv1a_hex8("/a/b/project"));
        assert_ne!(fnv1a_hex8("/a/b/project"), fnv1a_hex8("/c/d/project"));
    }

    #[test]
    fn sanitize_keeps_names_readable() {
        assert_eq!(sanitize("aegis-demo"), "aegis-demo");
        assert_eq!(sanitize("my proj (v2)"), "my_proj__v2_");
    }

    #[test]
    fn rewrite_walks_nested_json() {
        let mut v: serde_json::Value = serde_json::json!({
            "file": "/old/backups/b-1-pg.sql",
            "items": [{"saved_as": "/old/backups/b-1/x.txt"}],
            "count": 3
        });
        rewrite_strings(&mut v, "/old/backups", "/new/backups");
        assert_eq!(v["file"], "/new/backups/b-1-pg.sql");
        assert_eq!(v["items"][0]["saved_as"], "/new/backups/b-1/x.txt");
    }
}
