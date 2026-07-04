use crate::audit::now;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The insurance engine.
///
/// Doctrine:
///   - Backups fire BEFORE execution, on enforcement paths only (run, hook).
///   - Never on deny — nothing will execute, nothing needs insuring.
///   - Best-effort: a failed backup is reported, never blocks an approved
///     command. Insurance failing to bind must not cancel the flight.
///   - Every backup is recorded in an append-only manifest, restorable by id.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupRecord {
    pub id: String,
    pub ts: String,
    /// "git-ref" | "pg-dump" | "files"
    pub kind: String,
    /// The command this backup insures against.
    pub command: String,
    /// Kind-specific restore data.
    pub data: serde_json::Value,
    /// Human description of what was saved and how restore works.
    pub note: String,
}

/// What WOULD be backed up for this command — used by previews.
pub fn plan(command: &str) -> Option<String> {
    let segments = crate::shell::split_segments(command);
    if segments.len() > 1 {
        return segments.iter().find_map(|s| plan(s));
    }
    let tokens = crate::pg::shell_tokens(command);
    if let Some((remote, branch)) = git_force_push_target(&tokens) {
        return Some(format!(
            "snapshot {}/{} to a local backup branch before it is overwritten",
            remote, branch
        ));
    }
    if let Some((tables, data_only)) = pg_backup_targets(command) {
        return Some(format!(
            "pg_dump {}{} before execution",
            tables.join(", "),
            if data_only { " (data)" } else { " (schema+data)" }
        ));
    }
    if let Some(paths) = rm_targets(&tokens) {
        return Some(format!(
            "copy {} path(s) to .termaxa/backups before deletion",
            paths.len()
        ));
    }
    if tf_state_target(&tokens).is_some() {
        return Some("copy local terraform.tfstate before apply/destroy (remote state not covered)".into());
    }
    None
}

/// Local terraform state worth insuring? (Remote backends — S3 etc. — are
/// versioned by their own backend and out of scope; we say so in the note.)
fn tf_state_target(tokens: &[String]) -> Option<PathBuf> {
    let bin = tokens.first()?;
    if bin != "terraform" && bin != "tofu" {
        return None;
    }
    let sub = tokens.get(1)?;
    if sub != "apply" && sub != "destroy" {
        return None;
    }
    let state = PathBuf::from("terraform.tfstate");
    if state.exists() { Some(state) } else { None }
}

/// Take the backup. Returns the record on success, a printable error string
/// on a failed attempt, or Ok(None) when the command needs no insurance.
pub fn take(termaxa_dir: &Path, command: &str) -> Result<Option<BackupRecord>> {
    let segments = crate::shell::split_segments(command);
    if segments.len() > 1 {
        for s in &segments {
            if let Some(rec) = take(termaxa_dir, s)? {
                return Ok(Some(rec)); // insure the first insurable segment
            }
        }
        return Ok(None);
    }
    let tokens = crate::pg::shell_tokens(command);
    let (ts_ms, ts) = now();
    let id = format!("b-{}", ts_ms);

    let record = if let Some((remote, branch)) = git_force_push_target(&tokens) {
        backup_git_ref(&id, &ts, command, &remote, &branch)?
    } else if let Some((tables, data_only)) = pg_backup_targets(command) {
        backup_pg(termaxa_dir, &id, &ts, command, &tokens, &tables, data_only)?
    } else if let Some(paths) = rm_targets(&tokens) {
        backup_files(termaxa_dir, &id, &ts, command, &paths)?
    } else if let Some(state) = tf_state_target(&tokens) {
        backup_files(termaxa_dir, &id, &ts, command, &[state])?
    } else {
        return Ok(None);
    };

    append_manifest(termaxa_dir, &record)?;
    Ok(Some(record))
}

// ---------------------------------------------------------------------------
// git: pin the remote ref about to be clobbered by a force push
// ---------------------------------------------------------------------------

fn git_force_push_target(tokens: &[String]) -> Option<(String, String)> {
    if tokens.first().map(|t| t.as_str()) != Some("git") || tokens.get(1).map(|t| t.as_str()) != Some("push") {
        return None;
    }
    let force = tokens.iter().any(|t| t == "--force" || t == "-f" || t == "--force-with-lease");
    if !force {
        return None;
    }
    let positional: Vec<&String> = tokens[2..].iter().filter(|t| !t.starts_with('-')).collect();
    let remote = positional.first().map(|s| s.to_string()).unwrap_or_else(|| "origin".into());
    let branch = positional
        .get(1)
        .map(|s| s.to_string())
        .or_else(current_branch)
        .unwrap_or_else(|| "main".into());
    Some((remote, branch))
}

fn backup_git_ref(id: &str, ts: &str, command: &str, remote: &str, branch: &str) -> Result<BackupRecord> {
    // Best effort: refresh our view of the remote first.
    let _ = Command::new("git").args(["fetch", remote, branch]).output();
    let sha = git_out(&["rev-parse", &format!("{}/{}", remote, branch)])
        .context("cannot resolve remote branch — is it pushed?")?;
    let backup_branch = format!("termaxa/backup/{}", id);
    let out = Command::new("git").args(["branch", &backup_branch, &sha]).output()?;
    if !out.status.success() {
        bail!("git branch failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(BackupRecord {
        id: id.into(),
        ts: ts.into(),
        kind: "git-ref".into(),
        command: command.into(),
        data: serde_json::json!({ "branch": backup_branch, "sha": sha, "remote": remote, "target": branch }),
        note: format!("{}/{} @ {} pinned to {}", remote, branch, &sha[..8.min(sha.len())], backup_branch),
    })
}

// ---------------------------------------------------------------------------
// postgres: pg_dump the tables a destructive statement targets
// ---------------------------------------------------------------------------

/// (tables to dump, data_only). data_only when the table itself survives
/// (TRUNCATE/DELETE) — restoring is then just refilling rows. Full dump with
/// --clean only for DROP, where the table must be recreated. CASCADE
/// truncates also empty FK dependents, so those join the dump list: the
/// insurance must cover the same blast radius the preview measures.
fn pg_backup_targets(command: &str) -> Option<(Vec<String>, bool)> {
    let tokens = crate::pg::shell_tokens(command);
    if tokens.first().map(|t| t.ends_with("psql")) != Some(true) {
        return None;
    }
    let sql = tokens
        .iter()
        .position(|t| t == "-c" || t == "--command")
        .and_then(|i| tokens.get(i + 1))?;
    let mut tables = Vec::new();
    let mut any_drop = false;
    for stmt in crate::pg::parse_destructive(sql) {
        match stmt {
            crate::pg::Destructive::DropTable { tables: t, .. } => {
                any_drop = true;
                tables.extend(t);
            }
            crate::pg::Destructive::Truncate { tables: t, cascade } => {
                if cascade {
                    for table in &t {
                        tables.extend(crate::pg::fk_dependents(command, table));
                    }
                }
                tables.extend(t);
            }
            crate::pg::Destructive::DeleteFrom { table, .. } => tables.push(table),
        }
    }
    tables.dedup();
    if tables.is_empty() {
        None
    } else {
        Some((tables, !any_drop))
    }
}

fn backup_pg(
    termaxa_dir: &Path,
    id: &str,
    ts: &str,
    command: &str,
    tokens: &[String],
    tables: &[String],
    data_only: bool,
) -> Result<BackupRecord> {
    let dir = backups_dir(termaxa_dir)?;
    let file = dir.join(format!("{}-pg.sql", id));

    // Reuse the psql connection args verbatim; swap the binary for pg_dump.
    let mut args: Vec<String> = crate::pg::strip_command_flag(tokens)[1..].to_vec();
    for t in tables {
        args.push("-t".into());
        args.push(t.clone());
    }
    if data_only {
        args.push("--data-only".into());
    } else {
        args.extend(["--clean", "--if-exists"].iter().map(|s| s.to_string()));
    }
    args.push("-f".into());
    args.push(file.display().to_string());

    let out = Command::new("pg_dump")
        .args(&args)
        .env("PGCONNECT_TIMEOUT", "5")
        .output()
        .context("pg_dump not found on PATH — cannot insure this operation")?;
    if !out.status.success() {
        bail!("pg_dump failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let conn: Vec<String> = crate::pg::strip_command_flag(tokens);
    Ok(BackupRecord {
        id: id.into(),
        ts: ts.into(),
        kind: "pg-dump".into(),
        command: command.into(),
        data: serde_json::json!({ "file": file.display().to_string(), "tables": tables, "conn": conn }),
        note: format!("pg_dump {} → {}", tables.join(", "), file.display()),
    })
}

// ---------------------------------------------------------------------------
// rm: copy targets aside before deletion
// ---------------------------------------------------------------------------

fn rm_targets(tokens: &[String]) -> Option<Vec<PathBuf>> {
    if tokens.first().map(|t| t.as_str()) != Some("rm") {
        return None;
    }
    let paths: Vec<PathBuf> = tokens[1..]
        .iter()
        .filter(|t| !t.starts_with('-'))
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

fn backup_files(termaxa_dir: &Path, id: &str, ts: &str, command: &str, paths: &[PathBuf]) -> Result<BackupRecord> {
    let dir = backups_dir(termaxa_dir)?.join(id);
    fs::create_dir_all(&dir)?;
    let mut saved = Vec::new();
    for p in paths {
        let name = p.file_name().map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "item".into());
        let dest = dir.join(&name);
        copy_recursive(p, &dest)?;
        saved.push(serde_json::json!({
            "original": p.canonicalize().unwrap_or_else(|_| p.clone()).display().to_string(),
            "saved_as": dest.display().to_string(),
        }));
    }
    Ok(BackupRecord {
        id: id.into(),
        ts: ts.into(),
        kind: "files".into(),
        command: command.into(),
        data: serde_json::json!({ "items": saved }),
        note: format!("{} path(s) copied to {}", paths.len(), dir.display()),
    })
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

// ---------------------------------------------------------------------------
// manifest + restore
// ---------------------------------------------------------------------------

fn backups_dir(termaxa_dir: &Path) -> Result<PathBuf> {
    let dir = termaxa_dir.join("backups");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn append_manifest(termaxa_dir: &Path, record: &BackupRecord) -> Result<()> {
    let path = backups_dir(termaxa_dir)?.join("manifest.jsonl");
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(record)?)?;
    Ok(())
}

pub fn list(termaxa_dir: &Path) -> Result<Vec<BackupRecord>> {
    let path = backups_dir(termaxa_dir)?.join("manifest.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

/// Restore a backup by id. `confirm` is the caller's y/N gate result —
/// restores are writes and get the same respect as any other write.
pub fn restore(termaxa_dir: &Path, id: &str) -> Result<String> {
    let record = list(termaxa_dir)?
        .into_iter()
        .find(|r| r.id == id)
        .with_context(|| format!("no backup with id `{}` — see `termaxa backups`", id))?;

    match record.kind.as_str() {
        "git-ref" => {
            let sha = record.data["sha"].as_str().context("bad record")?;
            let remote = record.data["remote"].as_str().context("bad record")?;
            let target = record.data["target"].as_str().context("bad record")?;
            let refspec = format!("{}:refs/heads/{}", sha, target);
            let out = Command::new("git")
                .args(["push", "--force", remote, &refspec])
                .output()?;
            if !out.status.success() {
                bail!("restore push failed: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
            Ok(format!("{}/{} restored to {}", remote, target, &sha[..8.min(sha.len())]))
        }
        "pg-dump" => {
            let file = record.data["file"].as_str().context("bad record")?;
            let conn: Vec<String> = record.data["conn"]
                .as_array()
                .context("bad record")?
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            let mut args: Vec<String> = conn[1..].to_vec();
            args.extend(["-v", "ON_ERROR_STOP=1", "-f"].iter().map(|s| s.to_string()));
            args.push(file.to_string());
            let out = Command::new(&conn[0]).args(&args).output()?;
            if !out.status.success() {
                bail!("psql restore failed: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
            Ok(format!("restored from {}", file))
        }
        "files" => {
            let items = record.data["items"].as_array().context("bad record")?;
            let mut n = 0;
            for item in items {
                let original = PathBuf::from(item["original"].as_str().context("bad record")?);
                let saved = PathBuf::from(item["saved_as"].as_str().context("bad record")?);
                copy_recursive(&saved, &original)?;
                n += 1;
            }
            Ok(format!("{} path(s) restored to original locations", n))
        }
        other => bail!("unknown backup kind `{}`", other),
    }
}

fn current_branch() -> Option<String> {
    git_out(&["rev-parse", "--abbrev-ref", "HEAD"])
}

fn git_out(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
