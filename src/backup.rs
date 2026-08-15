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
/// Takes an explicit `cwd` because it filters candidate paths by `exists()`:
/// resolved against the wrong directory, an insurable command reports as
/// uninsurable and the preview tells a human "not reversible without a
/// backup" about a file that would in fact be copied aside. A preview whose
/// lines are meant to be facts cannot resolve against the process cwd.
pub fn plan(command: &str, cwd: &Path) -> Option<String> {
    let segments = crate::shell::split_segments(command);
    if segments.len() > 1 {
        return segments.iter().find_map(|s| plan(s, cwd));
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
            if data_only {
                " (data)"
            } else {
                " (schema+data)"
            }
        ));
    }
    if let Some(paths) = rm_targets(&tokens, cwd) {
        return Some(format!(
            "copy {} path(s) to .termaxa/backups before deletion",
            paths.len()
        ));
    }
    if tf_state_target(&tokens).is_some() {
        return Some(
            "copy local terraform.tfstate before apply/destroy (remote state not covered)".into(),
        );
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
    if state.exists() {
        Some(state)
    } else {
        None
    }
}

/// Take the backup. Returns the record on success, a printable error string
/// on a failed attempt, or Ok(None) when the command needs no insurance.
pub fn take(termaxa_dir: &Path, command: &str, cwd: &Path) -> Result<Option<BackupRecord>> {
    let segments = crate::shell::split_segments(command);
    if segments.len() > 1 {
        for s in &segments {
            if let Some(rec) = take(termaxa_dir, s, cwd)? {
                return Ok(Some(rec)); // insure the first insurable segment
            }
        }
        return Ok(None);
    }
    let redirects = segments
        .into_iter()
        .next()
        .map(|s| s.redirects)
        .unwrap_or_default();
    let tokens = crate::pg::shell_tokens(command);
    let (ts_ms, ts) = now();
    let id = format!("b-{}", ts_ms);

    let record = if let Some((remote, branch)) = git_force_push_target(&tokens) {
        backup_git_ref(&id, &ts, command, &remote, &branch)?
    } else if let Some((tables, data_only)) = pg_backup_targets(command) {
        backup_pg(termaxa_dir, &id, &ts, command, &tokens, &tables, data_only)?
    } else if let Some(paths) = rm_targets(&tokens, cwd) {
        backup_files(termaxa_dir, &id, &ts, command, &paths)?
    } else if let Some(state) = tf_state_target(&tokens) {
        backup_files(termaxa_dir, &id, &ts, command, &[state])?
    } else if let Some(paths) = overwrite_paths(&redirects, cwd) {
        backup_files(termaxa_dir, &id, &ts, command, &paths)?
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
    if tokens.first().map(|t| t.as_str()) != Some("git")
        || tokens.get(1).map(|t| t.as_str()) != Some("push")
    {
        return None;
    }
    let force = tokens
        .iter()
        .any(|t| t == "--force" || t == "-f" || t == "--force-with-lease");
    if !force {
        return None;
    }
    let positional: Vec<&String> = tokens[2..].iter().filter(|t| !t.starts_with('-')).collect();
    let remote = positional
        .first()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "origin".into());
    let branch = positional
        .get(1)
        .map(|s| s.to_string())
        .or_else(current_branch)
        .unwrap_or_else(|| "main".into());
    Some((remote, branch))
}

fn backup_git_ref(
    id: &str,
    ts: &str,
    command: &str,
    remote: &str,
    branch: &str,
) -> Result<BackupRecord> {
    // Best effort: refresh our view of the remote first.
    let _ = Command::new("git").args(["fetch", remote, branch]).output();
    let sha = git_out(&["rev-parse", &format!("{}/{}", remote, branch)])
        .context("cannot resolve remote branch — is it pushed?")?;
    let backup_branch = format!("termaxa/backup/{}", id);
    let out = Command::new("git")
        .args(["branch", &backup_branch, &sha])
        .output()?;
    if !out.status.success() {
        bail!(
            "git branch failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(BackupRecord {
        id: id.into(),
        ts: ts.into(),
        kind: "git-ref".into(),
        command: command.into(),
        data: serde_json::json!({ "branch": backup_branch, "sha": sha, "remote": remote, "target": branch }),
        note: format!(
            "{}/{} @ {} pinned to {}",
            remote,
            branch,
            &sha[..8.min(sha.len())],
            backup_branch
        ),
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

    // Take ONLY the connection parameters, rebuilt (see pg::connection_args).
    // Copying the psql argv verbatim used to void insurance silently: psql's
    // `-t` is pg_dump's `--table`, and `-X`/`-A`/`-1` are not pg_dump options,
    // so pg_dump exited non-zero, `take` returned Err, and `hook` ignores Err.
    // `psql -X -d shop -c "TRUNCATE users"` got no backup while the same
    // command without `-X` did.
    let mut args: Vec<String> = crate::pg::connection_args(tokens);
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
        bail!(
            "pg_dump failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let conn: Vec<String> = crate::pg::connection_args(tokens);
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

/// Paths a delete command would destroy, resolved to real filesystem paths.
///
/// Two bugs lived in the previous version, both surfaced when the v0.14 delete
/// preview and this function disagreed about the same command:
///
///   1. It built paths with `PathBuf::from(token)`, so a Git Bash form like
///      `/c/Users/x/Desktop` never passed `.exists()` on Windows and the
///      command silently got NO insurance — while the identical target written
///      `C:\Users\x\Desktop` was fully backed up. Path syntax must never
///      decide whether a safety net exists.
///   2. It matched only `rm`, so PowerShell and cmd deletes were uninsured
///      even though the classifier and the policy both recognise them.
///
/// Everything here routes through `crate::delete` — the same resolution and
/// the same per-shell flag rules the preview uses — so the two engines cannot
/// disagree about what a command targets.
/// Files a truncating redirect is about to write over.
///
/// v0.15, #14. `cat /dev/null > .env` destroys a file without deleting
/// anything, so `rm_targets` never saw it and no backup was taken. Insurance is
/// the same mechanism as for a delete — copy aside first — because the outcome
/// is the same: the contents are gone.
///
/// v0.16 §1.5: consumes the redirects the segment arrived with, from the same
/// split every other engine reads. Until now this function re-scanned its
/// input string — the one caller that computed redirects from something other
/// than a split segment, which is exactly how two engines start disagreeing
/// about what a command targets (decision #37).
///
/// Only files that already EXIST are insurable. `> newfile` creates rather than
/// destroys, and backing up a path with no contents is noise in the manifest.
/// Appends (`>>`) are excluded here by `Overwrite::truncates`.
fn overwrite_paths(redirects: &[crate::shell::Overwrite], cwd: &Path) -> Option<Vec<PathBuf>> {
    let paths: Vec<PathBuf> = redirects
        .iter()
        .filter(|o| o.truncates)
        .map(|o| crate::delete::resolve_path_in(&o.target, cwd))
        .filter(|p| p.is_file())
        .collect();
    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

fn rm_targets(tokens: &[String], cwd: &Path) -> Option<Vec<PathBuf>> {
    // Same head resolution the classifier and the preview use. When these
    // disagreed, a command could be CLASSIFIED destructive and take no
    // insurance - gated without a net, which is worse than missing both.
    let (head, at) = crate::delete::resolve_head(tokens)?;
    if !crate::delete::is_delete_command(&head) {
        return None;
    }
    let paths: Vec<PathBuf> = tokens[at + 1..]
        .iter()
        .filter(|t| !crate::delete::is_flag(&head, t))
        .map(|t| crate::delete::resolve_path_in(t, cwd))
        .filter(|p| p.exists())
        .collect();
    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

fn backup_files(
    termaxa_dir: &Path,
    id: &str,
    ts: &str,
    command: &str,
    paths: &[PathBuf],
) -> Result<BackupRecord> {
    let dir = backups_dir(termaxa_dir)?.join(id);
    fs::create_dir_all(&dir)?;
    let mut saved = Vec::new();
    for p in paths {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
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
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
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
                bail!(
                    "restore push failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Ok(format!(
                "{}/{} restored to {}",
                remote,
                target,
                &sha[..8.min(sha.len())]
            ))
        }
        "pg-dump" => {
            let file = record.data["file"].as_str().context("bad record")?;
            // Derive the connection from the ORIGINAL command every time,
            // through the same allowlist used to take the backup. Two reasons:
            // the stored `conn` of a pre-0.14.1 record is the user's raw argv,
            // which would carry `-f`/`-o` into this psql call; and indexing
            // conn[0]/conn[1..] panicked on an empty array.
            let tokens = crate::pg::shell_tokens(&record.command);
            let prog = crate::pg::psql_program(&tokens).unwrap_or_else(|| "psql".to_string());
            let mut args: Vec<String> = crate::pg::connection_args(&tokens);
            args.extend(
                ["-w", "-X", "-v", "ON_ERROR_STOP=1", "-f"]
                    .iter()
                    .map(|s| s.to_string()),
            );
            args.push(file.to_string());
            let out = Command::new(&prog).args(&args).output()?;
            if !out.status.success() {
                bail!(
                    "psql restore failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
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
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests resolve against the process cwd deliberately: they build their
    /// fixtures with absolute paths, so the base is irrelevant to them. The
    /// point of the parameter is that PRODUCTION never uses this.
    fn test_cwd() -> std::path::PathBuf {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    }
    /// #14. The insurance half: an overwrite that is not denied must still be
    /// recoverable, because "agents write files constantly" is exactly why the
    /// gate cannot ask about every one.
    #[test]
    fn an_existing_file_about_to_be_overwritten_is_insurable() {
        let tmp = crate::testutil::TempTree::new("bk-ow");
        let dir = tmp.path();
        let target = dir.join("config.json");
        std::fs::write(&target, "original contents").unwrap();

        let cmd = format!("echo {{}} > {}", target.display());
        let found =
            overwrite_targets(&cmd, &test_cwd()).expect("an existing file must be insurable");
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("config.json"));
    }

    /// Creating a file destroys nothing, and appending destroys nothing.
    /// Backing either up is noise in the manifest.
    #[test]
    fn creating_or_appending_is_not_insurable() {
        let tmp = crate::testutil::TempTree::new("bk-ow2");
        let dir = tmp.path();
        let existing = dir.join("app.log");
        std::fs::write(&existing, "log").unwrap();

        assert!(
            overwrite_targets(
                &format!("echo x > {}", dir.join("brand-new.txt").display()),
                &test_cwd(),
            )
            .is_none(),
            "> onto a path that does not exist creates rather than destroys"
        );
        assert!(
            overwrite_targets(&format!("echo x >> {}", existing.display()), &test_cwd()).is_none(),
            ">> appends"
        );
    }

    use crate::testutil::TempTree;

    /// The old `overwrite_targets(command, cwd)` shape, for tests: split the
    /// command as production now does and hand the first segment's redirects
    /// to `overwrite_paths`.
    fn overwrite_targets(command: &str, cwd: &Path) -> Option<Vec<PathBuf>> {
        let redirects = crate::shell::split_segments(command)
            .into_iter()
            .next()
            .map(|s| s.redirects)
            .unwrap_or_default();
        overwrite_paths(&redirects, cwd)
    }

    /// A real temp directory containing one file. The guard is returned with
    /// it: dropping it removes the tree, so the caller has to keep it alive
    /// for as long as the path is used.
    fn scratch(tag: &str) -> (TempTree, PathBuf) {
        let tmp = TempTree::new(&format!("bk-{tag}"));
        tmp.file("f.txt", "x");
        let dir = tmp.path().to_path_buf();
        (tmp, dir)
    }

    #[test]
    fn path_syntax_does_not_decide_whether_insurance_exists() {
        // The v0.14 bug: `/c/Users/x/Desktop` got no backup while the
        // identical target written `C:\Users\x\Desktop` did. The case where
        // insurance mattered most was the one silently without it.
        let (_tmp, dir) = scratch("syntax");
        let win = dir.display().to_string();
        let planned_win = plan(&format!("rm -rf {}", win), &test_cwd()).is_some();
        assert!(planned_win, "an existing path must be insurable: {win}");

        #[cfg(windows)]
        {
            // C:\Users\x\tmp  ->  /c/Users/x/tmp
            let bash = format!("/{}", win.replacen(':', "", 1).replace('\\', "/"));
            assert_eq!(
                plan(&format!("rm -rf {}", bash), &test_cwd()).is_some(),
                planned_win,
                "git-bash form must reach the same decision, got none for {bash}"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn powershell_and_cmd_deletes_are_insurable_too() {
        // Previously only `rm` was matched, so every PowerShell and cmd delete
        // ran uninsured even though policy and the classifier both gate them.
        let (_tmp, dir) = scratch("shells");
        let p = dir.display().to_string();

        assert!(plan(&format!("Remove-Item -Recurse -Force {}", p), &test_cwd()).is_some());
        assert!(plan(&format!("del /s /q {}", p), &test_cwd()).is_some());
        assert!(plan(&format!("rmdir /s {}", p), &test_cwd()).is_some());
        assert!(plan(&format!("rm -rf {}", p), &test_cwd()).is_some());

        // Non-deletes stay uninsured.
        assert!(plan("git status", &test_cwd()).is_none());
        assert!(plan(&format!("ls -la {}", p), &test_cwd()).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    /// v0.16 item 1, the whole point of the parameter: a hook runs in
    /// whatever directory the harness spawned it in, which is NOT the
    /// directory the agent's command runs in. Before this, a relative target
    /// resolved against the process cwd, found nothing, and took NO BACKUP —
    /// silently, because "no such file" and "nothing to insure" are the same
    /// answer. Both target kinds are covered: rm targets and redirect
    /// overwrite targets.
    #[test]
    fn the_payload_cwd_governs_resolution_not_the_process_cwd() {
        let tmp = TempTree::new("payload-cwd");
        let project = tmp.dir("project");
        let elsewhere = tmp.dir("elsewhere");
        std::fs::write(project.join("doomed.txt"), "real content").unwrap();
        std::fs::write(project.join("target.env"), "SECRET=1").unwrap();

        // The process cwd is deliberately WRONG: neither file exists here.
        assert!(!elsewhere.join("doomed.txt").exists());

        let rm = rm_targets(
            &[
                "rm".to_string(),
                "-rf".to_string(),
                "doomed.txt".to_string(),
            ],
            &project,
        )
        .expect("a relative rm target must resolve against the PAYLOAD cwd");
        assert_eq!(rm.len(), 1);
        assert_eq!(rm[0], project.join("doomed.txt"));

        let ov = overwrite_targets("cat /dev/null > target.env", &project)
            .expect("a relative redirect target must resolve against the PAYLOAD cwd");
        assert_eq!(ov.len(), 1);
        assert_eq!(ov[0], project.join("target.env"));

        // Control leg — without it this test cannot distinguish "resolved
        // correctly" from "resolves everything to something". Against the
        // wrong base the same command finds nothing, which is exactly the
        // silent no-backup this parameter exists to prevent.
        assert!(
            rm_targets(
                &[
                    "rm".to_string(),
                    "-rf".to_string(),
                    "doomed.txt".to_string()
                ],
                &elsewhere,
            )
            .is_none(),
            "control: the wrong base must find nothing, or the test proves nothing"
        );
        assert!(
            overwrite_targets("cat /dev/null > target.env", &elsewhere).is_none(),
            "control: the wrong base must find nothing for overwrites too"
        );
    }

    /// `plan` filters by `exists()`, so a wrong base makes an insurable
    /// command report as uninsurable — the preview then tells a human "not
    /// reversible without a backup" about a file that WOULD be copied aside.
    #[test]
    fn plan_reports_insurance_against_the_payload_cwd() {
        let tmp = TempTree::new("plan-cwd");
        let project = tmp.dir("proj");
        let elsewhere = tmp.dir("other");
        std::fs::write(project.join("doomed.txt"), "x").unwrap();

        assert!(
            plan("rm -rf doomed.txt", &project).is_some(),
            "insurable against the payload cwd"
        );
        assert!(
            plan("rm -rf doomed.txt", &elsewhere).is_none(),
            "control: the wrong base reports no insurance — the preview lie this prevents"
        );
    }

    #[test]
    fn cmd_switches_are_not_treated_as_targets() {
        // `/s` must not be resolved as a path, and a nonexistent target must
        // not produce a plan merely because a switch was present.
        assert!(plan("del /s /q C:\\definitely-not-here-xyz-9f2", &test_cwd()).is_none());
    }

    // -----------------------------------------------------------------------
    // What the command says: the parsing that decides whether insurance
    // applies at all, and to what.
    // -----------------------------------------------------------------------

    use crate::testutil::TestEnv;

    fn tokens_of(command: &str) -> Vec<String> {
        crate::pg::shell_tokens(command)
    }

    #[test]
    fn a_forced_push_names_the_ref_it_would_overwrite() {
        assert_eq!(
            git_force_push_target(&tokens_of("git push --force origin main")),
            Some(("origin".to_string(), "main".to_string()))
        );
        // Flags are not positional arguments: reading them as one would pin
        // `--force-with-lease` instead of the branch about to be lost.
        assert_eq!(
            git_force_push_target(&tokens_of("git push origin main --force-with-lease")),
            Some(("origin".to_string(), "main".to_string()))
        );
    }

    #[test]
    fn every_spelling_of_force_counts_and_an_ordinary_push_does_not() {
        for flag in ["--force", "-f", "--force-with-lease"] {
            assert!(
                git_force_push_target(&tokens_of(&format!("git push {flag} origin main")))
                    .is_some(),
                "{flag} is a force push"
            );
        }
        // An ordinary push only adds commits; there is nothing to insure.
        assert_eq!(
            git_force_push_target(&tokens_of("git push origin main")),
            None
        );
    }

    #[test]
    fn only_git_push_itself_is_a_forced_push() {
        assert_eq!(
            git_force_push_target(&tokens_of("git commit --force")),
            None
        );
        assert_eq!(
            git_force_push_target(&tokens_of("hub push --force origin main")),
            None
        );
    }

    #[test]
    fn a_truncate_is_insured_with_data_only_and_a_drop_with_the_schema() {
        let (tables, data_only) = pg_backup_targets(r#"psql -d shop -c "TRUNCATE users""#)
            .expect("a truncate is insurable");
        assert_eq!(tables, ["users"]);
        assert!(data_only, "the table survives a truncate; only its rows go");

        let (tables, data_only) = pg_backup_targets(r#"psql -d shop -c "DROP TABLE users""#)
            .expect("a drop is insurable");
        assert_eq!(tables, ["users"]);
        assert!(
            !data_only,
            "a drop takes the table itself, so the schema has to be in the dump"
        );
    }

    #[test]
    fn insurance_needs_a_psql_command_carrying_a_destructive_statement() {
        assert!(
            pg_backup_targets(r#"mysql -e "DROP TABLE users""#).is_none(),
            "another client is not psql"
        );
        assert!(
            pg_backup_targets("psql -d shop").is_none(),
            "no statement, nothing to insure against"
        );
        assert!(
            pg_backup_targets(r#"psql -d shop -c "SELECT 1""#).is_none(),
            "a read destroys nothing"
        );
        assert!(
            pg_backup_targets(r#"psql -d shop --command "TRUNCATE users""#).is_some(),
            "the long spelling is the same flag"
        );
    }

    #[test]
    fn local_terraform_state_is_insured_only_for_apply_and_destroy() {
        let mut env = TestEnv::new("bk-tfstate");
        let stack = env.root().join("stack");
        std::fs::create_dir_all(&stack).expect("stack dir must be creatable");
        std::fs::write(stack.join("terraform.tfstate"), "{}").expect("state must be writable");
        env.chdir(&stack);

        for bin in ["terraform", "tofu"] {
            for verb in ["apply", "destroy"] {
                assert!(
                    tf_state_target(&tokens_of(&format!("{bin} {verb}"))).is_some(),
                    "{bin} {verb} rewrites state"
                );
            }
            assert_eq!(
                tf_state_target(&tokens_of(&format!("{bin} plan"))),
                None,
                "a plan changes nothing"
            );
        }
        assert_eq!(
            tf_state_target(&tokens_of("ansible apply")),
            None,
            "another tool's apply is not terraform's"
        );

        // Remote state is versioned by its own backend and out of scope: with
        // no local file there is nothing here to copy.
        let empty = env.root().join("remote-backend");
        std::fs::create_dir_all(&empty).expect("dir must be creatable");
        env.chdir(&empty);
        assert_eq!(tf_state_target(&tokens_of("terraform destroy")), None);
    }

    #[test]
    fn a_compound_command_is_planned_by_its_insurable_segment() {
        // The first segment insures nothing, which must not make the whole
        // command read as uninsurable.
        let planned = plan(
            r#"echo hi && psql -d shop -c "TRUNCATE users""#,
            &test_cwd(),
        )
        .expect("the insurable segment must be found");
        assert!(planned.contains("pg_dump"), "{planned}");
    }

    #[test]
    fn take_insures_the_first_insurable_segment_of_a_compound() {
        let tmp = TempTree::new("bk-compound");
        let state = tmp.dir("state");
        let doomed = tmp.file("doomed.txt", "precious");

        let record = take(
            &state,
            &format!("echo hi && rm -rf {}", doomed.display()),
            &test_cwd(),
        )
        .expect("taking a backup must not fail")
        .expect("the delete segment is insurable");

        assert_eq!(record.kind, "files");
        assert!(
            state.join("backups").join("manifest.jsonl").is_file(),
            "an insured operation leaves a record behind"
        );
    }

    // -----------------------------------------------------------------------
    // git-ref insurance, against a real repository. `git_out` reads whatever
    // repo the PROCESS is in, so these move into one.
    // -----------------------------------------------------------------------

    fn git_run(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "user.email=tests@termaxa.invalid",
                "-c",
                "user.name=termaxa tests",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .expect("git must be available: this is git insurance");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A working copy on `branch`, with an `origin` that already has it.
    fn repo_with_remote(env: &TestEnv, branch: &str) -> PathBuf {
        let root = env.root().to_path_buf();
        let remote = root.join("remote.git");
        git_run(
            &root,
            &["init", "--bare", "-q", remote.to_str().expect("utf-8 path")],
        );

        let work = root.join("work");
        std::fs::create_dir_all(&work).expect("work dir must be creatable");
        git_run(&work, &["init", "-q"]);
        git_run(
            &work,
            &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
        );
        git_run(
            &work,
            &[
                "remote",
                "add",
                "origin",
                remote.to_str().expect("utf-8 path"),
            ],
        );
        std::fs::write(work.join("seed.txt"), "seed\n").expect("file must be writable");
        git_run(&work, &["add", "-A"]);
        git_run(&work, &["commit", "-q", "-m", "seed"]);
        git_run(&work, &["push", "-q", "-u", "origin", branch]);
        work
    }

    #[test]
    fn the_branch_defaults_to_the_one_the_repository_is_on() {
        let mut env = TestEnv::new("bk-branch");
        let work = repo_with_remote(&env, "release/7");
        env.chdir(&work);

        assert_eq!(current_branch(), Some("release/7".to_string()));
        // A force push that names no branch insures the branch you are on,
        // not a guessed `main`.
        assert_eq!(
            git_force_push_target(&tokens_of("git push --force")),
            Some(("origin".to_string(), "release/7".to_string()))
        );
    }

    #[test]
    fn a_forced_push_is_insured_by_pinning_the_remote_ref() {
        let mut env = TestEnv::new("bk-gitref");
        let work = repo_with_remote(&env, "main");
        env.chdir(&work);

        let record = backup_git_ref(
            "b-1",
            "2026-01-01T00:00:00Z",
            "git push --force origin main",
            "origin",
            "main",
        )
        .expect("the remote ref must be pinnable");

        assert_eq!(record.kind, "git-ref");
        // The snapshot has to be a real ref, or the record promises a restore
        // that cannot happen.
        let pinned = record.data["branch"]
            .as_str()
            .expect("the record names its branch");
        assert_eq!(pinned, "termaxa/backup/b-1");
        assert_eq!(
            git_run(&work, &["rev-parse", pinned]),
            git_run(&work, &["rev-parse", "origin/main"]),
            "the backup branch must point at what the remote had"
        );
    }

    // -----------------------------------------------------------------------
    // The postgres paths, driven by stub binaries. Neither pg_dump nor psql is
    // a reasonable test dependency, and what matters here is what the gate
    // does with their EXIT STATUS — which a script can produce exactly.
    // -----------------------------------------------------------------------

    /// Put `name` on PATH as a script exiting with `code`, for the life of the
    /// returned guard. PATH is process-global, so every caller holds `TestEnv`.
    #[cfg(unix)]
    fn stub_on_path(env: &TestEnv, name: &str, code: i32) -> PathGuard {
        use std::os::unix::fs::PermissionsExt as _;
        let bin_dir = env.root().join("stub-bin");
        std::fs::create_dir_all(&bin_dir).expect("stub dir must be creatable");
        let path = bin_dir.join(name);
        // Write the -f target if asked for one, so a "successful" dump leaves
        // the file its record will name.
        std::fs::write(
            &path,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"-f\" ]; then : > \"$2\"; fi\n  \
             shift\ndone\necho 'stub' >&2\n"
                .to_string()
                + &format!("exit {code}\n"),
        )
        .expect("stub must be writable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stub must be executable");

        let previous = std::env::var_os("PATH");
        let combined = match &previous {
            Some(p) => format!("{}:{}", bin_dir.display(), p.to_string_lossy()),
            None => bin_dir.display().to_string(),
        };
        std::env::set_var("PATH", combined);
        PathGuard { previous }
    }

    /// Restores PATH on drop, so a failing assertion cannot leave a stub
    /// binary in front of the real one for the rest of the process.
    #[cfg(unix)]
    struct PathGuard {
        previous: Option<std::ffi::OsString>,
    }

    #[cfg(unix)]
    impl Drop for PathGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_dump_that_failed_is_not_recorded_as_insurance() {
        // The one lie insurance must never tell. `hook` ignores an Err from
        // `take` and proceeds, so the error is what keeps a phantom record
        // out of the manifest.
        let env = TestEnv::new("bk-pg-fail");
        let _guard = stub_on_path(&env, "pg_dump", 1);
        let state = env.root().join("state");

        let err = take(&state, r#"psql -d shop -c "TRUNCATE users""#, &test_cwd())
            .expect_err("a dump that did not run is not a backup");
        assert!(err.to_string().contains("pg_dump failed"), "{err}");
        assert!(
            !state.join("backups").join("manifest.jsonl").exists(),
            "nothing may be recorded for a dump that failed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_successful_dump_is_recorded_with_the_file_it_wrote() {
        let env = TestEnv::new("bk-pg-ok");
        let _guard = stub_on_path(&env, "pg_dump", 0);
        let state = env.root().join("state");

        let record = take(&state, r#"psql -d shop -c "TRUNCATE users""#, &test_cwd())
            .expect("the dump must succeed")
            .expect("a truncate is insurable");

        assert_eq!(record.kind, "pg-dump");
        let file = record.data["file"]
            .as_str()
            .expect("the record names a file");
        assert!(
            Path::new(file).is_file(),
            "the record must name a dump that exists: {file}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_restore_that_failed_is_reported_rather_than_claimed() {
        let env = TestEnv::new("bk-restore-fail");
        let state = env.root().join("state");
        {
            // Take a real record first, with a dump that works.
            let _guard = stub_on_path(&env, "pg_dump", 0);
            take(&state, r#"psql -d shop -c "TRUNCATE users""#, &test_cwd())
                .expect("the dump must succeed")
                .expect("a truncate is insurable");
        }

        // Then fail the restore: reporting success here would leave someone
        // believing their data came back.
        let _guard = stub_on_path(&env, "psql", 1);
        let id = list(&state).expect("the manifest must read")[0].id.clone();
        let err = restore(&state, &id).expect_err("a failed restore is not a restore");
        assert!(err.to_string().contains("psql restore failed"), "{err}");
    }

    #[test]
    fn a_restore_push_that_failed_is_reported_rather_than_claimed() {
        // Restoring a git ref means force-pushing the pinned sha back. If
        // that push does not land, the remote still holds the overwritten
        // history — saying "restored" would send someone away believing the
        // opposite of what happened.
        let mut env = TestEnv::new("bk-restore-push");
        let work = repo_with_remote(&env, "main");
        env.chdir(&work);
        let state = env.root().join("state");

        let record = backup_git_ref(
            "b-1",
            "2026-01-01T00:00:00Z",
            "git push --force origin main",
            "origin",
            "main",
        )
        .expect("the remote ref must be pinnable");
        append_manifest(&state, &record).expect("the record must be writable");

        // Take the remote away, so the restore push cannot succeed.
        std::fs::remove_dir_all(env.root().join("remote.git")).expect("remote must be removable");

        let err = restore(&state, "b-1").expect_err("a push that failed is not a restore");
        assert!(err.to_string().contains("restore push failed"), "{err}");
    }

    #[test]
    fn a_branch_that_cannot_be_created_is_reported_not_recorded() {
        // Recording a snapshot that was never taken tells the user they are
        // insured when they are not — the one lie insurance must not tell.
        let mut env = TestEnv::new("bk-gitref-fail");
        let work = repo_with_remote(&env, "main");
        env.chdir(&work);
        git_run(&work, &["branch", "termaxa/backup/b-collide", "HEAD"]);

        let err = backup_git_ref(
            "b-collide",
            "2026-01-01T00:00:00Z",
            "git push --force origin main",
            "origin",
            "main",
        )
        .expect_err("a branch that cannot be created is not a backup");
        assert!(err.to_string().contains("git branch failed"), "{err}");
    }
}
