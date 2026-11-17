use crate::policy::Policy;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Where things live — the v0.8 split, written in scar tissue.
///
/// Field report, v0.6: `.termaxa/` lived inside the governed repo, so a
/// `git reset --hard` reverted the policy and ATE THE AUDIT LOG — twice.
/// Runtime state has no business living inside the repo it protects.
///
///   - `policy.yaml`  → stays in-repo (`<project>/.termaxa/`): it is
///     configuration, reviewable in PRs, policy-as-code.
///   - logs + backups → `~/.termaxa/projects/<name>-<hash8>/`: runtime state,
///     outside every repo, untouchable by any git operation BY CONSTRUCTION.
pub struct Paths {
    /// The in-repo `.termaxa/` directory (holds policy.yaml).
    pub project_dir: PathBuf,
    /// Home-directory state root for this project (holds logs/, backups/).
    pub state_dir: PathBuf,
    /// True when the project has no policy and a plugin's hook is watching
    /// it (`resolve_watched`): `project_dir` is then where `init` WOULD put
    /// the policy, and `policy_file()` names a file that does not exist.
    pub watched: bool,
}

impl Paths {
    pub fn policy_file(&self) -> PathBuf {
        self.project_dir.join("policy.yaml")
    }

    /// The audit log's location. Does NOT create anything — callers that
    /// intend to write go through `AuditLog::new`, which does.
    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join("logs").join("audit.jsonl")
    }
}

/// Resolve paths for the current project, creating state dirs and running
/// one-time migration of any legacy in-repo state.
pub fn resolve() -> Result<Paths> {
    let cwd = std::env::current_dir()?;
    resolve_from(&cwd)
}

/// Resolve paths starting the policy search from an EXPLICIT directory, rather
/// than the process cwd. Hooks use this with the agent-supplied payload `cwd`
/// so they never depend on where the agent happened to spawn the process.
///
/// This variant has SIDE EFFECTS by design: it creates the state directories
/// and runs one-time legacy migration, because every caller is about to write
/// (evaluate, log, back up). Diagnostics must use `resolve_readonly`.
pub fn resolve_from(start: &std::path::Path) -> Result<Paths> {
    let paths = resolve_readonly(start)?;

    #[cfg(test)]
    crate::testutil::making_state(&paths.state_dir);
    fs::create_dir_all(paths.state_dir.join("logs"))?;
    fs::create_dir_all(paths.state_dir.join("backups"))?;

    migrate_legacy_state(&paths.project_dir, &paths.state_dir)?;

    Ok(paths)
}

/// Compute where things live WITHOUT touching the filesystem.
///
/// `termaxa doctor` must observe, never mutate: a diagnostic that creates
/// directories (or silently migrates legacy state) changes the thing it was
/// asked to describe, and on a project that has never run an agent it would
/// manufacture the very state it is reporting on. Path computation only —
/// no `create_dir_all`, no migration.
pub fn resolve_readonly(start: &std::path::Path) -> Result<Paths> {
    let Some(policy_file) = Policy::find_policy_file(start) else {
        bail!("no .termaxa/policy.yaml found in this directory or any parent — run `termaxa init` first");
    };
    let project_dir = policy_file.parent().unwrap().to_path_buf();
    let project_root = project_dir.parent().unwrap_or(&project_dir).to_path_buf();
    let state_dir = state_dir_for(&project_root)?;

    Ok(Paths {
        project_dir,
        state_dir,
        watched: false,
    })
}

/// Set by `termaxa hook --plugin`: this hook was registered by a plugin, for
/// every project on the machine, not by `termaxa init` for one. Two things
/// follow from that and nothing else does (decision #147):
///
///   * a project with NO policy is watched (`Policy::watching`) where a
///     project's own hook refuses every command (decision #19, which stands
///     for every hook without the flag);
///   * a project that registers a hook of its own is left to that hook, so a
///     command is judged, recorded and copied once.
///
/// A flag of this process and not a parameter: its readers are several
/// modules deep (the hook, the witness, the copy's project root). And not an
/// environment variable: a variable something else exported (a `.envrc`, a
/// launch script) would make a project's OWN hook step aside for itself,
/// which is every command ungated. Only the command line sets it.
///
/// Under test the flag is the thread's and not the process's: cargo runs
/// tests as threads of one process, and a flag one test raised would have
/// every other test's hook watching the directory it happened to be in.
#[cfg(not(test))]
static PLUGIN_HOOK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
thread_local! {
    static PLUGIN_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(not(test))]
pub fn plugin_hook() -> bool {
    PLUGIN_HOOK.load(std::sync::atomic::Ordering::Relaxed)
}
#[cfg(test)]
pub fn plugin_hook() -> bool {
    PLUGIN_HOOK.with(|flag| flag.get())
}

/// `termaxa hook --plugin` calls this once, before it reads its input.
#[cfg(not(test))]
pub fn set_plugin_hook(on: bool) {
    PLUGIN_HOOK.store(on, std::sync::atomic::Ordering::Relaxed);
}
#[cfg(test)]
pub fn set_plugin_hook(on: bool) {
    PLUGIN_HOOK.with(|flag| flag.set(on));
}

/// The directory a project with no policy is taken to be: the checkout
/// `start` is in; outside any checkout, the directory the session was
/// started in when `start` is inside it (Claude Code exports it to its
/// hooks as `CLAUDE_PROJECT_DIR`, so a `cd build` does not start a second
/// record); otherwise `start` itself. The checkout is where `termaxa init`
/// is run, so the record kept while watching is the record the project's
/// own policy continues (same root, same state directory).
pub fn watch_root(start: &Path) -> PathBuf {
    if let Some(checkout) = start.ancestors().find(|d| crate::delete::is_checkout(d)) {
        return checkout.to_path_buf();
    }
    if let Ok(session) = std::env::var("CLAUDE_PROJECT_DIR") {
        let session = PathBuf::from(session);
        if session.is_dir() {
            let inside = |a: &Path, b: &Path| match (a.canonicalize(), b.canonicalize()) {
                (Ok(a), Ok(b)) => a.starts_with(b),
                _ => a.starts_with(b),
            };
            if inside(start, &session) {
                return session;
            }
        }
    }
    start.to_path_buf()
}

/// The root of the project `cwd` is in: the directory that holds
/// `.termaxa/`, found the way the hook finds its policy, and for a plugin's
/// hook in a project with no policy the root it is watched from. `None`
/// outside any project.
pub fn project_root(cwd: &Path) -> Option<PathBuf> {
    match resolve_readonly(cwd) {
        Ok(paths) => paths.project_dir.parent().map(Path::to_path_buf),
        Err(_) if plugin_hook() => Some(watch_root(cwd)),
        Err(_) => None,
    }
}

/// Paths for a project with NO policy that a plugin's hook is watching
/// (decision #147). Creates the state directories, as `resolve_from` does:
/// the caller is about to write the record.
pub fn resolve_watched(start: &Path) -> Result<Paths> {
    let paths = watched_readonly(start)?;
    #[cfg(test)]
    crate::testutil::making_state(&paths.state_dir);
    for dir in ["logs", "backups"] {
        let dir = paths.state_dir.join(dir);
        fs::create_dir_all(&dir).with_context(|| {
            format!(
                "termaxa is watching this project (it has no .termaxa/policy.yaml) and cannot \
                 create {} to keep the record in",
                dir.display()
            )
        })?;
    }
    Ok(paths)
}

fn watched_readonly(start: &Path) -> Result<Paths> {
    let root = watch_root(start);
    Ok(Paths {
        project_dir: root.join(".termaxa"),
        state_dir: state_dir_for(&root)?,
        watched: true,
    })
}

/// Paths for the commands that READ a project's record (`log`, `report`,
/// `stats`, `backups`, `rollback`, `paths`): the project's own when it has a
/// policy, and otherwise the record a plugin's hook kept while watching it,
/// if there is one. With neither, the error `resolve` gives. Nothing is
/// created: a project nobody watched has no record to read.
pub fn resolve_record() -> Result<Paths> {
    let cwd = std::env::current_dir()?;
    match resolve_from(&cwd) {
        Ok(paths) => Ok(paths),
        Err(no_policy) => watched_record(&cwd).ok_or(no_policy),
    }
}

/// The record a plugin's hook kept of a project with no policy, if it kept
/// one: the paths it wrote under, and nothing created.
pub fn watched_record(start: &Path) -> Option<Paths> {
    watched_readonly(start)
        .ok()
        .filter(|watched| watched.log_file().is_file())
}

/// `$TERMAXA_HOME` (tests, custom setups) or `~/.termaxa`.
///
/// Public since v0.16: `supervise` needs the same answer for the socket path,
/// and a second copy of the TERMAXA_HOME-then-HOME logic is exactly how two
/// readers of one question start disagreeing (#37).
pub fn home_base() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("TERMAXA_HOME") {
        if !custom.trim().is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }
    let home = std::env::var("USERPROFILE") // Windows
        .or_else(|_| std::env::var("HOME")) // Unix
        .context("cannot locate home directory (USERPROFILE/HOME unset)")?;
    Ok(PathBuf::from(home).join(".termaxa"))
}

/// State dir for `check` demo mode (no project policy). Audit logs for
/// zero-setup demo checks land in a shared bucket under ~/.termaxa, so demo
/// runs are still recorded without requiring `termaxa init`.
pub fn demo_state_dir() -> Result<PathBuf> {
    let dir = home_base()?.join("demo");
    #[cfg(test)]
    crate::testutil::making_state(&dir);
    fs::create_dir_all(dir.join("logs"))?;
    fs::create_dir_all(dir.join("backups"))?;
    Ok(dir)
}

fn state_dir_for(project_root: &Path) -> Result<PathBuf> {
    let canonical = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
    let name = canonical
        .file_name()
        .map(|n| sanitize(&n.to_string_lossy()))
        .unwrap_or_else(|| "project".into());
    let key = format!(
        "{}-{}",
        name,
        fnv1a_hex8(&hash_key(&canonical.to_string_lossy()))
    );
    Ok(home_base()?.join("projects").join(key))
}

/// Canonicalize a path *string* for stable hashing across representations:
/// unify separators to '/', and lowercase a Windows drive letter. This makes
/// `C:\Users\x\proj` and `c:/Users/x/proj` hash identically, so `init` and
/// the agent hook always resolve to the same project state dir.
fn hash_key(s: &str) -> String {
    let mut out = s.replace('\\', "/");
    // lowercase a leading "X:" drive letter
    let bytes = out.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let mut c = out.into_bytes();
        c[0] = c[0].to_ascii_lowercase();
        out = String::from_utf8(c).unwrap();
    }
    // strip any trailing slash
    while out.ends_with('/') && out.len() > 1 {
        out.pop();
    }
    out
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
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
/// those paths would make `termaxa rollback` a liar — so every string in
/// every record gets the old-prefix → new-prefix rewrite.
fn migrate_legacy_state(project_dir: &Path, state_dir: &Path) -> Result<()> {
    let mut migrated = false;

    // 1. audit log: append old lines to the home log, remove the original.
    let old_log = project_dir.join("logs").join("audit.jsonl");
    if old_log.is_file() {
        let content = fs::read_to_string(&old_log)?;
        let new_log = state_dir.join("logs").join("audit.jsonl");
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&new_log)?;
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
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&new_manifest)?;
            f.write_all(out.as_bytes())?;
            fs::remove_file(&old_manifest)?;
        }
        let _ = fs::remove_dir(&old_backups);
        migrated = true;
    }

    if migrated {
        eprintln!(
            "termaxa: migrated legacy in-repo state to {}",
            state_dir.display()
        );
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

    use crate::testutil::{TempTree, TestEnv};

    #[test]
    fn hash_key_stable_across_path_representations() {
        // The exact Windows/Cursor mismatch: backslash+uppercase vs slash+lowercase.
        assert_eq!(hash_key("C:\\Users\\x\\proj"), hash_key("c:/Users/x/proj"));
        assert_eq!(hash_key("C:/Users/x/proj/"), hash_key("c:/Users/x/proj"));
        // Unix paths unaffected.
        assert_eq!(hash_key("/home/u/proj"), "/home/u/proj");
    }

    #[test]
    fn resolve_from_uses_given_root_not_process_cwd() {
        let env = TestEnv::new("cwdtest");
        // A project with a policy, in a dir that is NOT the process cwd.
        let proj = env.project("proj");

        // Resolve FROM the project dir explicitly (simulating payload.cwd),
        // while the actual process cwd is elsewhere.
        let paths = resolve_from(&proj).expect("resolve_from should find the project policy");
        assert!(
            paths.policy_file().starts_with(&proj),
            "policy must resolve under the given root, got {}",
            paths.policy_file().display()
        );
        assert!(
            paths.policy_file().is_file(),
            "policy file should exist at resolved path"
        );
        // The regression guard for the flake: if `TERMAXA_HOME` is ever unset
        // or inherited from elsewhere, the state dir lands outside this test's
        // tree and this fails the same way every run, instead of failing once
        // in a hundred on whichever runner happens to lose the race.
        assert!(
            paths.state_dir.starts_with(env.home()),
            "state must resolve under this test's own TERMAXA_HOME, got {}",
            paths.state_dir.display()
        );
    }

    #[test]
    fn only_a_drive_letter_is_case_folded() {
        // The lowercasing exists for `C:` vs `c:`. A directory name that
        // merely starts with a letter must keep its case, or two different
        // projects can share a state directory.
        assert_eq!(hash_key("Users/x/proj"), "Users/x/proj");
        assert_ne!(hash_key("Users/x/proj"), hash_key("users/x/proj"));
    }

    #[test]
    fn the_root_path_survives_both_guards() {
        // One character: the trailing-slash strip must not eat the only
        // thing there is, and the drive-letter check must not read a second
        // byte that does not exist.
        assert_eq!(hash_key("/"), "/");
        assert_eq!(hash_key("/a/"), "/a");
        assert_eq!(hash_key("/a///"), "/a");
    }

    #[test]
    fn the_hash_is_the_published_algorithm_not_merely_a_stable_one() {
        // Golden values. Any other mixing step still produces hashes that are
        // stable and distinct, so only a known answer pins FNV-1a itself —
        // and the state directory a project resolves to depends on it.
        assert_eq!(fnv1a_hex8("abc"), "e25ef552");
        assert_eq!(fnv1a_hex8("/home/u/proj"), "430add1b");
    }

    #[test]
    fn demo_state_dir_sits_under_the_home_and_is_ready_to_write() {
        let env = TestEnv::new("demo-state");
        let dir = demo_state_dir().expect("demo state must resolve");

        assert!(
            dir.starts_with(env.home()),
            "demo state belongs under TERMAXA_HOME, got {}",
            dir.display()
        );
        assert!(dir.ends_with("demo"));
        // A zero-setup check writes immediately; the directories have to be
        // there before it does.
        assert!(dir.join("logs").is_dir());
        assert!(dir.join("backups").is_dir());
    }

    #[test]
    fn legacy_in_repo_state_is_moved_and_its_recorded_paths_rewritten() {
        let env = TestEnv::new("migrate");
        let proj = env.project("legacy");
        let in_repo = proj.join(".termaxa");

        // The pre-v0.8 layout: logs and backups inside the repository.
        std::fs::create_dir_all(in_repo.join("logs")).expect("legacy logs must be creatable");
        std::fs::write(
            in_repo.join("logs").join("audit.jsonl"),
            "{\"command\":\"legacy entry\"}\n",
        )
        .expect("legacy log must be writable");

        let old_backups = in_repo.join("backups");
        std::fs::create_dir_all(&old_backups).expect("legacy backups must be creatable");
        let payload = old_backups.join("payload.sql");
        std::fs::write(&payload, "-- dump\n").expect("payload must be writable");
        let record = serde_json::json!({
            "id": "b1",
            "data": { "file": payload.display().to_string() },
        });
        std::fs::write(old_backups.join("manifest.jsonl"), format!("{}\n", record))
            .expect("legacy manifest must be writable");

        let paths = resolve_from(&proj).expect("resolve must migrate on the way past");

        // Nothing is left behind in the repository.
        assert!(!in_repo.join("logs").join("audit.jsonl").exists());
        assert!(!payload.exists());

        // The payload moved, or `rollback` would point at nothing.
        let new_backups = paths.state_dir.join("backups");
        assert!(
            new_backups.join("payload.sql").is_file(),
            "the payload must arrive at {}",
            new_backups.display()
        );

        // The old log is appended to the home log rather than replacing it.
        let log = std::fs::read_to_string(paths.log_file()).expect("the log must be readable");
        assert!(log.contains("legacy entry"), "{log:?}");

        // And every recorded path is rewritten, which is the whole reason the
        // manifest is handled apart from the payloads it names.
        //
        // Compared as a PATH rather than as text: the manifest is JSON, so on
        // Windows every separator in it is an escaped backslash and a raw path
        // never appears literally. Matching the rendering rather than the
        // value passed on both other platforms and failed only where the
        // escaping exists.
        let manifest = std::fs::read_to_string(new_backups.join("manifest.jsonl"))
            .expect("the manifest must be readable");
        let record: serde_json::Value =
            serde_json::from_str(manifest.trim()).expect("the record must still be JSON");
        let recorded = record["data"]["file"]
            .as_str()
            .expect("the record names its payload");
        assert_eq!(
            Path::new(recorded),
            new_backups.join("payload.sql"),
            "the record must name the payload's new home"
        );
        assert!(
            !Path::new(recorded).starts_with(&old_backups),
            "no record may still point into the repository: {recorded}"
        );
    }

    #[test]
    fn copy_recursive_reproduces_a_whole_tree() {
        // `move_path` only reaches this when `rename` fails, i.e. across a
        // filesystem — and then it is the only thing between a backup and a
        // lost payload.
        let tmp = TempTree::new("copy-tree");
        let src = tmp.dir("src");
        std::fs::create_dir_all(src.join("nested").join("deeper")).expect("tree must be creatable");
        std::fs::write(src.join("top.txt"), "top").expect("file must be writable");
        std::fs::write(src.join("nested").join("deeper").join("leaf.txt"), "leaf")
            .expect("file must be writable");

        let dst = tmp.absent("dst");
        copy_recursive(&src, &dst).expect("the tree must copy");

        assert_eq!(
            std::fs::read_to_string(dst.join("top.txt")).expect("top must arrive"),
            "top"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("nested").join("deeper").join("leaf.txt"))
                .expect("the nested leaf must arrive"),
            "leaf"
        );
    }

    #[test]
    fn hash_is_stable_and_distinguishes() {
        assert_eq!(fnv1a_hex8("/a/b/project"), fnv1a_hex8("/a/b/project"));
        assert_ne!(fnv1a_hex8("/a/b/project"), fnv1a_hex8("/c/d/project"));
    }

    #[test]
    fn sanitize_keeps_names_readable() {
        assert_eq!(sanitize("termaxa-demo"), "termaxa-demo");
        assert_eq!(sanitize("my proj (v2)"), "my_proj__v2_");
    }

    #[test]
    fn resolve_from_uses_explicit_dir_not_process_cwd() {
        // Regression: a hook spawned from the WRONG directory must still find the
        // project's policy via the explicit start dir (the agent's payload cwd).
        // This is the exact Cursor failure mode: process cwd != project dir.
        let mut env = TestEnv::new("cwd-test");
        let proj = env.project("proj");
        let aegis = proj.join(".termaxa");

        // Simulate the agent spawning us from somewhere unrelated. The guard
        // remembers where the process was and steps back out before it deletes
        // the tree, so nothing after this test inherits a deleted cwd.
        let elsewhere = env.root().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        env.chdir(&elsewhere);

        // resolve() (process cwd = elsewhere) must FAIL to find the policy...
        assert!(
            resolve().is_err(),
            "process-cwd resolve should not find the policy"
        );
        // ...but resolve_from(project) must SUCCEED.
        let r = resolve_from(&proj);
        assert!(
            r.is_ok(),
            "explicit resolve_from(project cwd) must find the policy"
        );
        assert_eq!(r.unwrap().policy_file(), aegis.join("policy.yaml"));
    }

    #[test]
    fn resolve_readonly_creates_nothing() {
        // A diagnostic must not manufacture the state it reports on.
        // `termaxa doctor` runs on projects that have never executed anything;
        // if resolving created logs/ and backups/, the report would describe
        // directories it had just invented.
        let env = TestEnv::new("ro");
        let proj = env.project("proj");

        let p = resolve_readonly(&proj).expect("must resolve without creating anything");
        assert!(
            !p.state_dir.join("logs").exists(),
            "resolve_readonly must not create logs/"
        );
        assert!(
            !p.state_dir.join("backups").exists(),
            "resolve_readonly must not create backups/"
        );

        // ...while the writing variant does create them.
        let p2 = resolve_from(&proj).expect("resolve_from must succeed");
        assert!(p2.state_dir.join("logs").is_dir());
        assert!(p2.state_dir.join("backups").is_dir());
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

    /// A project with no policy is rooted at its checkout, from any
    /// directory inside it, and its state is the state a policy written at
    /// that root resolves to: what was watched is what `init` continues.
    #[test]
    fn a_watched_project_is_rooted_where_init_would_root_it() {
        let env = TestEnv::new("paths-watch-root");
        let proj = env.root().join("proj");
        let deep = proj.join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(proj.join(".git")).unwrap();

        assert_eq!(watch_root(&deep), proj);
        assert_eq!(watch_root(&proj), proj);
        let watched = resolve_watched(&deep).unwrap();
        assert!(watched.watched);
        assert_eq!(watched.project_dir, proj.join(".termaxa"));
        assert!(
            !watched.policy_file().exists(),
            "nothing is written in the project"
        );
        assert!(watched.state_dir.starts_with(env.home()));
        assert!(watched.state_dir.join("logs").is_dir());

        std::fs::create_dir_all(proj.join(".termaxa")).unwrap();
        std::fs::write(
            proj.join(".termaxa").join("policy.yaml"),
            "version: 1\ndefault: ask\nrules: []\n",
        )
        .unwrap();
        let owned = resolve_from(&deep).unwrap();
        assert!(!owned.watched);
        assert_eq!(owned.state_dir, watched.state_dir);
    }

    /// Outside any checkout the session's own directory is the root, when
    /// the call is inside it, so a `cd build` does not start a second
    /// record; a call somewhere else is its own.
    #[test]
    fn outside_a_checkout_a_watched_project_is_the_sessions_directory() {
        let mut env = TestEnv::new("paths-watch-session");
        env.plugin_hook();
        let session = env.root().join("scratch");
        let build = session.join("build");
        let elsewhere = env.root().join("elsewhere");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        if watch_root(&build) != build {
            // The suite's own temp directory is inside somebody's checkout:
            // every directory here has that root, and there is no
            // "outside a checkout" on this machine to test.
            return;
        }
        std::env::set_var("CLAUDE_PROJECT_DIR", &session);
        assert_eq!(watch_root(&build), session);
        assert_eq!(watch_root(&session), session);
        assert_eq!(watch_root(&elsewhere), elsewhere);
        assert_eq!(project_root(&build), Some(session.clone()));
        std::env::remove_var("CLAUDE_PROJECT_DIR");
        assert_eq!(watch_root(&build), build);
    }

    /// The root a copy is planned against (`project_root`): the policy's
    /// directory, or under a plugin's hook the watched root, so a build
    /// directory in a watched project is the build directory it is in any
    /// other. Without the flag a project with no policy has no root, as
    /// before.
    #[test]
    fn a_plugins_hook_gives_a_watched_project_a_root() {
        let mut env = TestEnv::new("paths-watch-project-root");
        let proj = env.root().join("proj");
        let sub = proj.join("web");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        assert_eq!(project_root(&sub), None);
        env.plugin_hook();
        assert_eq!(project_root(&sub), Some(proj.clone()));
        let owned = env.project("owned");
        assert_eq!(project_root(&owned), Some(owned.clone()));
    }

    /// The commands that read a record find a watched one, and looking for
    /// one makes nothing: a project nobody watched has no state afterwards.
    #[test]
    fn a_watched_record_is_found_only_once_it_exists() {
        let mut env = TestEnv::new("paths-watch-record");
        let proj = env.root().join("proj");
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        env.chdir(&proj);

        assert!(watched_record(&proj).is_none());
        assert!(resolve_record().is_err(), "no policy and no record");
        assert!(
            !env.home().join("projects").exists(),
            "looking for a record created nothing"
        );

        let watched = resolve_watched(&proj).unwrap();
        assert!(
            watched_record(&proj).is_none(),
            "a state directory with no line in it is not a record"
        );
        std::fs::write(watched.log_file(), "").unwrap();
        let found = resolve_record().expect("the watched record");
        assert!(found.watched);
        assert_eq!(found.state_dir, watched.state_dir);
    }
}
