//! Session circuit breaker.
//!
//! Detects repeated destructive *intent* within a single agent session and
//! escalates `ask` decisions to `deny`. This closes the "whack-a-mole" gap:
//! an agent retrying the same destructive goal with different syntax
//! (`rm -rf .` -> `Remove-Item -Recurse -Force .` -> `del /s /q .`) until one
//! spelling slips past the policy as a mere `ask` that an auto-approving UI
//! waves through.
//!
//! Design principles:
//! - The breaker only ESCALATES (`ask` -> `deny`). It never relaxes a `deny`
//!   and never touches an explicit `allow` (that is deliberate user policy).
//! - State is derived entirely from the append-only audit log. Nothing to
//!   reset; a new session starts clean because its `session_id` is new.
//! - Fail open on any read/parse error: a corrupt or missing log must never
//!   wedge the agent (best-effort principle, decision #4).
//! - Approved asks don't count: an `ask` that a human approved (evidenced by
//!   a later `source == "post"` execution record for the same command in the
//!   same session) is excluded from the threshold. Only denials and
//!   unanswered/unconfirmed asks count. Until post-execution hooks are wired
//!   for a given agent, this degrades to strict counting (all asks count).
//!
//! This module is deliberately self-contained: it has its own light
//! tokenizer and segment splitter so it compiles without changing the
//! visibility of anything in `backup.rs`, `pg.rs`, or `shell.rs`. If you
//! later make `shell::split_segments` pub, you can swap the private copy out.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// The matched_rule value the hook sets when the circuit breaker escalates.
/// report.rs counts trips by this exact string — the shared const keeps them
/// in sync via the compiler instead of a magic string in two files.
pub const BREAKER_RULE: &str = "circuit-breaker";

// ---------------------------------------------------------------------------
// Intent taxonomy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Intent {
    /// Recursive / forced file or directory deletion (any shell dialect).
    FileDelete,
    /// Destructive SQL routed through a DB client: DROP, TRUNCATE,
    /// DELETE without WHERE.
    DbDestroy,
    /// History- or ref-destroying git: push --force, reset --hard,
    /// clean -f, branch -D.
    GitDestructive,
    /// Infrastructure teardown: terraform/tofu destroy, kubectl delete.
    InfraDestroy,
}

impl Intent {
    pub fn label(&self) -> &'static str {
        match self {
            Intent::FileDelete => "file-delete",
            Intent::DbDestroy => "db-destroy",
            Intent::GitDestructive => "git-destructive",
            Intent::InfraDestroy => "infra-destroy",
        }
    }

    /// Severity rank used when a compound command carries several intents:
    /// the most severe one is reported (and therefore counted).
    fn rank(&self) -> u8 {
        match self {
            Intent::DbDestroy => 4,
            Intent::InfraDestroy => 3,
            Intent::FileDelete => 2,
            Intent::GitDestructive => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classify a full (possibly compound) command line. Splits on `&&`, `||`,
/// `;`, `|` exactly like the policy engine's shell splitter, classifies each
/// segment, and returns the most severe intent found — mirroring the
/// "most dangerous segment dictates the verdict" rule.
pub fn classify_command(command: &str) -> Option<Intent> {
    split_segments(command)
        .iter()
        .filter_map(|seg| classify_segment(seg))
        .max_by_key(|i| i.rank())
}

/// Classify one shell segment. Returns `None` for benign commands.
///
/// Scope is deliberately limited to *commands*: `python -c "shutil.rmtree(...)"`
/// will not classify. That is the cooperative-gate boundary SECURITY.md
/// documents; the breaker is a speed bump for syntax variation, not a sandbox.
pub fn classify_segment(segment: &str) -> Option<Intent> {
    let toks = tokens(segment);
    if toks.is_empty() {
        return None;
    }
    let lc: Vec<String> = toks.iter().map(|t| t.to_ascii_lowercase()).collect();
    let first = lc[0].as_str();

    // --- file deletes: unix rm, PowerShell Remove-Item + aliases, cmd del ---
    // PowerShell aliases: rm, ri, del, erase, rd all map to Remove-Item.
    let delete_cmds = ["rm", "ri", "del", "erase", "rd", "rmdir", "remove-item"];
    if delete_cmds.contains(&first) {
        let recursive = lc.iter().skip(1).any(|t| {
            t == "-recurse"
                || t == "/s"
                || (t.starts_with('-') && !t.starts_with("--") && t.contains('r'))
        });
        let force = lc.iter().skip(1).any(|t| {
            t == "-force"
                || t == "/q"
                || t == "--force"
                || (t.starts_with('-') && !t.starts_with("--") && t.contains('f'))
        });
        if recursive || force {
            return Some(Intent::FileDelete);
        }
    }
    // PowerShell full form spelled with any casing is covered by lowercase
    // compare above ("remove-item").

    // --- delete via command indirection: find / xargs -----------------------
    // A live agent bypassed the direct-delete check with
    //   find . -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    // because the first token is `find`, not a delete command. Catch the
    // common wrapper forms without pretending to fully parse find/xargs.
    if first == "find" {
        // `find ... -delete` erases matched entries directly.
        if lc.iter().any(|t| t == "-delete") {
            return Some(Intent::FileDelete);
        }
        // `find ... -exec/-execdir/-ok/-okdir <deletecmd> ...` runs a delete
        // per match. Look for a delete command anywhere after such a flag.
        let exec_flags = ["-exec", "-execdir", "-ok", "-okdir"];
        if lc.iter().any(|t| exec_flags.contains(&t.as_str()))
            && lc
                .iter()
                .any(|t| delete_cmds.contains(&t.as_str()) || t == "unlink")
        {
            return Some(Intent::FileDelete);
        }
    }
    // `... | xargs rm ...` or `xargs rm` as a segment (the pipe splitter feeds
    // us `xargs rm -rf` on its own). If xargs is invoking a delete command,
    // that's a bulk delete.
    if first == "xargs"
        && lc
            .iter()
            .skip(1)
            .any(|t| delete_cmds.contains(&t.as_str()) || t == "unlink")
    {
        return Some(Intent::FileDelete);
    }
    // Bare `unlink <file>` and GNU `shred -u` (delete-after-overwrite).
    if first == "unlink" && toks.len() > 1 {
        return Some(Intent::FileDelete);
    }
    if first == "shred" && lc.iter().any(|t| t == "-u" || t == "--remove") {
        return Some(Intent::FileDelete);
    }

    // --- git destructive ---
    if first == "git" {
        let sub = lc.get(1).map(|s| s.as_str()).unwrap_or("");
        let hit = match sub {
            "push" => lc
                .iter()
                .any(|t| t == "--force" || t == "-f" || t == "--force-with-lease"),
            "reset" => lc.iter().any(|t| t == "--hard"),
            "clean" => lc
                .iter()
                .any(|t| t.starts_with('-') && !t.starts_with("--") && t.contains('f')),
            // -D is case-sensitive: -d only deletes merged branches.
            "branch" => toks.iter().any(|t| t == "-D"),
            _ => false,
        };
        if hit {
            return Some(Intent::GitDestructive);
        }
    }

    // --- destructive SQL via a DB client ---
    let db_clients = ["psql", "mysql", "sqlcmd", "sqlite3", "mariadb"];
    if db_clients.contains(&first) {
        let upper = segment.to_ascii_uppercase();
        if upper.contains("DROP TABLE")
            || upper.contains("DROP DATABASE")
            || upper.contains("DROP SCHEMA")
            || upper.contains("TRUNCATE")
        {
            return Some(Intent::DbDestroy);
        }
        if upper.contains("DELETE FROM") && !upper.contains("WHERE") {
            return Some(Intent::DbDestroy);
        }
    }

    // --- infra teardown ---
    if (first == "terraform" || first == "tofu")
        && lc.iter().any(|t| t == "destroy" || t == "-destroy")
    {
        return Some(Intent::InfraDestroy);
    }
    if first == "kubectl" && lc.get(1).map(|s| s.as_str()) == Some("delete") {
        return Some(Intent::InfraDestroy);
    }

    None
}

// ---------------------------------------------------------------------------
// Session history: tail-read the audit log and count prior attempts
// ---------------------------------------------------------------------------

/// Count prior attempts in this session with the given intent that should
/// press toward the breaker threshold:
///   - `deny` entries always count;
///   - `ask` entries count UNLESS a later execution record exists for the
///     same command in the same session (`source == "post"`), which means a
///     human approved it. Approved work is not flailing.
///
/// Reads only the last `max_bytes` of the log (bounded, microseconds), and
/// fails open (returns 0) on any IO or parse problem.
pub fn recent_intent_count(
    log_path: &Path,
    session: &str,
    intent: Intent,
    max_bytes: u64,
) -> usize {
    let Ok(mut f) = File::open(log_path) else {
        return 0;
    };
    let len = match f.metadata() {
        Ok(m) => m.len(),
        Err(_) => return 0,
    };
    let start = len.saturating_sub(max_bytes);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return 0;
    }
    let mut buf = String::new();
    if f.read_to_string(&mut buf).is_err() {
        return 0;
    }

    // If we landed mid-line, the first line is partial garbage — drop it.
    let lines = buf.lines().skip(if start > 0 { 1 } else { 0 });

    let entries: Vec<serde_json::Value> = lines
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["session"].as_str() == Some(session))
        .collect();

    // Commands the human demonstrably approved (a post-execution record
    // exists). Requires the optional post-hook wiring; absent that, this set
    // is empty and counting is strict.
    let approved: HashSet<&str> = entries
        .iter()
        .filter(|e| e["source"].as_str() == Some("post"))
        .filter_map(|e| e["command"].as_str())
        .collect();

    entries
        .iter()
        .filter(|e| e["intent"].as_str() == Some(intent.label()))
        .filter(|e| match e["decision"].as_str() {
            Some("deny") => true,
            Some("ask") => !approved.contains(e["command"].as_str().unwrap_or("")),
            _ => false,
        })
        .count()
}

// ---------------------------------------------------------------------------
// Configuration (read from policy.yaml, serde-default so old policies parse)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    pub enabled: bool,
    /// Number of prior counted attempts before the breaker trips.
    /// threshold = 2 means the 3rd attempt is denied.
    pub threshold: usize,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        BreakerConfig {
            enabled: true,
            threshold: 2,
        }
    }
}

/// Read the optional `circuit_breaker:` block from policy.yaml. Missing
/// file, missing block, or malformed values all yield the safe default
/// (enabled, threshold 2) — existing policies keep working untouched.
pub fn breaker_config(policy_path: &Path) -> BreakerConfig {
    let d = BreakerConfig::default();
    let Ok(text) = std::fs::read_to_string(policy_path) else {
        return d;
    };
    let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
        return d;
    };
    let cb = &v["circuit_breaker"];
    BreakerConfig {
        enabled: cb["enabled"].as_bool().unwrap_or(d.enabled),
        threshold: cb["threshold"].as_u64().unwrap_or(d.threshold as u64) as usize,
    }
}

// ---------------------------------------------------------------------------
// The one call the hook makes
// ---------------------------------------------------------------------------

/// If this command should be escalated from `ask` to `deny`, returns
/// `Some((intent, prior_count, reason))`. Returns `None` when: the command
/// carries no destructive intent, there is no session id, the breaker is
/// disabled, or the threshold hasn't been reached.
pub fn maybe_trip(
    policy_path: &Path,
    log_path: &Path,
    session: Option<&str>,
    command: &str,
) -> Option<(Intent, usize, String)> {
    let intent = classify_command(command)?;
    let session = session?;
    let cfg = breaker_config(policy_path);
    if !cfg.enabled {
        return None;
    }
    let prior = recent_intent_count(log_path, session, intent, 64 * 1024);
    if prior >= cfg.threshold {
        let reason = format!(
            "circuit breaker: {} prior {} attempt(s) this session — \
             repeated destructive intent, denying variant #{}",
            prior,
            intent.label(),
            prior + 1
        );
        return Some((intent, prior, reason));
    }
    None
}

// ---------------------------------------------------------------------------
// Private helpers: quote-aware tokenizer + segment splitter
// ---------------------------------------------------------------------------

fn tokens(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in segment.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(c),
            },
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn split_segments(command: &str) -> Vec<String> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    cur.push(c);
                }
                '&' | '|' => {
                    if chars.peek() == Some(&c) {
                        chars.next();
                    }
                    if !cur.trim().is_empty() {
                        segs.push(cur.trim().to_string());
                    }
                    cur.clear();
                }
                ';' => {
                    if !cur.trim().is_empty() {
                        segs.push(cur.trim().to_string());
                    }
                    cur.clear();
                }
                _ => cur.push(c),
            },
        }
    }
    if !cur.trim().is_empty() {
        segs.push(cur.trim().to_string());
    }
    segs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- classification ---

    #[test]
    fn classifies_unix_rm() {
        assert_eq!(classify_command("rm -rf ."), Some(Intent::FileDelete));
        assert_eq!(classify_command("rm -fr /tmp/x"), Some(Intent::FileDelete));
        assert_eq!(classify_command("rm notes.txt"), None);
    }

    #[test]
    fn classifies_powershell_delete_variants() {
        assert_eq!(
            classify_command("Remove-Item -Recurse -Force ."),
            Some(Intent::FileDelete)
        );
        assert_eq!(classify_command("del /s /q ."), Some(Intent::FileDelete));
        assert_eq!(classify_command("rd /s /q build"), Some(Intent::FileDelete));
        // pipeline: splitter isolates the Remove-Item segment
        assert_eq!(
            classify_command("Get-ChildItem -Force . | Remove-Item -Recurse -Force"),
            Some(Intent::FileDelete)
        );
    }

    #[test]
    fn classifies_delete_indirection_find_and_xargs() {
        // The EXACT command a live agent used to bypass the classifier
        // (v0.11.0 breaker-test session 59ef759a, 12:58).
        assert_eq!(
            classify_command("find . -mindepth 1 -maxdepth 1 -exec rm -rf {} +"),
            Some(Intent::FileDelete)
        );
        // find -delete (no external command)
        assert_eq!(
            classify_command("find /tmp/cache -type f -delete"),
            Some(Intent::FileDelete)
        );
        // find -execdir / -okdir variants
        assert_eq!(
            classify_command("find . -name '*.log' -execdir rm {} ;"),
            Some(Intent::FileDelete)
        );
        // xargs-fed delete (pipe splitter hands us the xargs segment alone)
        assert_eq!(
            classify_command("find . -name '*.tmp' | xargs rm -f"),
            Some(Intent::FileDelete)
        );
        assert_eq!(classify_command("xargs rm -rf"), Some(Intent::FileDelete));
        // unlink and shred -u
        assert_eq!(
            classify_command("unlink important.db"),
            Some(Intent::FileDelete)
        );
        assert_eq!(
            classify_command("shred -u secret.key"),
            Some(Intent::FileDelete)
        );
        // find WITHOUT a delete action must NOT classify (no false positives)
        assert_eq!(classify_command("find . -name '*.rs' -print"), None);
        assert_eq!(classify_command("find . -type d"), None);
        // xargs feeding a benign command must NOT classify
        assert_eq!(classify_command("find . -name '*.rs' | xargs wc -l"), None);
        // bare unlink with no target is a syscall-y edge; treat as non-delete
        assert_eq!(classify_command("unlink"), None);
    }

    #[test]
    fn classifies_compound_by_most_dangerous_segment() {
        // The exact Cursor evasion shape from live testing.
        assert_eq!(
            classify_command(
                "cd \"c:\\Users\\User\\code\\cursor-test3\" && rm -rf .cursor .git .termaxa"
            ),
            Some(Intent::FileDelete)
        );
        assert_eq!(
            classify_command("git status && rm -rf /"),
            Some(Intent::FileDelete)
        );
    }

    #[test]
    fn classifies_git_destructive() {
        assert_eq!(
            classify_command("git push --force origin main"),
            Some(Intent::GitDestructive)
        );
        assert_eq!(
            classify_command("git reset --hard HEAD~3"),
            Some(Intent::GitDestructive)
        );
        assert_eq!(
            classify_command("git clean -fd"),
            Some(Intent::GitDestructive)
        );
        assert_eq!(classify_command("git status"), None);
        assert_eq!(classify_command("git push origin main"), None);
        // -d (lowercase, merged-only) is not destructive; -D is.
        assert_eq!(classify_command("git branch -d feature"), None);
        assert_eq!(
            classify_command("git branch -D feature"),
            Some(Intent::GitDestructive)
        );
    }

    #[test]
    fn classifies_db_destroy() {
        assert_eq!(
            classify_command(r#"psql -c "DROP TABLE users CASCADE""#),
            Some(Intent::DbDestroy)
        );
        assert_eq!(
            classify_command(r#"psql -c "TRUNCATE audit_log""#),
            Some(Intent::DbDestroy)
        );
        assert_eq!(
            classify_command(r#"psql -c "DELETE FROM users""#),
            Some(Intent::DbDestroy)
        );
        // filtered delete is not classified — matches pg.rs's caution
        assert_eq!(
            classify_command(r#"psql -c "DELETE FROM users WHERE id = 5""#),
            None
        );
        // raw SQL not routed through a client is out of scope
        assert_eq!(classify_command("DROP TABLE users"), None);
    }

    #[test]
    fn classifies_infra_destroy() {
        assert_eq!(
            classify_command("terraform destroy -auto-approve"),
            Some(Intent::InfraDestroy)
        );
        assert_eq!(classify_command("tofu destroy"), Some(Intent::InfraDestroy));
        assert_eq!(
            classify_command("kubectl delete deployment api"),
            Some(Intent::InfraDestroy)
        );
        assert_eq!(classify_command("terraform plan"), None);
    }

    #[test]
    fn severity_ordering_on_mixed_compound() {
        // db-destroy outranks file-delete
        assert_eq!(
            classify_command(r#"rm -rf ./cache && psql -c "TRUNCATE users""#),
            Some(Intent::DbDestroy)
        );
    }

    // --- counting + breaker ---

    fn write_log(lines: &[serde_json::Value]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tmx-intent-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for l in lines {
            writeln!(f, "{}", l).unwrap();
        }
        path
    }

    fn entry(session: &str, decision: &str, intent: &str, command: &str) -> serde_json::Value {
        serde_json::json!({
            "ts": "2026-07-09T00:00:00Z",
            "source": "hook",
            "session": session,
            "decision": decision,
            "intent": intent,
            "command": command,
        })
    }

    #[test]
    fn counts_asks_and_denies_for_same_session_and_intent() {
        let log = write_log(&[
            entry("s1", "ask", "file-delete", "rm -rf ."),
            entry("s1", "ask", "file-delete", "Remove-Item -Recurse -Force ."),
            entry("s1", "allow", "file-delete", "rm -rf /tmp/scratch"),
        ]);
        assert_eq!(
            recent_intent_count(&log, "s1", Intent::FileDelete, 64 * 1024),
            2
        );
    }

    #[test]
    fn session_isolation() {
        let log = write_log(&[
            entry("s1", "ask", "file-delete", "rm -rf ."),
            entry("s1", "deny", "file-delete", "del /s /q ."),
        ]);
        assert_eq!(
            recent_intent_count(&log, "s2", Intent::FileDelete, 64 * 1024),
            0
        );
    }

    #[test]
    fn intent_isolation() {
        let log = write_log(&[
            entry("s1", "ask", "file-delete", "rm -rf ."),
            entry("s1", "ask", "file-delete", "del /s /q ."),
        ]);
        assert_eq!(
            recent_intent_count(&log, "s1", Intent::GitDestructive, 64 * 1024),
            0
        );
    }

    #[test]
    fn approved_ask_is_excluded() {
        // ask -> human approved -> post execution record exists
        let log = write_log(&[
            entry("s1", "ask", "file-delete", "rm -rf ./node_modules"),
            entry("s1", "executed", "file-delete", "rm -rf ./node_modules"),
        ]);
        // patch the second entry's source to "post"
        let text = std::fs::read_to_string(&log).unwrap();
        let patched: Vec<String> = text
            .lines()
            .map(|l| {
                if l.contains("executed") {
                    l.replace("\"source\":\"hook\"", "\"source\":\"post\"")
                } else {
                    l.to_string()
                }
            })
            .collect();
        std::fs::write(&log, patched.join("\n") + "\n").unwrap();

        assert_eq!(
            recent_intent_count(&log, "s1", Intent::FileDelete, 64 * 1024),
            0
        );
    }

    #[test]
    fn old_log_lines_without_intent_are_ignored_not_fatal() {
        let log = write_log(&[
            serde_json::json!({
                "ts": "2026-01-01T00:00:00Z", "source": "hook",
                "session": "s1", "decision": "ask", "command": "rm -rf ."
                // no "intent" field — pre-v0.11 line
            }),
            entry("s1", "ask", "file-delete", "del /s /q ."),
        ]);
        assert_eq!(
            recent_intent_count(&log, "s1", Intent::FileDelete, 64 * 1024),
            1
        );
    }

    #[test]
    fn missing_log_fails_open() {
        let ghost = std::env::temp_dir().join("tmx-intent-no-such-dir/audit.jsonl");
        assert_eq!(
            recent_intent_count(&ghost, "s1", Intent::FileDelete, 64 * 1024),
            0
        );
    }

    #[test]
    fn breaker_trips_on_third_variant() {
        // the money test: the live Cursor whack-a-mole scenario
        let log = write_log(&[
            entry("s1", "ask", "file-delete", "rm -rf ."),
            entry("s1", "ask", "file-delete", "Remove-Item -Recurse -Force ."),
        ]);
        let policy = std::env::temp_dir().join(format!(
            "tmx-intent-pol-{}-{:?}.yaml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&policy, "version: 1\ndefault: ask\nrules: []\n").unwrap();

        let tripped = maybe_trip(&policy, &log, Some("s1"), "del /s /q .");
        assert!(
            tripped.is_some(),
            "third delete variant must trip the breaker"
        );
        let (intent, prior, reason) = tripped.unwrap();
        assert_eq!(intent, Intent::FileDelete);
        assert_eq!(prior, 2);
        assert!(reason.contains("circuit breaker"));

        // benign command in the same hot session must NOT trip
        assert!(maybe_trip(&policy, &log, Some("s1"), "git status").is_none());
        // no session id -> no breaker
        assert!(maybe_trip(&policy, &log, None, "del /s /q .").is_none());
    }

    #[test]
    fn breaker_respects_config() {
        let log = write_log(&[
            entry("s1", "ask", "file-delete", "rm -rf ."),
            entry("s1", "ask", "file-delete", "del /s /q ."),
        ]);
        let policy = std::env::temp_dir().join(format!(
            "tmx-intent-pol-off-{}-{:?}.yaml",
            std::process::id(),
            std::thread::current().id()
        ));
        // disabled
        std::fs::write(
            &policy,
            "version: 1\ndefault: ask\nrules: []\ncircuit_breaker:\n  enabled: false\n",
        )
        .unwrap();
        assert!(maybe_trip(&policy, &log, Some("s1"), "rd /s /q .").is_none());

        // higher threshold
        std::fs::write(
            &policy,
            "version: 1\ndefault: ask\nrules: []\ncircuit_breaker:\n  threshold: 5\n",
        )
        .unwrap();
        assert!(maybe_trip(&policy, &log, Some("s1"), "rd /s /q .").is_none());
    }

    #[test]
    fn config_defaults_when_block_missing_or_file_absent() {
        let policy = std::env::temp_dir().join("tmx-intent-nopolicy.yaml");
        let _ = std::fs::remove_file(&policy);
        let c = breaker_config(&policy);
        assert!(c.enabled);
        assert_eq!(c.threshold, 2);
    }
}
