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
//! This module keeps its own light tokenizer, but segment splitting is
//! shared with the policy engine (`shell::split_segments`) on purpose: when
//! the two had separate copies they disagreed, and a classifier that reads a
//! command differently from the gate is worse than no classifier.

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
    /// Destruction by OVERWRITE rather than deletion: `cmd > existing-file`.
    /// Nothing is removed; the contents are replaced. v0.15 — see #14.
    FileOverwrite,
}

impl Intent {
    pub fn label(&self) -> &'static str {
        match self {
            Intent::FileDelete => "file-delete",
            Intent::DbDestroy => "db-destroy",
            Intent::GitDestructive => "git-destructive",
            Intent::InfraDestroy => "infra-destroy",
            Intent::FileOverwrite => "file-overwrite",
        }
    }

    /// Severity rank used when a compound command carries several intents:
    /// the most severe one is reported (and therefore counted).
    fn rank(&self) -> u8 {
        match self {
            Intent::DbDestroy => 4,
            Intent::InfraDestroy => 3,
            Intent::FileDelete => 2,
            // Same destructive weight as a delete: the file is gone either way.
            Intent::FileOverwrite => 2,
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
    crate::shell::split_segments(command)
        .iter()
        .filter_map(classify_segment)
        .max_by_key(|i| i.rank())
}

/// A truncating redirect destroys whatever was at the target. Checked before
/// command-name classification, because the destructive part is the operator
/// rather than the program: `cat`, `echo` and `ls` are all read-only commands
/// right up until a `>` is attached to them. Reads the redirects the segment
/// arrived with — the split found them; nothing re-scans.
fn overwrite_intent(segment: &crate::shell::Segment) -> Option<Intent> {
    segment
        .redirects
        .iter()
        .any(|o| o.truncates)
        .then_some(Intent::FileOverwrite)
}

/// Classify one shell segment. Returns `None` for benign commands.
///
/// Scope is deliberately limited to *commands*: `python -c "shutil.rmtree(...)"`
/// will not classify. That is the cooperative-gate boundary SECURITY.md
/// documents; the breaker is a speed bump for syntax variation, not a sandbox.
fn classify_segment(segment: &crate::shell::Segment) -> Option<Intent> {
    // Both classifications, highest rank wins, the command-name one on ties.
    // NOT an early return on the overwrite: `psql -c "DROP TABLE u" > out.sql`
    // is db-destroy (rank 4) that also writes a file, and the first draft
    // demoted it to file-overwrite (rank 2) — every destructive command that
    // logs its output lost the rank the breaker keys on.
    let base = classify_segment_named(segment);
    let ow = overwrite_intent(segment);
    match (base, ow) {
        (Some(b), Some(o)) => Some(if b.rank() >= o.rank() { b } else { o }),
        (b, o) => b.or(o),
    }
}

/// Classification by command name and flags — everything except the
/// overwrite operator, which `classify_segment` merges in above.
fn classify_segment_named(segment: &str) -> Option<Intent> {
    let toks = tokens(segment);
    if toks.is_empty() {
        return None;
    }
    // The command's real head, past any wrapper, normalized the same way the
    // delete extractor and the insurance layer normalize it. Reading token
    // zero raw is what made `sudo rm -rf x`, `/bin/rm -rf x` and
    // `C:\Windows\System32\del.exe /s /q x` all classify as nothing.
    let (head, at) = crate::delete::resolve_head(&toks)?;
    let first = head.as_str();
    // Arguments begin after the command, which is `at`, not 0.
    let lc: Vec<String> = toks[at..].iter().map(|t| t.to_ascii_lowercase()).collect();

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
            // A leading `+` on a refspec IS a force push — `git push origin
            // +main` and `git push origin --force main` do the same thing,
            // and `+` is the only meaning `git push` gives that character.
            "push" => lc.iter().any(|t| {
                t == "--force" || t == "-f" || t == "--force-with-lease" || t.starts_with('+')
            }),
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
        // A file-overwrite counts as destructive pressure only when a RULE
        // objected. A default-ask on `cargo build > build.log` is the policy
        // having no opinion — the decline-not-allow principle applied to the
        // breaker. Without this, the third redirected build log of any real
        // session was DENIED (threshold 2), because agents redirect
        // constantly and every redirect accumulated toward a trip.
        .filter(|e| intent != Intent::FileOverwrite || e["matched_rule"].as_str().is_some())
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

pub fn tokens(segment: &str) -> Vec<String> {
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

// Segment splitting is delegated to `shell::split_segments` — the SAME
// function the policy engine uses.
//
// This module used to carry its own copy, and the copies disagreed. The local
// one split on a lone `&` but not on newlines; `shell`'s did the reverse. So
// `git status & rm -rf /` classified correctly and was allowed anyway, while
// `"git status\nrm -rf /"` was denied by policy but invisible to the breaker's
// counter. Two parsers for one grammar is the failure `delete::command_head`
// was introduced to end; this is the same fix applied to the same shape of
// bug.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempTree;

    /// #14 / #12. Destruction by overwrite: nothing is deleted, the contents
    /// are replaced. `cat`, `echo` and `ls` are read-only commands right up
    /// until a `>` is attached, so this classifies on the operator.
    #[test]
    fn a_truncating_redirect_is_a_destructive_intent() {
        for cmd in [
            "cat /dev/null > .env",
            "echo '' > config.json",
            "ls -la > /etc/hosts",
            "grep -r . / > /tmp/exfil",
            // `>|` clobbers past noclobber. Until v0.16 §1.5 the splitter cut
            // this at the `|`, so intent classified it None while backup
            // insured it — two engines disagreeing about one command.
            "cmd >| forced.txt",
        ] {
            assert_eq!(
                classify_command(cmd),
                Some(Intent::FileOverwrite),
                "{cmd} destroys a file by writing over it"
            );
        }
    }

    /// v0.16: a wrapper program hid the real command from every engine.
    /// Measured before the fix - each of these classified as `None`, so no
    /// intent, no breaker pressure, and (via the same head resolution) no
    /// insurance. The wrapper is not the danger; reading token zero as the
    /// command was.
    #[test]
    fn a_wrapper_does_not_hide_the_command_it_runs() {
        for cmd in [
            "sudo rm -rf ./dist",
            "doas rm -rf /",
            "env rm -rf ./dist",
            "env FOO=1 rm -rf ./dist",
            "sudo -u alice rm -rf ./dist",
            "nice -n 10 rm -rf x",
            "nohup rm -rf x",
            "command rm -rf x",
        ] {
            assert_eq!(
                classify_command(cmd),
                Some(Intent::FileDelete),
                "{cmd}: the wrapper must not hide the delete"
            );
        }
        // Not only deletes: a wrapper blanked the WHOLE classifier.
        assert_eq!(
            classify_command("sudo terraform destroy -auto-approve"),
            Some(Intent::InfraDestroy),
        );

        // Control legs. A wrapper with no command after it names nothing to
        // judge, and the word only counts in command position - otherwise
        // `echo sudo rm` would classify as a delete.
        for cmd in ["sudo", "sudo -u alice", "env FOO=1", "echo sudo rm -rf x"] {
            assert_eq!(classify_command(cmd), None, "{cmd} must not classify");
        }
    }

    /// The head is normalized by path and extension, as `delete.rs` always
    /// normalized it. These two modules disagreed: the Windows full-path form
    /// was a recognised delete to the extractor and nothing to the
    /// classifier, on the platform where every dialect bug has happened.
    #[test]
    fn a_path_qualified_command_is_the_command_it_names() {
        for cmd in [
            "/bin/rm -rf ./dist",
            "/usr/bin/rm -rf ./dist",
            "C:\\Windows\\System32\\del.exe /s /q x",
        ] {
            assert_eq!(
                classify_command(cmd),
                Some(Intent::FileDelete),
                "{cmd}: a path-qualified delete is still a delete"
            );
        }
        // Control leg - a path-qualified harmless command stays harmless.
        assert_eq!(classify_command("/bin/ls -la"), None);
    }

    /// Appending does not destroy, descriptor plumbing names no file, and a
    /// SINK is a discard device — truncating /dev/null destroys nothing.
    /// Classifying any of these fires on every build command in existence.
    #[test]
    fn appends_descriptors_and_sinks_are_not_destructive() {
        for cmd in [
            "echo entry >> app.log",
            "make 2>&1",
            "cmd >&2",
            "npm run build &> build.log",
            "cargo test > /dev/null",
            "cmd 2> /dev/null",
            "make >/dev/null 2>&1",
        ] {
            assert_eq!(classify_command(cmd), None, "{cmd} must not classify");
        }
    }

    /// A redirect never DEMOTES a higher-ranked intent. The first draft
    /// early-returned on the overwrite check, so a destructive command that
    /// also logged its output lost the rank the breaker keys on.
    #[test]
    fn a_redirect_never_downgrades_a_higher_intent() {
        assert_eq!(
            classify_command("psql -c \"DROP TABLE users\" > out.sql"),
            Some(Intent::DbDestroy),
            "db-destroy (4) must not demote to file-overwrite (2)"
        );
        assert_eq!(
            classify_command("terraform destroy -auto-approve > tf.log"),
            Some(Intent::InfraDestroy)
        );
        assert_eq!(
            classify_command("rm -rf build > rm.log"),
            Some(Intent::FileDelete),
            "equal ranks: the command-name classification wins the tie"
        );
    }

    /// The breaker half of decline-not-allow: a file-overwrite adds pressure
    /// only when a RULE objected. Two default-ask build logs (matched_rule
    /// null) must not cause the third to trip; three gated attempts must.
    #[test]
    fn only_gated_overwrites_accumulate_breaker_pressure() {
        let tmp = TempTree::new("intent-ow");
        let ungated = write_log(
            &tmp,
            &[
                entry_with_rule(
                    "s1",
                    "ask",
                    "file-overwrite",
                    "cargo build > build.log",
                    None,
                ),
                entry_with_rule("s1", "ask", "file-overwrite", "cargo test > test.log", None),
            ],
        );
        assert_eq!(
            recent_intent_count(&ungated, "s1", Intent::FileOverwrite, 64 * 1024),
            0,
            "default-ask overwrites are the policy having no opinion"
        );

        let tmp2 = TempTree::new("intent-ow2");
        let gated = write_log(
            &tmp2,
            &[
                entry_with_rule(
                    "s1",
                    "deny",
                    "file-overwrite",
                    "cat /dev/null > .env",
                    Some("*> .env*"),
                ),
                entry_with_rule(
                    "s1",
                    "deny",
                    "file-overwrite",
                    "echo '' > .env",
                    Some("*> .env*"),
                ),
                entry_with_rule(
                    "s1",
                    "deny",
                    "file-overwrite",
                    "true > .env",
                    Some("*> .env*"),
                ),
            ],
        );
        assert_eq!(
            recent_intent_count(&gated, "s1", Intent::FileOverwrite, 64 * 1024),
            3,
            "gated overwrite attempts count in full"
        );
    }

    /// A compound where the overwrite is not the first segment. The most
    /// severe intent governs, as it does for every other class.
    #[test]
    fn an_overwrite_is_found_in_a_compound() {
        assert_eq!(
            classify_command("git status && echo x > .env"),
            Some(Intent::FileOverwrite)
        );
    }

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
    fn a_plus_refspec_is_a_force_push() {
        // `git push origin +main` overwrites the remote branch exactly as
        // `--force` does; the flag spelling was the only one the breaker
        // could see.
        for cmd in [
            "git push origin +main",
            "git push origin +main:main",
            "git push origin +refs/heads/main:refs/heads/main",
            "git push origin +HEAD:production",
        ] {
            assert_eq!(classify_command(cmd), Some(Intent::GitDestructive), "{cmd}");
        }
        // A plain push is still a plain push, and `+` outside `git push`
        // means nothing here.
        assert_eq!(classify_command("git push origin main:main"), None);
        assert_eq!(classify_command("git log --format=+%h"), None);
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

    /// The tree must outlive the path it hands back, so the caller holds it.
    /// Before the guard existed this wrote to a pid+thread path that nothing
    /// ever removed, which is where most of the /tmp litter came from.
    fn write_log(tmp: &TempTree, lines: &[serde_json::Value]) -> std::path::PathBuf {
        let mut body = String::new();
        for l in lines {
            body.push_str(&format!("{}\n", l));
        }
        tmp.file("audit.jsonl", &body)
    }

    fn entry_with_rule(
        session: &str,
        decision: &str,
        intent: &str,
        command: &str,
        matched_rule: Option<&str>,
    ) -> serde_json::Value {
        let mut e = entry(session, decision, intent, command);
        if let Some(r) = matched_rule {
            e["matched_rule"] = serde_json::json!(r);
        }
        e
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
        let tmp = TempTree::new("intent");
        let log = write_log(
            &tmp,
            &[
                entry("s1", "ask", "file-delete", "rm -rf ."),
                entry("s1", "ask", "file-delete", "Remove-Item -Recurse -Force ."),
                entry("s1", "allow", "file-delete", "rm -rf /tmp/scratch"),
            ],
        );
        assert_eq!(
            recent_intent_count(&log, "s1", Intent::FileDelete, 64 * 1024),
            2
        );
    }

    #[test]
    fn session_isolation() {
        let tmp = TempTree::new("intent");
        let log = write_log(
            &tmp,
            &[
                entry("s1", "ask", "file-delete", "rm -rf ."),
                entry("s1", "deny", "file-delete", "del /s /q ."),
            ],
        );
        assert_eq!(
            recent_intent_count(&log, "s2", Intent::FileDelete, 64 * 1024),
            0
        );
    }

    #[test]
    fn intent_isolation() {
        let tmp = TempTree::new("intent");
        let log = write_log(
            &tmp,
            &[
                entry("s1", "ask", "file-delete", "rm -rf ."),
                entry("s1", "ask", "file-delete", "del /s /q ."),
            ],
        );
        assert_eq!(
            recent_intent_count(&log, "s1", Intent::GitDestructive, 64 * 1024),
            0
        );
    }

    #[test]
    fn approved_ask_is_excluded() {
        // ask -> human approved -> post execution record exists
        let tmp = TempTree::new("intent");
        let log = write_log(
            &tmp,
            &[
                entry("s1", "ask", "file-delete", "rm -rf ./node_modules"),
                entry("s1", "executed", "file-delete", "rm -rf ./node_modules"),
            ],
        );
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
        let tmp = TempTree::new("intent");
        let log = write_log(
            &tmp,
            &[
                serde_json::json!({
                    "ts": "2026-01-01T00:00:00Z", "source": "hook",
                    "session": "s1", "decision": "ask", "command": "rm -rf ."
                    // no "intent" field — pre-v0.11 line
                }),
                entry("s1", "ask", "file-delete", "del /s /q ."),
            ],
        );
        assert_eq!(
            recent_intent_count(&log, "s1", Intent::FileDelete, 64 * 1024),
            1
        );
    }

    #[test]
    fn missing_log_fails_open() {
        let tmp = TempTree::new("intent-ghost");
        let ghost = tmp.absent("no-such-dir/audit.jsonl");
        assert_eq!(
            recent_intent_count(&ghost, "s1", Intent::FileDelete, 64 * 1024),
            0
        );
    }

    #[test]
    fn breaker_trips_on_third_variant() {
        // the money test: the live Cursor whack-a-mole scenario
        let tmp = TempTree::new("intent");
        let log = write_log(
            &tmp,
            &[
                entry("s1", "ask", "file-delete", "rm -rf ."),
                entry("s1", "ask", "file-delete", "Remove-Item -Recurse -Force ."),
            ],
        );
        let policy = tmp.file("policy.yaml", "version: 1\ndefault: ask\nrules: []\n");

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
        let tmp = TempTree::new("intent");
        let log = write_log(
            &tmp,
            &[
                entry("s1", "ask", "file-delete", "rm -rf ."),
                entry("s1", "ask", "file-delete", "del /s /q ."),
            ],
        );
        // disabled
        let policy = tmp.file(
            "policy.yaml",
            "version: 1\ndefault: ask\nrules: []\ncircuit_breaker:\n  enabled: false\n",
        );
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
        let tmp = TempTree::new("intent-nopolicy");
        let policy = tmp.absent("policy.yaml");
        let c = breaker_config(&policy);
        assert!(c.enabled);
        assert_eq!(c.threshold, 2);
    }

    // -----------------------------------------------------------------------
    // Spellings. Every predicate below decides whether a command presses the
    // circuit breaker, so a flag it fails to recognise is a command that
    // accumulates no pressure at all.
    // -----------------------------------------------------------------------

    #[test]
    fn the_most_severe_intent_in_a_compound_is_the_one_reported() {
        // Ordered worst-first on purpose: a ranking that returned a constant
        // would still pick the last one and look correct.
        assert_eq!(
            classify_command(r#"psql -c "DROP TABLE users" && rm -rf ./build"#),
            Some(Intent::DbDestroy)
        );
    }

    #[test]
    fn a_delete_counts_when_it_is_recursive_or_forced_in_any_dialect() {
        for command in [
            "rm -r ./dir",
            "rm -f notes.txt",
            "rm -rf ./dir",
            "rm --force notes.txt",
            "del /s C:\\tmp",
            "del /q C:\\tmp",
            "Remove-Item -Recurse ./dir",
            "Remove-Item -Force notes.txt",
        ] {
            assert_eq!(
                classify_command(command),
                Some(Intent::FileDelete),
                "{command}"
            );
        }
        // A single-file delete with no force and no recursion is ordinary work.
        assert_eq!(classify_command("rm notes.txt"), None);
    }

    #[test]
    fn a_long_flag_that_merely_contains_the_letter_is_not_the_short_flag() {
        // `-r` and `-f` are read out of bundled short flags, so the letter
        // test must not reach into long options that happen to spell one.
        // All three are real rm options: the first two carry an `r`, and
        // `--one-file-system` carries an `f`.
        assert_eq!(classify_command("rm --verbose notes.txt"), None);
        assert_eq!(classify_command("rm --preserve-root notes.txt"), None);
        assert_eq!(classify_command("rm --one-file-system ./dir"), None);
    }

    #[test]
    fn find_and_xargs_count_only_when_they_invoke_a_delete() {
        for command in [
            "find . -delete",
            "find . -mindepth 1 -exec rm -rf {} +",
            "find . -execdir unlink {} ;",
            "xargs rm -rf",
        ] {
            assert_eq!(
                classify_command(command),
                Some(Intent::FileDelete),
                "{command}"
            );
        }
        // An -exec that runs something harmless is not a delete.
        assert_eq!(classify_command("find . -exec ls {} +"), None);
        assert_eq!(classify_command("xargs ls -la"), None);
    }

    #[test]
    fn shred_counts_only_when_it_also_removes() {
        assert_eq!(
            classify_command("shred -u secrets.txt"),
            Some(Intent::FileDelete)
        );
        assert_eq!(
            classify_command("shred --remove secrets.txt"),
            Some(Intent::FileDelete)
        );
        // Overwriting in place leaves the file there.
        assert_eq!(classify_command("shred secrets.txt"), None);
        // And the flag belongs to shred, not to whatever else spells it.
        assert_eq!(classify_command("ls -u"), None);
    }

    #[test]
    fn every_git_spelling_that_destroys_history_is_recognised() {
        for command in [
            "git push --force origin main",
            "git push -f origin main",
            "git push --force-with-lease origin main",
            "git push origin +main",
            "git reset --hard HEAD~3",
            "git branch -D feature",
        ] {
            assert_eq!(
                classify_command(command),
                Some(Intent::GitDestructive),
                "{command}"
            );
        }
        for benign in [
            "git push origin main",
            "git reset --soft HEAD~1",
            "git branch -d merged-feature",
        ] {
            assert_eq!(classify_command(benign), None, "{benign}");
        }
    }

    /// KNOWN GAP, pinned so a fix flips it deliberately rather than by
    /// accident: `git clean -f` is classified and `git clean --force` is not.
    /// The two spellings delete the same untracked files. The rm predicate a
    /// few lines above handles its own long form by listing `--force`
    /// explicitly; this one only reads bundled short flags, so the long
    /// spelling presses nothing toward the breaker and shows no intent in the
    /// report.
    #[test]
    fn git_clean_recognises_only_the_short_force_flag() {
        assert_eq!(
            classify_command("git clean -f"),
            Some(Intent::GitDestructive)
        );
        assert_eq!(
            classify_command("git clean -fd"),
            Some(Intent::GitDestructive)
        );
        assert_eq!(
            classify_command("git clean --force"),
            None,
            "if this ever starts classifying, the gap was fixed and this test \
             should be inverted rather than deleted"
        );
        // A dry run destroys nothing either way.
        assert_eq!(classify_command("git clean -n"), None);
    }

    #[test]
    fn destructive_sql_is_recognised_through_a_db_client() {
        for sql in [
            "DROP TABLE users",
            "DROP DATABASE shop",
            "DROP SCHEMA public CASCADE",
            "TRUNCATE users",
            "DELETE FROM users",
        ] {
            assert_eq!(
                classify_command(&format!(r#"psql -d shop -c "{sql}""#)),
                Some(Intent::DbDestroy),
                "{sql}"
            );
        }
        // A bounded delete is ordinary work, and a read is not destruction.
        assert_eq!(
            classify_command(r#"psql -d shop -c "DELETE FROM users WHERE id = 1""#),
            None
        );
        assert_eq!(classify_command(r#"psql -d shop -c "SELECT 1""#), None);
    }

    #[test]
    fn infrastructure_teardown_is_recognised_by_its_verb() {
        for command in [
            "terraform destroy",
            "tofu destroy",
            "kubectl delete pod web",
        ] {
            assert_eq!(
                classify_command(command),
                Some(Intent::InfraDestroy),
                "{command}"
            );
        }
        for benign in ["terraform plan", "kubectl get pods"] {
            assert_eq!(classify_command(benign), None, "{benign}");
        }
    }

    // -----------------------------------------------------------------------
    // The tail read. The breaker only sees what this window returns, so its
    // size and its boundary decide whether repeated attempts accumulate.
    // -----------------------------------------------------------------------

    /// A log of `n` entries, every line padded to exactly `LINE` bytes so the
    /// read window can be aligned on a line boundary on purpose.
    fn padded_log(dir: &std::path::Path, n: usize) -> std::path::PathBuf {
        const LINE: usize = 1024;
        let path = dir.join("audit.jsonl");
        let mut out = String::new();
        for i in 0..n {
            let mut entry = serde_json::json!({
                "session": "sess-1",
                "source": "hook",
                "command": format!("rm -rf ./dir{i}"),
                "decision": "deny",
                "intent": Intent::FileDelete.label(),
                "pad": "",
            });
            let base = serde_json::to_string(&entry).expect("entry must serialize");
            // -1 for the newline this line will carry.
            let pad = LINE - 1 - base.len();
            entry["pad"] = serde_json::Value::String("x".repeat(pad));
            let line = serde_json::to_string(&entry).expect("entry must serialize");
            assert_eq!(
                line.len(),
                LINE - 1,
                "every line must be exactly {LINE} bytes"
            );
            out.push_str(&line);
            out.push('\n');
        }
        std::fs::write(&path, out).expect("log must be writable");
        path
    }

    #[test]
    fn the_window_reads_back_the_bytes_it_promises() {
        let tmp = TempTree::new("intent-window");
        // 128 KiB of log: twice the window, so the count is decided by the
        // window size rather than by how much was written.
        let log = padded_log(tmp.path(), 128);

        let counted = recent_intent_count(&log, "sess-1", Intent::FileDelete, 64 * 1024);
        assert_eq!(
            counted, 63,
            "64 KiB holds 64 lines, and the one the window lands on top of is \
             dropped as possibly partial"
        );

        // A smaller window sees proportionally less, which is what makes the
        // constant load-bearing.
        let counted = recent_intent_count(&log, "sess-1", Intent::FileDelete, 8 * 1024);
        assert_eq!(counted, 7);
    }

    #[test]
    fn the_breaker_looks_back_further_than_a_line_or_two() {
        // The window is the whole reason repeated attempts accumulate.
        // Shrink it and a session that is plainly flailing reads as a first
        // offence, which is the failure mode the breaker exists to prevent.
        let tmp = TempTree::new("intent-trip-window");
        let log = padded_log(tmp.path(), 128);
        let policy = tmp.file(
            "policy.yaml",
            "version: 1\ndefault: ask\nrules: []\ncircuit_breaker:\n  enabled: true\n  threshold: 5\n",
        );

        let (intent, prior, _reason) =
            maybe_trip(&policy, &log, Some("sess-1"), "rm -rf ./another")
                .expect("dozens of prior denied attempts is well past a threshold of 5");
        assert_eq!(intent, Intent::FileDelete);
        assert!(
            prior >= 60,
            "the window must reach back across the whole log, counted {prior}"
        );
    }

    #[test]
    fn a_log_smaller_than_the_window_is_read_whole() {
        // start == 0, so there is no partial first line to drop, and dropping
        // one anyway would lose a real attempt.
        let tmp = TempTree::new("intent-whole");
        let log = padded_log(tmp.path(), 4);

        assert_eq!(
            recent_intent_count(&log, "sess-1", Intent::FileDelete, 64 * 1024),
            4
        );
    }
}
