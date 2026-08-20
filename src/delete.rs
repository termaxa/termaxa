//! File-delete blast radius.
//!
//! Every other preview engine answers "what will this destroy?" with a real
//! number — commits lost, rows affected, resources destroyed. Deletes were the
//! gap: the most common destructive command produced no preview at all.
//!
//! Field report (r/ClaudeCode, Aug 2026): an agent wrote a backup to a
//! mistyped path (`/c/Users/harih` — Git Bash style — instead of
//! `C:\Users\harih`), then ran `rm -rf "/c/Users/harih"` to clean up its own
//! mistake, believing that path was the stray folder it had just created. It
//! was the user's real profile: SSH private keys, Documents (70,201 files),
//! AppData. The agent's own postmortem counted the damage AFTER the fact,
//! with a loop over the same directories. Every number it printed existed
//! before the command ran. Nobody looked.
//!
//! So: look. Three tiers, cheapest first, each independently useful:
//!   1. FREE     — resolved target, outside-project-root, is-a-user-profile
//!   2. CHEAP    — sensitive children (.ssh/.aws/.gnupg/.env) one level deep
//!   3. BUDGETED — recursive file count, capped by BOTH file count and time
//!
//! Honesty rules, same as everywhere:
//!   * We report what the path CONTAINS. We cannot know what the author
//!     INTENDED — nothing here would have detected that the path had a typo
//!     in it. Making the gap visible is the whole contribution.
//!   * A capped count says it was capped. "5,000+" is not "5,000".
//!   * Any failure yields `None` and enforcement proceeds unchanged. A
//!     preview must never block or break a decision.

use crate::preview::Preview;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Hard budget for the recursive scan. This runs synchronously inside a hook
// while the agent waits, so it must be bounded on BOTH axes: a fast SSD with
// a million small files blows the count cap, a cold network drive blows the
// time cap. Whichever hits first, we stop and say so.
const MAX_FILES: usize = 5_000;
const MAX_TIME: Duration = Duration::from_millis(300);

// Directory/file names whose presence changes the severity of a delete
// regardless of how many files are involved. Losing one of these costs more
// than losing ten thousand build artifacts.
const SENSITIVE: &[(&str, &str)] = &[
    (".ssh", "SSH private keys"),
    (".aws", "AWS credentials"),
    (".gnupg", "GPG keys"),
    (".kube", "Kubernetes credentials"),
    (".docker", "Docker credentials"),
    (".env", "environment secrets"),
    (".git", "git history"),
    ("id_rsa", "SSH private key"),
    ("id_ed25519", "SSH private key"),
    ("credentials", "credentials file"),
    (".npmrc", "npm tokens"),
    (".pypirc", "PyPI tokens"),
    (".netrc", "stored logins"),
];

pub fn preview_for(command: &str, project_root: Option<&Path>, cwd: &Path) -> Option<Preview> {
    let targets = extract_targets_detailed(command);
    if targets.is_empty() {
        return None;
    }

    let mut lines = Vec::new();
    let mut summary_parts: Vec<String> = Vec::new();
    let mut worst_first: Vec<String> = Vec::new();
    // Roadmap 2.5: whether anything here is beyond the reach of insurance.
    // Computed while the preview walks its targets; reported, not acted on.
    let mut uninsurable = false;

    for tok in targets.iter().take(3) {
        let raw = &tok.text;

        // Issue #11: a target carrying a variable the shell has not expanded
        // yet. `resolve_path_in` would happily join `x/$SID` onto the cwd and
        // print a real-looking path that will never exist — while the path the
        // shell actually deletes, if `$SID` is empty, is the parent. Both
        // public incidents (the `$TEMP_WT` worktree wipe, Codex's `$HOME`
        // cleanup) ran on exactly that gap between the written string and the
        // executed path. `resolve::target` has refused to resolve these since
        // v0.16; the preview is the reader a human sees, so it must refuse
        // too — an admitted unknown, not a confident wrong answer.
        if tok.has_unexpanded_var() {
            lines.push(format!("  target      : {}", raw));
            lines.push(
                "  ⚠ UNRESOLVED: contains a shell variable — if empty at execution, \
                 the delete lands on a different path than written"
                    .into(),
            );
            lines.push(
                "  ✗ insurance : cannot back up a path unknown until the shell expands it \
                 — NOT recoverable"
                    .into(),
            );
            worst_first.push("UNRESOLVED variable in target".into());
            uninsurable = true;
            summary_parts.push(format!("{} — unresolved variable", short(raw)));
            continue;
        }

        let resolved = resolve_path_in(raw, cwd);
        let display = resolved.display().to_string();

        lines.push(format!("  target      : {}", display));
        // Only worth showing when the resolution genuinely changed the path
        // in a way a reader would miss — a drive conversion (`/c/...` ->
        // `C:\...`) or a `~` expansion. Echoing an identical path back, or
        // showing `./target` beside its absolute form, is noise that trains
        // people to skip the block.
        let raw_norm = raw.trim_matches('"').replace('\\', "/").to_lowercase();
        let disp_norm = display.replace('\\', "/").to_lowercase();
        let cosmetic = raw_norm == disp_norm
            || disp_norm.ends_with(&raw_norm.trim_start_matches("./").to_string());
        if !cosmetic {
            lines.push(format!("  as written  : {}", raw));
        }

        // ---- tier 1: free ----
        if let Some(root) = project_root {
            if !is_inside(&resolved, root) {
                lines.push(format!("  ⚠ OUTSIDE the project root ({})", root.display()));
                worst_first.push("OUTSIDE project root".into());
            }
        }
        if is_user_profile(&resolved) {
            lines.push("  ⚠ resolves to a USER PROFILE directory".into());
            worst_first.push("resolves to a user profile".into());
        }
        if is_filesystem_root(&resolved) {
            lines.push("  ⚠ resolves to a FILESYSTEM ROOT".into());
            worst_first.push("resolves to a filesystem root".into());
        }

        if !resolved.exists() {
            lines.push("  contains    : (path does not exist — nothing to delete)".into());
            summary_parts.push(format!("{} does not exist", short(&display)));
            continue;
        }

        // ---- tier 2: cheap, one level deep ----
        let notable = sensitive_children(&resolved);
        if !notable.is_empty() {
            let names: Vec<String> = notable
                .iter()
                .map(|(n, w)| format!("{} ({})", n, w))
                .collect();
            lines.push(format!("  ⚠ contains  : {}", names.join(", ")));
            worst_first.push(format!("contains {}", notable[0].0));
        }

        // ---- tier 3: budgeted recursive scan ----
        let scan = scan_budgeted(&resolved);
        let count_str = if scan.capped {
            format!("{}+ files (stopped counting)", fmt_num(scan.files))
        } else {
            format!("{} files", fmt_num(scan.files))
        };
        lines.push(format!(
            "  contains    : {} across {} director{}",
            count_str,
            fmt_num(scan.dirs),
            if scan.dirs == 1 { "y" } else { "ies" }
        ));

        // ---- insurance ----
        // Two different facts get two different sentences. "Not recoverable"
        // is ambiguous on its own: it could mean the backup engine does not
        // cover this command, or that the target is simply too big to copy.
        // A preview whose lines are meant to be facts has to say which.
        match crate::backup::plan(command, cwd) {
            Some(plan) if !scan.capped => {
                lines.push(format!("  insurance   : {} (automatic on run/hook)", plan));
            }
            Some(_) => {
                lines.push(format!(
                    "  ✗ insurance : too large to copy ({}+ files) — NOT recoverable",
                    fmt_num(MAX_FILES)
                ));
                worst_first.push("NOT recoverable".into());
                uninsurable = true;
            }
            None => {
                lines
                    .push("  ✗ insurance : no backup covers this command — NOT recoverable".into());
                worst_first.push("NOT recoverable".into());
                uninsurable = true;
            }
        }

        summary_parts.push(format!("{} — {}", short(&display), count_str));
    }

    // The summary is what lands in an agent's confirmation prompt, where it
    // competes with approval fatigue. Lead with the scariest fact, not the
    // first one: "OUTSIDE project root" stops a hand mid-click; a file count
    // alone reads like every other number on the screen.
    worst_first.dedup();
    let summary = if worst_first.is_empty() {
        summary_parts.join("; ")
    } else {
        format!("{} — {}", worst_first.join(", "), summary_parts.join("; "))
    };

    Some(Preview {
        title: "delete impact".into(),
        lines,
        summary,
        uninsurable,
    })
}

// ---------------------------------------------------------------------------
// target extraction
// ---------------------------------------------------------------------------

/// Pull delete targets out of a command string, across the three shells the
/// classifier already knows about. Deliberately conservative: if we can't
/// confidently identify a target we return nothing rather than guessing, and
/// the caller falls back to no preview.
///
/// A projection of `extract_targets_detailed` — one extractor, two views
/// (decision #37: two engines parsing the same command differently is the
/// bug class this module exists to close). Callers that need to know whether
/// a target can be resolved at all take the detailed form.
pub fn extract_targets(command: &str) -> Vec<String> {
    extract_targets_detailed(command)
        .into_iter()
        .map(|t| t.text)
        .collect()
}

/// Delete targets with their quoting provenance attached.
///
/// The provenance exists because of what `tokenize` throws away: after quote
/// stripping, `'lit$SID'` and `$SID` are indistinguishable strings, and only
/// one of them expands. Keeping the quotes in the token text instead — the
/// obvious fix — breaks `resolve_head`, which must keep recognising `"rm"`
/// as `rm` (the quoting shape this project has already shipped a bypass
/// for). So the text stays exactly what it was, and what the quotes *meant*
/// travels beside it.
pub fn extract_targets_detailed(command: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    for segment in crate::shell::split_segments(command) {
        let tokens = tokenize_detailed(&segment);
        if tokens.is_empty() {
            continue;
        }
        let texts: Vec<String> = tokens.iter().map(|t| t.text.clone()).collect();
        let Some((head, at)) = resolve_head(&texts) else {
            continue;
        };
        if !is_delete_command(&head) {
            continue;
        }

        // Targets start after the command, not after token zero: with a
        // wrapper present those are different positions, and reading from
        // token zero would take the wrapper's own arguments as targets.
        for t in tokens.iter().skip(at + 1) {
            if is_flag(&head, &t.text) {
                continue;
            }
            out.push(t.clone());
        }
    }
    out
}

/// Is this token a flag rather than a target?
///
/// Flag syntax is a property of the SHELL, not of the string. `/s` is a cmd
/// switch; `/c` is a drive root in Git Bash. Both are two characters starting
/// with a slash, so any shape-based guess gets one of them wrong — and the one
/// it gets wrong is `rm -rf /c`, a whole-drive delete, which is precisely the
/// command that most needs a preview and a backup.
///
/// Public because `backup::rm_targets` must agree with `extract_targets` about
/// what counts as a target. Two engines parsing the same command differently
/// is the bug class this whole module exists to close.
pub fn is_flag(head: &str, token: &str) -> bool {
    match head {
        // POSIX-only: `-` introduces options, a leading `/` is a path.
        // `rm -rf /c` must keep `/c` as a target — that is a whole-drive
        // delete, the command that most needs a preview and a backup.
        "rm" | "unlink" => token.starts_with('-'),
        // PowerShell: -Recurse, -Force, -Path. Never `/`.
        "remove-item" | "ri" => token.starts_with('-'),
        // cmd-family: /s /q /f are switches. But "a leading slash means a
        // switch" is too broad — on Unix every absolute path starts with one,
        // and `rmdir` exists in both shells. Found by CI: `del /s /q /tmp/x`
        // ate its own target on Linux and macOS.
        //
        // So match the SHAPE of a cmd switch, not merely the slash: a bare
        // two-character token (`/s`, `/q`) or an attribute selector
        // (`/a:h`). Anything longer is a path.
        "del" | "rd" | "rmdir" => token.starts_with('-') || is_cmd_switch(token),
        // cmd-family copy/move: /Y /D /Z are switches, same shape rule and
        // the same reason it must be a SHAPE rule - `copy /Y a b` on a Unix
        // box would otherwise keep `/Y` and lose nothing, but `cp /etc/x y`
        // must keep `/etc/x`. Added in v0.16 when the target extractor
        // reported `/Y` as a file: harmless for `copy /Y a b`, but
        // `copy /Y .env` then read `.env` as the DESTINATION, denying a
        // command that only copies from it.
        "copy" | "move" | "xcopy" | "robocopy" => token.starts_with('-') || is_cmd_switch(token),
        _ => token.starts_with('-'),
    }
}

/// A cmd.exe switch: `/s`, `/q`, `/f`, or an attribute selector like `/a:h`.
///
/// Deliberately shape-matched rather than "starts with a slash": on Unix an
/// absolute path also starts with a slash, and `rmdir` is a real command on
/// both platforms. The narrow rule keeps `/tmp/build` and `/c/Users/x` as
/// targets while still filtering the switches cmd actually uses.
fn is_cmd_switch(token: &str) -> bool {
    if !token.starts_with('/') {
        return false;
    }
    token.len() == 2 || (token.len() <= 4 && token.starts_with("/a:"))
}

/// Normalise a command head to a bare, lowercase program name:
/// `C:\Windows\System32\del.exe` -> `del`. Shared for the same reason
/// `is_flag` is.
pub fn command_head(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    lower
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&lower)
        .trim_end_matches(".exe")
        .to_string()
}

/// Wrapper programs that run another command, with the real command's name
/// somewhere after their own arguments. Until v0.16 every consumer read
/// token zero as the command, so `sudo rm -rf x` classified as nothing at
/// all: the classifier saw `sudo`, the delete extractor saw `sudo`, and
/// `backup` took no insurance. The gap was not specific to deletes — measured
/// on the previous commit, `sudo terraform destroy -auto-approve` also
/// classified as `None`. A wrapper blanked the whole engine.
///
/// HAND-WALKED LIST (decision #56: a membership list that sizes a decision
/// gets walked by a person and says so). Each entry runs an arbitrary command
/// and is common in agent output. Being on this list is NOT a claim that the
/// wrapper is dangerous — `sudo` precedes plenty of harmless work. It says
/// only "the real command name is further along."
///
/// Deliberately NOT here: `xargs` and `find -exec`, which take a command but
/// are already handled where their own semantics matter; shell builtins
/// (`exec`, `eval`), which do not appear as token zero of a segment the
/// splitter produced; and `time` / `strace` / `watch`, which are diagnostic
/// wrappers no agent has been observed reaching for in this codebase's field
/// reports. Add them when something observes one, not before.
const COMMAND_WRAPPERS: [&str; 6] = ["sudo", "doas", "env", "command", "nohup", "nice"];

/// Flags on a wrapper that consume the FOLLOWING token as their value. Without
/// this, `sudo -u alice rm -rf x` reads `alice` as the command name and the
/// delete is invisible again — the same miss in a different spelling.
fn wrapper_flag_takes_value(wrapper: &str, flag: &str) -> bool {
    match wrapper {
        "sudo" | "doas" => matches!(
            flag,
            "-u" | "-g" | "-p" | "-C" | "-D" | "-h" | "-R" | "-T" | "--user" | "--group"
        ),
        "env" => matches!(flag, "-u" | "--unset" | "-S" | "--split-string"),
        "nice" => matches!(flag, "-n" | "--adjustment"),
        _ => false,
    }
}

/// The real command's normalized head, and the index of the token it came
/// from. `None` when the segment is only wrappers and their arguments, which
/// names no command to judge.
///
/// One answer to "what command is this?", shared by the classifier, the
/// delete extractor and the insurance layer. They used to compute it three
/// ways and disagreed (decision #37): `delete.rs` normalized paths through
/// `command_head` while `intent.rs` compared token zero raw, so
/// `C:\Windows\System32\del.exe /s /q x` was a recognised delete to one and
/// nothing to the other — on the platform where every dialect bug has
/// actually happened.
pub fn resolve_head(tokens: &[String]) -> Option<(String, usize)> {
    let mut i = 0;
    loop {
        let head = command_head(tokens.get(i)?);
        if !COMMAND_WRAPPERS.contains(&head.as_str()) {
            return Some((head, i));
        }
        let wrapper = head;
        i += 1;
        // Skip the wrapper's own arguments: flags (and their values, where the
        // flag takes one) and `KEY=VALUE` environment assignments, which `env`
        // and `sudo` both accept before the command name.
        while let Some(tok) = tokens.get(i) {
            if tok.starts_with('-') {
                if wrapper_flag_takes_value(&wrapper, tok) {
                    i += 1;
                }
                i += 1;
            } else if is_env_assignment(tok) {
                i += 1;
            } else {
                break;
            }
        }
    }
}

/// `FOO=bar` before a command name is an environment assignment, not the
/// command. Guarded against paths that merely contain `=`: the name half must
/// be a plain identifier.
fn is_env_assignment(token: &str) -> bool {
    match token.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.chars().next().is_some_and(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// Does this command head delete things?
pub fn is_delete_command(head: &str) -> bool {
    matches!(
        head,
        "rm" | "rmdir" | "del" | "rd" | "unlink" | "remove-item" | "ri"
    )
}

/// Minimal tokenizer that respects single and double quotes. We cannot reuse
/// the policy normalizer here: it lowercases, and paths are case-sensitive on
/// every platform that matters for a delete.
/// Tokenizer shared with the target extractor, which needs the same splitting
/// the delete extractor uses so the two cannot disagree about where a
/// command's arguments begin.
pub fn tokenize_public(s: &str) -> Vec<String> {
    tokenize(s)
}

fn tokenize(s: &str) -> Vec<String> {
    tokenize_detailed(s).into_iter().map(|t| t.text).collect()
}

/// A token with the one fact quote-stripping destroys: whether its content
/// came from inside single quotes, where the shell expands nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tok {
    pub text: String,
    /// Every character of `text` arrived from inside single quotes.
    /// `'lit$SID'` keeps this; `x/$SID` and `"$SID"` do not (double quotes
    /// expand variables, so for this question they are the same as no
    /// quotes at all).
    pub single_quoted: bool,
}

impl Tok {
    /// Does this token carry a shell variable the gate cannot expand —
    /// `$NAME` or `${NAME}` outside single quotes and not escaped?
    ///
    /// Deliberately NOT a blanket dollar check. The r/ClaudeCode design
    /// review named the false positives a naive rule produces, and each is
    /// excluded here and pinned by a test:
    ///
    ///   `'lit$SID'`   single quotes never expand — a filename
    ///   `\$SID`       the backslash reaches the shell as an escape
    ///   `costs$5`     a digit after `$` is positional-parameter shaped; in
    ///                 a delete target it is overwhelmingly a filename
    ///
    /// Out of scope, deliberately: `$(...)` is command substitution, a
    /// different hazard; `%VAR%` is cmd, where an undefined name stays as
    /// literal text rather than collapsing to empty, so the failure class
    /// this detects — a path silently shrinking to its parent — does not
    /// arise there.
    pub fn has_unexpanded_var(&self) -> bool {
        if self.single_quoted {
            return false;
        }
        let chars: Vec<char> = self.text.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            if *c != '$' {
                continue;
            }
            if i > 0 && chars[i - 1] == '\\' {
                continue;
            }
            if let Some(next) = chars.get(i + 1) {
                if next.is_ascii_alphabetic() || *next == '_' || *next == '{' {
                    return true;
                }
            }
        }
        false
    }
}

/// `tokenize`, keeping provenance instead of discarding it. The `text` field
/// of every token is byte-identical to what `tokenize` returns — consumers
/// like `resolve_head` see exactly the strings they always did.
fn tokenize_detailed(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    // True until the first character arrives from outside single quotes.
    // An empty token never gets pushed, so the initial value only ever
    // reaches `out` alongside at least one single-quoted character.
    let mut all_single = true;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), ch) if ch == q => quote = None,
            (Some(q), ch) => {
                if q != '\'' {
                    all_single = false;
                }
                cur.push(ch);
            }
            (None, '"') | (None, '\'') => quote = Some(c),
            (None, ch) if ch.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(Tok {
                        text: std::mem::take(&mut cur),
                        single_quoted: all_single,
                    });
                }
                all_single = true;
            }
            (None, ch) => {
                all_single = false;
                cur.push(ch);
            }
        }
    }
    if !cur.is_empty() {
        out.push(Tok {
            text: cur,
            single_quoted: all_single,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// path resolution
// ---------------------------------------------------------------------------

/// Resolve a path as written into something the filesystem understands.
///
/// The Git Bash case is load-bearing: `/c/Users/x` looks like an absolute Unix
/// path and is really `C:\Users\x`. That exact conversion is what the incident
/// turned on — the agent wrote to `/c/Users/harih` believing it was a stray
/// directory, when on Windows it resolves to the real profile.
/// Resolve a raw target against an explicit base directory.
///
/// v0.16, decision #48's sibling: the base is a parameter, never the process
/// cwd. A hook runs in whatever directory the harness spawned it in, which is
/// not the directory the agent's command runs in — resolving a relative target
/// against the wrong base silently found nothing and took no backup (the
/// documented Cursor no-backup case). The payload carries the real cwd; every
/// caller threads it here.
pub fn resolve_path_in(raw: &str, cwd: &Path) -> PathBuf {
    let s = raw.trim().trim_matches('"').trim_matches('\'');

    // WSL: /mnt/c/... -> C:\...
    if let Some(rest) = s.strip_prefix("/mnt/") {
        if let Some((drive, tail)) = split_drive(rest) {
            return PathBuf::from(format!("{}:\\{}", drive.to_ascii_uppercase(), tail));
        }
    }
    // Git Bash / MSYS: /c/... -> C:\...
    //
    // Only when that drive actually exists. A single-letter first segment is
    // NOT proof of a drive — `/usr/local/lib` would otherwise resolve to
    // `C:/usr/local/lib`, which is both wrong and dangerous in a tool that
    // reports blast radius. One stat call turns a guess into a fact.
    if let Some(rest) = s.strip_prefix('/') {
        if let Some((drive, tail)) = split_drive(rest) {
            let root = format!("{}:\\", drive.to_ascii_uppercase());
            if Path::new(&root).exists() {
                return PathBuf::from(format!("{}{}", root, tail.replace('/', "\\")));
            }
        }
    }
    // ~ expansion
    if s == "~" || s.starts_with("~/") || s.starts_with("~\\") {
        if let Some(home) = home_dir() {
            let tail = s.trim_start_matches('~').trim_start_matches(['/', '\\']);
            return if tail.is_empty() {
                home
            } else {
                home.join(tail)
            };
        }
    }

    let p = PathBuf::from(s);
    let joined = if p.is_absolute() { p } else { cwd.join(p) };
    normalise(joined)
}

/// Collapse `.` and `..` components lexically.
///
/// `canonicalize` is not an option here: the target may legitimately not exist
/// ("nothing to delete" is a valid preview), and on Windows it returns `\\?\`
/// verbatim paths that read badly in output meant for a human deciding whether
/// to approve.
///
/// Found by live testing: `./target` resolved to
/// `C:\Users\User\ycdemo2\./target`, which `is_inside` then judged to be
/// OUTSIDE the project root — a false alarm on the most ordinary delete there
/// is. A warning that fires on `rm -rf ./target` is a warning nobody reads.
fn normalise(p: PathBuf) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(pre) => out.push(pre.as_os_str()),
            Component::RootDir => {
                // Pushing "\\" onto a PathBuf holding "C:" would CLOBBER the
                // prefix — PathBuf::push treats a rooted component as a fresh
                // absolute path. Append at the OsString level instead so
                // "C:" + root becomes "C:\\" rather than "\\".
                let mut buf = out.into_os_string();
                buf.push(std::path::MAIN_SEPARATOR.to_string());
                out = PathBuf::from(buf);
            }
            Component::Normal(n) => out.push(n),
        }
    }
    out
}

/// "c/Users/x" -> ("c", "Users/x"); returns None when there's no leading
/// single-letter segment to treat as a drive.
fn split_drive(s: &str) -> Option<(&str, &str)> {
    let mut parts = s.splitn(2, '/');
    let head = parts.next()?;
    if head.len() != 1 || !head.chars().next()?.is_ascii_alphabetic() {
        return None;
    }
    Some((head, parts.next().unwrap_or("")))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()
        .map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// signals
// ---------------------------------------------------------------------------

/// Is `target` inside `root`?
///
/// Both sides go through `for_compare` so they are always in the same form.
/// Found by live testing: the root always canonicalizes (it exists), while a
/// target that does not exist yet falls back to its lexical path — on Windows
/// that meant comparing `C:\...\build` against `\\?\C:\...`, which never
/// matches, so an ordinary in-project delete was reported as OUTSIDE.
pub fn is_inside(target: &Path, root: &Path) -> bool {
    let t = for_compare(target);
    let r = for_compare(root);
    t.starts_with(&r)
}

/// Put a path into a form two paths can actually be compared in: canonicalized
/// when possible, with Windows' `\\?\` verbatim prefix stripped, and
/// case-folded on platforms with case-insensitive filesystems.
///
/// CANONICALIZES THE DEEPEST EXISTING ANCESTOR, not just the path itself.
/// `canonicalize` fails on a path that does not exist yet, and the old
/// fallback returned the raw lexical path - so comparing an existing root
/// against a not-yet-created child put the two sides in DIFFERENT forms
/// whenever any ancestor was a symlink. `is_inside` then answered false for a
/// child that is plainly inside its parent.
///
/// Found by CI (2026-08-16) on all three runners while two developer machines
/// passed: GitHub's runners reach the temp directory through a symlink and
/// `/tmp` here does not. Reproduced locally by pointing a root at a symlink -
/// child absent, is_inside false; child created, is_inside true. Same path,
/// two answers, decided by whether the target had been created yet, which is
/// exactly backwards for a tool that judges commands BEFORE they run.
///
/// Real-world reach, not just tests: macOS `/tmp` and `/var` are symlinks,
/// as are plenty of home directories on shared mounts. Any project reached
/// through one made every not-yet-created target read as outside the project.
fn for_compare(p: &Path) -> PathBuf {
    let c = canonical_prefix(p);
    let s = c.to_string_lossy().to_string();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
    if cfg!(windows) {
        PathBuf::from(s.to_lowercase())
    } else {
        PathBuf::from(s)
    }
}

/// Canonicalize as much of `p` as exists, then re-append the rest.
///
/// Walks up to the deepest ancestor that exists, canonicalizes THAT, and
/// rejoins the components below it. A path that exists entirely canonicalizes
/// entirely, as before; one that does not still gets its real prefix, so two
/// paths under the same root always compare in the same form.
fn canonical_prefix(p: &Path) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(c) = cur.canonicalize() {
            let mut out = c;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.file_name(), cur.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                cur = parent.to_path_buf();
            }
            // Nothing along the path exists (or we reached the root without
            // finding anything): the lexical form is the best answer there is.
            _ => return p.to_path_buf(),
        }
    }
}

/// Does this path resolve to a user profile — either the current user's home,
/// or a sibling under the same parent (`C:\Users\someone`, `/home/someone`)?
///
/// The sibling case matters: an agent operating on a mistyped path may land on
/// a profile that isn't the one running the agent.
pub fn is_user_profile(p: &Path) -> bool {
    if let Some(home) = home_dir() {
        if p == home {
            return true;
        }
        if let Some(parent) = home.parent() {
            // Same depth, same parent → a sibling profile.
            if p.parent() == Some(parent) && p.components().count() == home.components().count() {
                return true;
            }
        }
    }
    // Fallback for the common shapes when HOME is unset.
    let s = p.to_string_lossy().replace('\\', "/").to_lowercase();
    let depth = s.trim_end_matches('/').matches('/').count();
    (s.contains("/users/") && depth <= 2) || (s.starts_with("/home/") && depth == 2)
}

pub fn is_filesystem_root(p: &Path) -> bool {
    p.parent().is_none()
        || matches!(
            p.to_string_lossy().as_ref(),
            "/" | "C:\\" | "c:\\" | "C:/" | "c:/"
        )
}

/// Sensitive entries one level under the target. One directory read — no walk.
fn sensitive_children(dir: &Path) -> Vec<(String, &'static str)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        for (needle, what) in SENSITIVE {
            if name.eq_ignore_ascii_case(needle) || name.starts_with(needle) {
                found.push((name.clone(), *what));
                break;
            }
        }
    }
    found.sort();
    found.dedup_by(|a, b| a.0 == b.0);
    found
}

pub struct Scan {
    pub files: usize,
    pub dirs: usize,
    /// True when we stopped early — the real number is larger than `files`.
    pub capped: bool,
}

/// Recursive count under a hard budget on files AND wall-clock time.
///
/// This runs inside a hook with an agent waiting on the other end, so an
/// unbounded walk is not an option: a cold network drive or a node_modules
/// tree would hang the gate. Capping is honest as long as the output says it
/// was capped — and for the decision at hand, "5,000+" is just as decisive as
/// an exact number. Nobody deletes five thousand files by accident and calls
/// it a stray folder.
pub fn scan_budgeted(root: &Path) -> Scan {
    let start = Instant::now();
    let mut files = 0usize;
    let mut dirs = 0usize;
    let mut stack = vec![root.to_path_buf()];

    if root.is_file() {
        return Scan {
            files: 1,
            dirs: 0,
            capped: false,
        };
    }

    while let Some(dir) = stack.pop() {
        // Budget check at the pop bounds long runs of small directories…
        if files >= MAX_FILES || start.elapsed() > MAX_TIME {
            return Scan {
                files,
                dirs,
                capped: true,
            };
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue; // unreadable subtree — count what we can, stay silent
        };
        dirs += 1;
        for e in entries.flatten() {
            // …and the check HERE bounds one large directory. Until v0.16 the
            // budget was only consulted between directories, so a single big
            // dir ran to completion: thousands of symlink_metadata calls with
            // no way to stop. On a filesystem where each stat costs
            // milliseconds — WSL2 with Windows drives mounted was the field
            // case — that turned a 300ms budget into 5.8–7.1 measured seconds,
            // blew the doctor probe's 2s timeout, and a correctly gated setup
            // reported "registered but NOT firing". hook_configured inverted:
            // red over a gated session. It also let a flat directory of 6,000
            // files overrun MAX_FILES and return capped:false. Reported by
            // Tim Schipper. The residue, stated: a budget can only act BETWEEN
            // syscalls — one genuinely hung stat (dead network mount) is the
            // OS's to interrupt, not ours.
            if files >= MAX_FILES || start.elapsed() > MAX_TIME {
                return Scan {
                    files,
                    dirs,
                    capped: true,
                };
            }
            // symlink_metadata: do NOT follow links. Following them would both
            // inflate the count and risk walking out of the target entirely
            // (see the junction-traversal issue).
            match e.path().symlink_metadata() {
                Ok(m) if m.is_dir() => stack.push(e.path()),
                Ok(_) => files += 1,
                Err(_) => {}
            }
        }
    }
    Scan {
        files,
        dirs,
        capped: false,
    }
}

// ---------------------------------------------------------------------------
// formatting
// ---------------------------------------------------------------------------

fn fmt_num(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Trim a path for the one-line summary, keeping the tail (which is the part
/// that identifies it) rather than the head.
///
/// Counts CHARACTERS, not bytes. `&p[p.len() - 39..]` panicked whenever the
/// cut landed inside a multi-byte codepoint — 22 of 207 realistic Cyrillic,
/// CJK and Latin-1 paths in Schipper's sweep. It is reachable from
/// `preview_for` → `preview::generate` → `hook::run`, so it fired *inside the
/// gate*, on exactly the non-ASCII Windows profile this module was written
/// for: a panicking hook is an ungated agent.
fn short(p: &str) -> String {
    const MAX: usize = 40;
    let n = p.chars().count();
    if n <= MAX {
        return p.to_string();
    }
    let tail: String = p.chars().skip(n - (MAX - 1)).collect();
    format!("…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The old process-cwd form, kept for tests only. Production has no
    /// caller left: with every site threaded, `resolve_path` became dead
    /// code and clippy said so, which is the cleanest possible proof that
    /// the ambient fallback is gone (v0.16 item 1).
    fn resolve_path_here(raw: &str) -> PathBuf {
        resolve_path_in(raw, &std::env::current_dir().unwrap())
    }
    use crate::testutil::TempTree;

    /// Schipper review, finding 2. Sweeps every length across non-ASCII
    /// prefixes so the truncation point lands mid-codepoint; the old byte
    /// slice panicked on 22 of these.
    #[test]
    fn short_never_panics_on_non_ascii_paths() {
        for prefix in [
            "/home/Пользователь/",
            "/home/user/用户文档/",
            "/home/Jörg/Bücher/",
            "C:\\Users\\Пользователь\\Рабочий стол\\",
            "/home/user/📁/",
        ] {
            for n in 0..80 {
                let p = format!("{prefix}{}", "a".repeat(n));
                let s = short(&p);
                assert!(s.chars().count() <= 40, "not trimmed: {s}");
                if p.chars().count() > 40 {
                    assert!(s.starts_with('…'), "expected ellipsis: {s}");
                    assert!(p.ends_with(
                        &s[s.char_indices().nth(1).map(|(i, _)| i).unwrap_or(s.len())..]
                    ));
                }
            }
        }
    }

    #[test]
    fn short_leaves_ascii_behaviour_unchanged() {
        assert_eq!(short("/tmp/x"), "/tmp/x");
        let long = format!("/home/user/{}", "a".repeat(60));
        assert_eq!(short(&long).chars().count(), 40);
        assert!(short(&long).ends_with("aaa"));
    }

    #[test]
    fn extracts_targets_across_shells() {
        assert_eq!(
            extract_targets("rm -rf /c/Users/harih"),
            vec!["/c/Users/harih"]
        );
        assert_eq!(extract_targets("rm -rf ./build"), vec!["./build"]);
        assert_eq!(
            extract_targets("Remove-Item -Recurse -Force C:\\tmp\\x"),
            vec!["C:\\tmp\\x"]
        );
        assert_eq!(extract_targets("del /s /q C:\\tmp"), vec!["C:\\tmp"]);
        assert_eq!(extract_targets("rmdir /s C:\\tmp"), vec!["C:\\tmp"]);
        // quoted paths with spaces survive as one target
        assert_eq!(
            extract_targets(r#"rm -rf "/c/Users/my name/x""#),
            vec!["/c/Users/my name/x"]
        );
        // non-deletes produce nothing
        assert!(extract_targets("git status").is_empty());
        assert!(extract_targets("ls -la /c/Users").is_empty());
    }

    #[test]
    fn preview_admits_an_unresolvable_target_instead_of_inventing_a_path() {
        // Issue #11, asserted as the r/ClaudeCode review asked: prove the
        // BAD OUTCOME is blocked — a resolved path printed for a target the
        // shell has not expanded — not merely that a dollar token exists.
        let cwd = std::env::current_dir().unwrap();
        let p = preview_for("rm -rf x/$SID", None, &cwd).expect("delete preview");

        // The line issue #11 was filed about: cwd-joined `$SID`, a path that
        // will never exist, printed as fact.
        let invented = resolve_path_in("x/$SID", &cwd).display().to_string();
        assert!(
            !p.lines.iter().any(|l| l.contains(&invented)),
            "preview printed a resolved path for an unexpanded variable: {:?}",
            p.lines
        );
        // What replaces it: the target as written, and an admitted unknown.
        assert!(p.lines.iter().any(|l| l.contains("x/$SID")));
        assert!(p.lines.iter().any(|l| l.contains("UNRESOLVED")));
        // The summary leads with it — that is the sentence an agent's
        // confirmation prompt shows a human.
        assert!(p.summary.contains("UNRESOLVED variable"));
        // No backup can cover a path unknown until expansion.
        assert!(p.uninsurable);
    }

    #[test]
    fn unexpanded_var_detection_is_quote_aware() {
        // The three false positives from the r/ClaudeCode review, plus the
        // live cases. `flagged(cmd)` = the sole extracted target carries an
        // unexpanded variable.
        fn flagged(cmd: &str) -> bool {
            let t = extract_targets_detailed(cmd);
            assert_eq!(t.len(), 1, "expected one target from {cmd:?}, got {t:?}");
            t[0].has_unexpanded_var()
        }

        assert!(flagged("rm -rf x/$SID")); // the incident shape
        assert!(flagged("rm -rf \"$SID\"")); // double quotes expand
        assert!(flagged("rm -rf ${SID}")); // braced form
        assert!(!flagged("rm -rf 'lit$SID'")); // single quotes do not
        assert!(!flagged("rm -rf \\$SID")); // escaped, reaches shell literal
        assert!(!flagged("rm -rf costs$5")); // digit: a filename
        assert!(!flagged("rm -rf x")); // control
                                       // `$(...)` is command substitution — a different hazard, not this
                                       // detector's claim to make.
        assert!(!flagged("rm -rf $(pwd)"));

        // Single-quote provenance survives extraction with the text intact.
        let t = extract_targets_detailed("rm -rf 'lit$SID'");
        assert_eq!(t[0].text, "lit$SID");
        assert!(t[0].single_quoted);
    }

    #[test]
    fn quoted_head_resolution_survives_the_provenance_change() {
        // Regression guard. Keeping quotes in the token text — the obvious
        // way to remember them — makes `resolve_head` stop recognising
        // `"rm"`, the quoting shape this project has already shipped a
        // bypass for. Provenance must travel BESIDE the text, never in it.
        assert_eq!(extract_targets("\"rm\" -rf x"), vec!["x"]);

        // And the two views are one extractor: the plain form is exactly
        // the detailed form's text (decision #37 — two engines parsing one
        // command differently is the bug class this module closes).
        for cmd in [
            "rm -rf x/$SID",
            "\"rm\" -rf x",
            "rm -rf 'lit$SID'",
            "git status && rm -rf ./dist",
            "del /s /q C:\\tmp",
        ] {
            let plain = extract_targets(cmd);
            let detailed: Vec<String> = extract_targets_detailed(cmd)
                .into_iter()
                .map(|t| t.text)
                .collect();
            assert_eq!(plain, detailed, "views diverged for {cmd:?}");
        }
    }

    #[test]
    fn flag_syntax_is_decided_per_shell_not_by_shape() {
        // `/s` is a cmd switch; `/c` is a drive root. Same shape, opposite
        // meanings. A shape-based guess drops `rm -rf /c` — a whole-drive
        // delete — which is the command that most needs a preview.
        assert!(is_flag("del", "/s"));
        assert!(is_flag("rd", "/q"));
        assert!(!is_flag("rm", "/c"));
        assert!(!is_flag("rm", "/mnt/c/data"));
        assert!(is_flag("rm", "-rf"));
        assert!(is_flag("remove-item", "-Recurse"));
        assert!(!is_flag("remove-item", "C:\\tmp"));

        // `rmdir` lives in both shells — the one genuinely ambiguous head.
        // A bare two-char switch is a flag; a longer slash token is a path.
        assert!(is_flag("rmdir", "/s"));
        assert!(is_flag("rmdir", "-p"));
        assert!(!is_flag("rmdir", "/c/data"));
        assert!(!is_flag("rmdir", "./build"));

        // Caught by CI on Linux/macOS: "a leading slash is a switch" ate the
        // target of `del /s /q /tmp/x`, because every absolute Unix path
        // starts with a slash.
        assert!(!is_flag("del", "/tmp/x"));
        assert!(!is_flag("rd", "/var/lib/thing"));
        assert!(is_flag("del", "/a:h"));
        assert!(!is_flag("del", "/a/b/c"));
    }

    #[test]
    fn whole_drive_delete_is_not_mistaken_for_a_flag() {
        assert_eq!(extract_targets("rm -rf /c"), vec!["/c"]);
        assert_eq!(extract_targets("rm -rf /"), vec!["/"]);
    }

    #[test]
    fn command_heads_normalise() {
        assert_eq!(command_head("rm"), "rm");
        assert_eq!(command_head("/bin/rm"), "rm");
        assert_eq!(command_head("C:\\Windows\\System32\\del.exe"), "del");
        assert_eq!(command_head("Remove-Item"), "remove-item");
    }

    #[test]
    fn extracts_from_compound_segments() {
        let t = extract_targets("git status && rm -rf ./dist");
        assert_eq!(t, vec!["./dist"]);
    }

    #[test]
    fn resolves_git_bash_paths_only_when_the_drive_exists() {
        // The incident: /c/Users/harih is NOT a stray unix directory — it is
        // the real profile. But the conversion is gated on drive C: actually
        // existing, because a single-letter first segment is not proof of a
        // drive (see /usr below). Windows-only: on CI's Linux runner there is
        // no C:, so the branch correctly never fires.
        #[cfg(windows)]
        {
            let p = resolve_path_here("/c/Users/harih");
            let s = p.to_string_lossy().to_lowercase();
            assert!(
                s.starts_with("c:") && s.contains("users"),
                "git-bash path must resolve to a Windows path, got {s}"
            );
        }

        // The regression: `/u` must NOT be read as drive U:. On Windows a
        // rooted path resolves against the CURRENT drive, so /usr becomes
        // C:\usr — correct, and crucially not U:\sr.
        #[cfg(windows)]
        {
            let u = resolve_path_here("/usr/local/lib")
                .to_string_lossy()
                .to_lowercase();
            assert!(
                !u.starts_with("u:"),
                "/usr must not become drive U:, got {u}"
            );
            assert!(u.contains("usr"), "the path must survive intact, got {u}");
        }

        #[cfg(unix)]
        {
            assert_eq!(
                resolve_path_here("/usr/local/lib"),
                PathBuf::from("/usr/local/lib")
            );
            assert_eq!(resolve_path_here("/etc/hosts"), PathBuf::from("/etc/hosts"));
        }
    }

    #[test]
    fn relative_paths_normalise_and_stay_inside_the_project() {
        // Live-testing regression: `./target` resolved with the dot component
        // intact, so is_inside said OUTSIDE the project root — a false alarm
        // on the most ordinary delete there is.
        let root = std::env::current_dir().unwrap();
        let t = resolve_path_here("./target");
        let s = t.to_string_lossy().to_string();
        assert!(
            !s.contains("/./") && !s.contains("\\.\\") && !s.ends_with("/."),
            "dot components must be collapsed, got {s}"
        );
        assert!(
            is_inside(&t, &root),
            "./target must be inside the cwd, got {s}"
        );

        // `..` climbs out, and must be reported as outside.
        let up = resolve_path_here("../sibling");
        assert!(
            !is_inside(&up, &root),
            "../sibling must be outside the cwd, got {}",
            up.display()
        );

        // A bare relative name resolves under the cwd too. This is the
        // asymmetry that broke it: `target` exists (cargo makes it) so it
        // canonicalized, while `build` does not — and on Windows the two
        // forms are not comparable unless both are normalised first.
        let b = resolve_path_here("build");
        assert!(
            is_inside(&b, &root),
            "a non-existent in-project path must still be inside, got {}",
            b.display()
        );
        assert!(
            is_inside(&resolve_path_here("definitely-not-created-yet"), &root),
            "existence must not change the inside/outside answer"
        );
    }

    #[test]
    fn quotes_are_stripped_before_resolution() {
        // Whatever /c/tmp resolves to on this platform, the quoted form must
        // resolve identically — the assertion is about quote handling, not
        // about drive conversion.
        assert_eq!(
            resolve_path_here("\"/c/tmp\"")
                .to_string_lossy()
                .to_lowercase(),
            resolve_path_here("/c/tmp").to_string_lossy().to_lowercase()
        );
        assert_eq!(
            resolve_path_here("'/tmp/x'").to_string_lossy(),
            resolve_path_here("/tmp/x").to_string_lossy()
        );
    }

    #[test]
    fn filesystem_roots_are_recognised() {
        assert!(is_filesystem_root(Path::new("/")));
        assert!(is_filesystem_root(Path::new("C:\\")));
        assert!(!is_filesystem_root(Path::new("/usr")));
    }

    /// Regression, CI 2026-08-16: a target that does not exist YET is still
    /// inside its parent, even when the parent is reached through a symlink.
    ///
    /// `for_compare` canonicalized the existing root and fell back to the raw
    /// lexical path for the absent child, putting the two sides in different
    /// forms and answering false. Two developer machines passed and all three
    /// CI runners failed, because GitHub's runners reach the temp directory
    /// through a symlink. The bug is not test-only: macOS `/tmp` and `/var`
    /// are symlinks, so any project under one had every not-yet-created
    /// target read as outside the project.
    ///
    /// The control leg is the point - the fix must not make `is_inside`
    /// simply answer true more often.
    #[cfg(unix)]
    #[test]
    fn a_target_that_does_not_exist_yet_is_still_inside_a_symlinked_root() {
        let t = TempTree::new("symlink-root");
        let real = t.dir("real");
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink must be creatable");

        // The failing case: absent child under a symlinked root.
        assert!(
            is_inside(&link.join("not-created-yet"), &link),
            "an absent child is still inside its parent"
        );
        assert!(
            is_inside(&link.join("a/b/c/d"), &link),
            "however deep, and however much of it exists"
        );
        // Present child, which passed even before the fix.
        let present = t.dir("real/present");
        assert!(is_inside(&present, &link));

        // CONTROL LEG: genuinely outside is still outside. Without this, a fix
        // that always answered true would pass every assertion above.
        assert!(
            !is_inside(t.path().join("elsewhere").as_path(), &link),
            "a sibling of the root is not inside it"
        );
    }

    #[test]
    fn inside_is_lexical_when_paths_do_not_exist() {
        let root = Path::new("/proj");
        assert!(is_inside(Path::new("/proj/src"), root));
        assert!(!is_inside(Path::new("/other/src"), root));
    }

    #[test]
    fn budgeted_scan_counts_and_reports_capping_honestly() {
        let tmp = TempTree::new("scan");
        let dir = tmp.path().to_path_buf();
        let sub = tmp.dir("nested");
        for i in 0..12 {
            std::fs::write(dir.join(format!("f{i}.txt")), "x").unwrap();
        }
        for i in 0..5 {
            std::fs::write(sub.join(format!("g{i}.txt")), "x").unwrap();
        }
        let scan = scan_budgeted(&dir);
        assert_eq!(scan.files, 17, "must count files recursively");
        assert_eq!(scan.dirs, 2);
        assert!(!scan.capped, "17 files is well under the budget");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The field case, made deterministic: the budget must bind INSIDE one
    /// directory, not just between directories. Before the fix this returned
    /// files=5500, capped=false — over budget and misreported. (The time
    /// half of the same check can't be pinned without a slow filesystem;
    /// it is the same line of code, so this count test holds both.)
    #[test]
    fn a_single_large_directory_cannot_blow_the_budget() {
        let tmp = TempTree::new("scan-flat");
        let dir = tmp.path().to_path_buf();
        for i in 0..(MAX_FILES + 500) {
            std::fs::write(dir.join(format!("f{i}")), "").unwrap();
        }
        let scan = scan_budgeted(&dir);
        assert!(
            scan.capped,
            "a flat directory larger than the budget must report capped"
        );
        assert!(
            scan.files <= MAX_FILES,
            "the count must stop at the budget, not at the directory's end: {}",
            scan.files
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn number_formatting_matches_the_incident() {
        assert_eq!(fmt_num(70201), "70,201");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(0), "0");
    }

    // -----------------------------------------------------------------------
    // What the preview says, and what it declines to say. Every line here is
    // read by a human deciding whether to approve a deletion.
    // -----------------------------------------------------------------------

    use crate::testutil::TestEnv;

    fn preview_lines(command: &str, root: Option<&Path>) -> Vec<String> {
        preview_for(command, root, &std::env::current_dir().unwrap())
            .map(|p| p.lines)
            .unwrap_or_default()
    }

    fn has_line(lines: &[String], needle: &str) -> bool {
        lines.iter().any(|l| l.contains(needle))
    }

    #[test]
    fn the_as_written_line_appears_only_when_resolution_changed_something() {
        // TestEnv, not TempTree: the `~` leg below reads HOME/USERPROFILE
        // through `home_dir()`, and `HomeGuard` (used by two tests in this
        // module) removes USERPROFILE and rewrites HOME process-globally.
        // Reading ambient env without the lock those writers hold is a race:
        // when it lost, `~` did not expand and the target became
        // `<cwd>/~/some-home-target`. Green on three CI runners as a pull
        // request, red on windows-latest for the identical commit as a push -
        // scheduling, not code.
        //
        // HOME is then set explicitly rather than trusted, so the assertion
        // depends on a value this test controls instead of on whatever the
        // machine happens to export. #18: the isolated way is the only way.
        let env = TestEnv::new("del-written");
        let home = env.root().join("home");
        std::fs::create_dir_all(&home).expect("home must be creatable");
        let _guard = HomeGuard::set(Some(&home));
        let tmp = TempTree::new("del-written-tree");
        let dir = tmp.dir("target");

        // An absolute path resolves to itself, and echoing it back twice is
        // noise that trains people to skip the block.
        let lines = preview_lines(&format!("rm -rf {}", dir.display()), None);
        assert!(!has_line(&lines, "as written"), "{lines:?}");

        // `./x` beside its absolute form is the same path to a reader.
        let lines = preview_lines("rm -rf ./some-relative-target", None);
        assert!(!has_line(&lines, "as written"), "{lines:?}");

        // A `~` expansion genuinely changes what is about to be deleted.
        let lines = preview_lines("rm -rf ~/some-home-target", None);
        assert!(
            has_line(&lines, "as written"),
            "an expansion the reader would miss has to be shown: {lines:?}"
        );
    }

    #[test]
    fn a_target_outside_the_project_root_is_called_out() {
        let tmp = TempTree::new("del-outside");
        let root = tmp.dir("project");
        let inside = tmp.dir("project/build");
        let outside = tmp.dir("elsewhere");

        let lines = preview_lines(&format!("rm -rf {}", outside.display()), Some(&root));
        assert!(has_line(&lines, "OUTSIDE the project root"), "{lines:?}");

        let lines = preview_lines(&format!("rm -rf {}", inside.display()), Some(&root));
        assert!(
            !has_line(&lines, "OUTSIDE the project root"),
            "a warning that fires on ordinary work is one nobody reads: {lines:?}"
        );
    }

    #[test]
    fn a_target_that_does_not_exist_says_so_instead_of_counting() {
        let tmp = TempTree::new("del-absent");
        let missing = tmp.absent("not-here");
        let present = tmp.dir("here");

        let lines = preview_lines(&format!("rm -rf {}", missing.display()), None);
        assert!(has_line(&lines, "does not exist"), "{lines:?}");
        // Nothing is counted, because there is nothing there to count. (The
        // absence is reported on the same `contains` line, so the assertion
        // is on the count itself.)
        assert!(!has_line(&lines, "files across"), "{lines:?}");

        let lines = preview_lines(&format!("rm -rf {}", present.display()), None);
        assert!(!has_line(&lines, "does not exist"), "{lines:?}");
        assert!(has_line(&lines, "files across"), "{lines:?}");
    }

    #[test]
    fn an_insurable_delete_within_budget_reports_its_insurance() {
        let tmp = TempTree::new("del-insurance");
        let dir = tmp.dir("small");
        std::fs::write(dir.join("a.txt"), "a").expect("file must be writable");

        let lines = preview_lines(&format!("rm -rf {}", dir.display()), None);
        assert!(
            has_line(&lines, "insurance   :"),
            "a small delete is recoverable and should say so: {lines:?}"
        );
        assert!(
            !has_line(&lines, "too large to copy"),
            "nothing here is too large: {lines:?}"
        );
    }

    #[test]
    fn a_delete_too_large_to_copy_says_that_rather_than_naming_insurance() {
        // "Not recoverable" is ambiguous on its own: it could mean no backup
        // engine covers the command, or that the target is simply too big to
        // copy. Two different facts get two different sentences, and reaching
        // this one needs a scan that actually caps.
        let tmp = TempTree::new("del-too-large");
        let dir = tmp.dir("huge");
        for i in 0..(MAX_FILES + 100) {
            std::fs::write(dir.join(format!("f{i}")), "").expect("file must be writable");
        }

        let lines = preview_lines(&format!("rm -rf {}", dir.display()), None);
        assert!(
            has_line(&lines, "too large to copy"),
            "an insurable command over budget must say which fact applies: {lines:?}"
        );
        assert!(
            !has_line(&lines, "insurance   :"),
            "it cannot both promise insurance and say it is out of reach: {lines:?}"
        );
        assert!(
            has_line(&lines, "+ files (stopped counting)"),
            "the count says it stopped: {lines:?}"
        );
    }

    #[test]
    fn a_cmd_switch_is_matched_by_shape_not_by_its_leading_slash() {
        for switch in ["/s", "/q", "/f", "/a:h", "/a:"] {
            assert!(is_cmd_switch(switch), "{switch} is a cmd switch");
        }
        // Four characters and a leading slash, but a path: `del /s /q /tmp`
        // must keep its target.
        for path in ["/tmp", "/usr", "/c/Users", "/a:hidden", "notaswitch"] {
            assert!(!is_cmd_switch(path), "{path} is a path");
        }
    }

    #[test]
    fn a_drive_letter_is_split_only_when_it_really_is_one() {
        assert_eq!(split_drive("c/Users/x"), Some(("c", "Users/x")));
        assert_eq!(split_drive("c"), Some(("c", "")));
        // `/usr/local/lib` must not resolve to `C:/usr/local/lib`.
        assert_eq!(split_drive("usr/local/lib"), None);
        assert_eq!(split_drive("1/x"), None);
    }

    #[test]
    fn a_tilde_is_expanded_to_the_home_it_names() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .expect("a home directory must be set");
        let home = PathBuf::from(home);

        assert_eq!(resolve_path_here("~"), home);
        assert_eq!(resolve_path_here("~/projects"), home.join("projects"));
        // A path that merely starts with the character is not an expansion.
        assert_ne!(resolve_path_here("~notauser"), home.join("notauser"));
    }

    /// Sets HOME/USERPROFILE for the life of the guard. Process-global, so
    /// every caller holds `TestEnv`'s lock.
    struct HomeGuard {
        home: Option<std::ffi::OsString>,
        profile: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        fn set(home: Option<&Path>) -> Self {
            let guard = HomeGuard {
                home: std::env::var_os("HOME"),
                profile: std::env::var_os("USERPROFILE"),
            };
            std::env::remove_var("USERPROFILE");
            match home {
                Some(p) => std::env::set_var("HOME", p),
                None => std::env::remove_var("HOME"),
            }
            guard
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match self.home.take() {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match self.profile.take() {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }

    #[test]
    fn a_home_and_its_siblings_are_recognised_as_profiles() {
        let env = TestEnv::new("del-profile");
        let users = env.root().join("home");
        let alice = users.join("alice");
        std::fs::create_dir_all(&alice).expect("home must be creatable");
        let _guard = HomeGuard::set(Some(&alice));

        assert!(is_user_profile(&alice), "the home itself");
        assert!(
            is_user_profile(&users.join("bob")),
            "a sibling profile: an agent on a mistyped path lands here"
        );
        assert!(
            !is_user_profile(&alice.join("projects")),
            "something inside a profile is not the profile"
        );
        assert!(
            !is_user_profile(&env.root().join("etc")),
            "a different parent is a different thing"
        );
        // Same depth as the home, different parent. Depth alone must not
        // make something a profile, or every third-level directory on the
        // machine becomes one.
        let same_depth_elsewhere = env.root().join("srv").join("bob");
        assert!(
            !is_user_profile(&same_depth_elsewhere),
            "{}",
            same_depth_elsewhere.display()
        );
    }

    #[test]
    fn the_profile_shapes_are_recognised_even_with_no_home_set() {
        let _env = TestEnv::new("del-profile-fallback");
        let _guard = HomeGuard::set(None);

        assert!(is_user_profile(Path::new("/home/alice")));
        assert!(is_user_profile(Path::new("/Users/alice")));
        assert!(is_user_profile(Path::new("C:\\Users\\alice")));
        assert!(!is_user_profile(Path::new("/home/alice/projects")));
        assert!(!is_user_profile(Path::new("/etc")));
    }

    #[test]
    fn sensitive_children_are_named_whatever_their_casing() {
        let tmp = TempTree::new("del-sensitive");
        let dir = tmp.dir("home");
        std::fs::create_dir_all(dir.join(".SSH")).expect("dir must be creatable");
        std::fs::write(dir.join(".env"), "SECRET=1").expect("file must be writable");
        std::fs::write(dir.join("notes.txt"), "hello").expect("file must be writable");

        let found = sensitive_children(&dir);
        let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&".SSH"),
            "an upper-case spelling holds the same keys: {names:?}"
        );
        assert!(names.contains(&".env"), "{names:?}");
        assert_eq!(
            found.len(),
            2,
            "two different sensitive entries are two findings: {names:?}"
        );
        assert!(
            !names.contains(&"notes.txt"),
            "ordinary files are not findings: {names:?}"
        );
    }
}
