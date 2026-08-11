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

pub fn preview_for(command: &str, project_root: Option<&Path>) -> Option<Preview> {
    let targets = extract_targets(command);
    if targets.is_empty() {
        return None;
    }

    let mut lines = Vec::new();
    let mut summary_parts: Vec<String> = Vec::new();
    let mut worst_first: Vec<String> = Vec::new();

    for raw in targets.iter().take(3) {
        let resolved = resolve_path(raw);
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
        match crate::backup::plan(command) {
            Some(plan) if !scan.capped => {
                lines.push(format!("  insurance   : {} (automatic on run/hook)", plan));
            }
            Some(_) => {
                lines.push(format!(
                    "  ✗ insurance : too large to copy ({}+ files) — NOT recoverable",
                    fmt_num(MAX_FILES)
                ));
                worst_first.push("NOT recoverable".into());
            }
            None => {
                lines
                    .push("  ✗ insurance : no backup covers this command — NOT recoverable".into());
                worst_first.push("NOT recoverable".into());
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
    })
}

// ---------------------------------------------------------------------------
// target extraction
// ---------------------------------------------------------------------------

/// Pull delete targets out of a command string, across the three shells the
/// classifier already knows about. Deliberately conservative: if we can't
/// confidently identify a target we return nothing rather than guessing, and
/// the caller falls back to no preview.
pub fn extract_targets(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in crate::shell::split_segments(command) {
        let tokens = tokenize(&segment);
        if tokens.is_empty() {
            continue;
        }
        let head = command_head(&tokens[0]);
        if !is_delete_command(&head) {
            continue;
        }

        for t in tokens.iter().skip(1) {
            if is_flag(&head, t) {
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
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), ch) if ch == q => quote = None,
            (Some(_), ch) => cur.push(ch),
            (None, '"') | (None, '\'') => quote = Some(c),
            (None, ch) if ch.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            (None, ch) => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
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
pub fn resolve_path(raw: &str) -> PathBuf {
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
    let joined = if p.is_absolute() {
        p
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(p)
    } else {
        p
    };
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
fn for_compare(p: &Path) -> PathBuf {
    let c = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let s = c.to_string_lossy().to_string();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
    if cfg!(windows) {
        PathBuf::from(s.to_lowercase())
    } else {
        PathBuf::from(s)
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
            let p = resolve_path("/c/Users/harih");
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
            let u = resolve_path("/usr/local/lib")
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
                resolve_path("/usr/local/lib"),
                PathBuf::from("/usr/local/lib")
            );
            assert_eq!(resolve_path("/etc/hosts"), PathBuf::from("/etc/hosts"));
        }
    }

    #[test]
    fn relative_paths_normalise_and_stay_inside_the_project() {
        // Live-testing regression: `./target` resolved with the dot component
        // intact, so is_inside said OUTSIDE the project root — a false alarm
        // on the most ordinary delete there is.
        let root = std::env::current_dir().unwrap();
        let t = resolve_path("./target");
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
        let up = resolve_path("../sibling");
        assert!(
            !is_inside(&up, &root),
            "../sibling must be outside the cwd, got {}",
            up.display()
        );

        // A bare relative name resolves under the cwd too. This is the
        // asymmetry that broke it: `target` exists (cargo makes it) so it
        // canonicalized, while `build` does not — and on Windows the two
        // forms are not comparable unless both are normalised first.
        let b = resolve_path("build");
        assert!(
            is_inside(&b, &root),
            "a non-existent in-project path must still be inside, got {}",
            b.display()
        );
        assert!(
            is_inside(&resolve_path("definitely-not-created-yet"), &root),
            "existence must not change the inside/outside answer"
        );
    }

    #[test]
    fn quotes_are_stripped_before_resolution() {
        // Whatever /c/tmp resolves to on this platform, the quoted form must
        // resolve identically — the assertion is about quote handling, not
        // about drive conversion.
        assert_eq!(
            resolve_path("\"/c/tmp\"").to_string_lossy().to_lowercase(),
            resolve_path("/c/tmp").to_string_lossy().to_lowercase()
        );
        assert_eq!(
            resolve_path("'/tmp/x'").to_string_lossy(),
            resolve_path("/tmp/x").to_string_lossy()
        );
    }

    #[test]
    fn filesystem_roots_are_recognised() {
        assert!(is_filesystem_root(Path::new("/")));
        assert!(is_filesystem_root(Path::new("C:\\")));
        assert!(!is_filesystem_root(Path::new("/usr")));
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

    #[test]
    fn number_formatting_matches_the_incident() {
        assert_eq!(fmt_num(70201), "70,201");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(0), "0");
    }
}
