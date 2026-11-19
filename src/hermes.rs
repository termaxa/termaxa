//! Hermes Agent's wiring: the hooks a profile's `config.yaml` declares, the
//! approval Hermes needs before it runs one, and what `termaxa init
//! --hermes` writes for both and `termaxa doctor` reads back.
//!
//! Read from Hermes Agent 0.23.2's own code (`agent/shell_hooks.py`,
//! `hermes_constants.py`, `hermes_cli/config.py`) on Nov 20, 2026, and
//! measured in a real session the day before (docs/dialects.md):
//!
//! - A hook is an entry under `hooks:` in the profile's `config.yaml`:
//!   `matcher` (a regex the tool's name must match in full), `command`,
//!   `timeout`, and `fail_closed`, which makes a hook that cannot answer
//!   refuse the call instead of letting it run.
//! - Hermes runs a hook only once its event and its exact command are
//!   approved in the profile's `shell-hooks-allowlist.json`. Without the
//!   approval the hook is skipped, with a line in `agent.log` and nothing
//!   else; only a foreground `hermes chat` asks. The approval is keyed on
//!   the event and the command, nothing more.
//! - The command is split into words and started without a shell.
//! - Hermes writes `config.yaml` with no `hooks:` key until someone adds
//!   one, and rewrites the file whole when its own settings change.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// The tools whose calls the gate reads: the shell, the two file writers,
/// and `execute_code`, which is always an ask.
pub const PRE_MATCHER: &str = "terminal|write_file|patch|execute_code";
/// The calls a receipt is kept for once they ran.
pub const POST_MATCHER: &str = "terminal|write_file|patch";
const TIMEOUT_SECS: u32 = 30;
pub const ALLOWLIST: &str = "shell-hooks-allowlist.json";
const EVENTS: [&str; 2] = ["pre_tool_call", "post_tool_call"];

/// The command `init --hermes` registers, for this binary. Hermes starts it
/// without a shell (`command_for`).
pub fn command_for_this_binary() -> Result<String> {
    let exe = std::env::current_exe().context("cannot tell where this termaxa binary is")?;
    Ok(command_for(
        &exe,
        termaxa_on_path().as_deref(),
        cfg!(windows),
    ))
}

/// On Windows, the full path of the binary: Windows looks for a bare name in
/// the directory Hermes runs from before it looks on PATH (`CreateProcess`),
/// so a `termaxa.exe` put there would be started in the gate's place.
/// Elsewhere, `termaxa` when PATH finds this binary, which keeps working
/// when an upgrade moves it (Homebrew keeps each version in a directory of
/// its own), and the full path when PATH finds another termaxa or none.
pub fn command_for(exe: &Path, on_path: Option<&Path>, windows: bool) -> String {
    let same = |a: &Path, b: &Path| match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !windows && on_path.is_some_and(|p| same(p, exe)) {
        return "termaxa hook --hermes".to_string();
    }
    let shown = exe.display().to_string();
    if shown.chars().any(char::is_whitespace) {
        format!("\"{shown}\" hook --hermes")
    } else {
        format!("{shown} hook --hermes")
    }
}

fn termaxa_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("termaxa"))
        .find(|p| p.is_file())
}

/// The `hooks:` block `init --hermes` adds: the four tools gated before
/// they run, with `fail_closed`, and receipts after the three that write.
pub fn hooks_block(command: &str) -> String {
    let command = yaml_quoted(command);
    format!(
        "# Added by `termaxa init --hermes`: Hermes asks termaxa before each terminal\n\
         # command, file write, patch and execute_code call, and refuses the call\n\
         # when termaxa cannot answer (fail_closed). `termaxa doctor` checks it.\n\
         hooks:\n  \
         pre_tool_call:\n    \
         - matcher: \"{PRE_MATCHER}\"\n      \
         command: {command}\n      \
         timeout: {TIMEOUT_SECS}\n      \
         fail_closed: true\n  \
         post_tool_call:\n    \
         - matcher: \"{POST_MATCHER}\"\n      \
         command: {command}\n      \
         timeout: {TIMEOUT_SECS}\n"
    )
}

/// Single quotes, in which YAML reads a backslash as itself: a Windows path
/// in double quotes would be read as escapes.
fn yaml_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// What adding the hooks to a `config.yaml` comes to.
#[derive(Debug, PartialEq)]
pub enum ConfigEdit {
    /// The file with the hooks added and nothing else changed.
    Edited(String),
    /// The gate's entry is there already.
    Wired,
    /// A `hooks:` block of the person's own is there, so the file is not
    /// edited; `termaxa` is a termaxa command in it, if one is.
    OwnHooks { termaxa: Option<String> },
}

/// `original` with the hooks block added for `command`, when that can be
/// done without changing anything the file already says: appended where
/// the file has no `hooks:` key, or in place of a `hooks:` line with
/// nothing under it. A file with hooks of its own is left alone, because
/// merging into it would mean rewriting text termaxa did not write. Every
/// edit is read back: the hooks must be there and every other key must say
/// what it said, or nothing is written.
pub fn config_with_hooks(original: &str, command: &str) -> Result<ConfigEdit> {
    let bom = original.starts_with('\u{feff}');
    let text = original.trim_start_matches('\u{feff}');
    let before = parse_mapping(text)?;
    let hooks = before.get("hooks");
    if let Some(hooks) = hooks.filter(|h| !is_empty(h)) {
        let pre = entries(hooks, "pre_tool_call");
        if pre.iter().any(|e| e.command == command) {
            return Ok(ConfigEdit::Wired);
        }
        let termaxa = pre
            .into_iter()
            .map(|e| e.command)
            .find(|c| crate::doctor::probe_allowed(c));
        return Ok(ConfigEdit::OwnHooks { termaxa });
    }
    let block = hooks_block(command);
    let edited = if hooks.is_some() {
        match replace_empty_hooks_line(text, &block) {
            Some(edited) => edited,
            None => return Ok(ConfigEdit::OwnHooks { termaxa: None }),
        }
    } else {
        let mut edited = text.to_string();
        if !edited.is_empty() {
            if !edited.ends_with('\n') {
                edited.push('\n');
            }
            edited.push('\n');
        }
        edited.push_str(&block);
        edited
    };

    let after = parse_mapping(&edited).ok();
    let added = after.as_ref().is_some_and(|after| {
        let wired = after.get("hooks").is_some_and(|h| {
            entries(h, "pre_tool_call")
                .iter()
                .any(|e| e.command == command)
        });
        let mut rest = after.clone();
        rest.remove("hooks");
        let mut was = before.clone();
        was.remove("hooks");
        wired && rest == was
    });
    if !added {
        bail!("adding the hooks would change what config.yaml says; add them by hand");
    }
    Ok(ConfigEdit::Edited(if bom {
        format!("\u{feff}{edited}")
    } else {
        edited
    }))
}

fn parse_mapping(text: &str) -> Result<serde_yaml::Mapping> {
    if text.trim().is_empty() {
        return Ok(serde_yaml::Mapping::new());
    }
    match serde_yaml::from_str::<serde_yaml::Value>(text)
        .context("config.yaml is not YAML termaxa can read")?
    {
        serde_yaml::Value::Mapping(m) => Ok(m),
        serde_yaml::Value::Null => Ok(serde_yaml::Mapping::new()),
        _ => bail!("config.yaml does not hold a mapping of settings"),
    }
}

fn is_empty(v: &serde_yaml::Value) -> bool {
    match v {
        serde_yaml::Value::Null => true,
        serde_yaml::Value::Mapping(m) => m.is_empty(),
        serde_yaml::Value::Sequence(s) => s.is_empty(),
        _ => false,
    }
}

/// The one top-level `hooks:` line whose value is nothing (`hooks:`,
/// `hooks: {}`, `hooks: null`, `hooks: ~`), replaced by `block`.
fn replace_empty_hooks_line(text: &str, block: &str) -> Option<String> {
    let empty = |line: &str| {
        let Some(rest) = line.strip_prefix("hooks:") else {
            return false;
        };
        let value = rest.split(" #").next().unwrap_or("").trim();
        matches!(value, "" | "{}" | "[]" | "null" | "~")
    };
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let at: Vec<usize> = (0..lines.len()).filter(|&i| empty(lines[i])).collect();
    let [at] = at[..] else {
        return None;
    };
    let mut out: String = lines[..at].concat();
    out.push_str(block);
    out.push_str(&lines[at + 1..].concat());
    Some(out)
}

/// One entry under `hooks.<event>`, read as Hermes reads it: the command
/// and the matcher trimmed, `fail_closed` (or Cursor's `failClosed`) true
/// only when it is the boolean true.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub command: String,
    pub matcher: Option<String>,
    pub fail_closed: bool,
}

fn entries(hooks: &serde_yaml::Value, event: &str) -> Vec<Entry> {
    let Some(list) = hooks.get(event).and_then(|l| l.as_sequence()) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|e| {
            let command = e.get("command")?.as_str()?.trim().to_string();
            let matcher = e
                .get("matcher")
                .and_then(|m| m.as_str())
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty());
            let fail_closed = e
                .get("fail_closed")
                .or_else(|| e.get("failClosed"))
                .and_then(|f| f.as_bool())
                .unwrap_or(false);
            Some(Entry {
                command,
                matcher,
                fail_closed,
            })
        })
        .collect()
}

/// The allowlist with both events approved for `command`, as
/// `hermes --accept-hooks` records an approval; `None` when both already
/// are. A file Hermes could not read is not overwritten: it may hold
/// approvals someone means to keep.
pub fn allowlist_with(original: Option<&str>, command: &str, now: &str) -> Result<Option<String>> {
    let mut doc = match original {
        None => json!({ "approvals": [] }),
        Some(text) => serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}'))
            .with_context(|| format!("{ALLOWLIST} is not JSON"))?,
    };
    let Some(map) = doc.as_object_mut() else {
        bail!("{ALLOWLIST} does not hold an object");
    };
    let approvals = map
        .entry("approvals")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .with_context(|| format!("`approvals` in {ALLOWLIST} is not a list"))?;
    let mut added = false;
    for event in EVENTS {
        let approved = approvals.iter().any(|e| {
            e.get("event").and_then(|v| v.as_str()) == Some(event)
                && e.get("command").and_then(|v| v.as_str()) == Some(command)
        });
        if !approved {
            // Hermes records the mtime of a hook's script so that `hermes
            // hooks doctor` can say the script changed since it was
            // approved. A binary is replaced by every upgrade, which that
            // check would report each time as a change to review, so none
            // is recorded (Hermes records none for a bare name either).
            approvals.push(json!({
                "approved_at": now,
                "command": command,
                "event": event,
                "script_mtime_at_approval": null,
            }));
            added = true;
        }
    }
    if !added {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string_pretty(&doc)? + "\n"))
}

/// Now, as Hermes writes a time: UTC, ISO 8601, microseconds when there
/// are any, and `Z`.
pub fn now_iso() -> String {
    let now = chrono::Utc::now();
    match now.timestamp_subsec_micros() {
        0 => now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        micros => format!("{}.{micros:06}Z", now.format("%Y-%m-%dT%H:%M:%S")),
    }
}

/// Replace `path` whole, never leaving half a file: written beside it and
/// renamed over it, with the permissions it had (Hermes keeps both files
/// readable by their owner only; `config.yaml` can hold keys). A new file
/// gets the owner-only mode Hermes gives its own.
pub fn write_atomically(path: &Path, text: &str) -> Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!("{name}.termaxa-tmp"));
    fs::write(&tmp, text).with_context(|| format!("cannot write {}", tmp.display()))?;
    let kept = match fs::metadata(path) {
        Ok(meta) => fs::set_permissions(&tmp, meta.permissions()),
        Err(_) => owner_only(&tmp),
    };
    if let Err(e) = kept.and_then(|_| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot replace {}", path.display()));
    }
    Ok(())
}

#[cfg(unix)]
fn owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// What a profile's files say about the gate's hook, for `doctor`.
#[derive(Debug, Default)]
pub struct Wiring {
    /// The `pre_tool_call` entry whose command is termaxa's, if one is.
    pub entry: Option<Entry>,
    /// A `post_tool_call` entry runs termaxa too.
    pub post: bool,
    /// The allowlist approves `pre_tool_call` for that command, or the
    /// profile approves every hook (`hooks_auto_accept`).
    pub approved: bool,
    /// Why `config.yaml` could not be read, when it could not.
    pub unreadable: Option<String>,
}

pub fn read_wiring(home: &Path) -> Wiring {
    let config = match fs::read_to_string(home.join("config.yaml")) {
        Ok(text) => text,
        Err(e) => {
            return Wiring {
                unreadable: Some(e.to_string()),
                ..Wiring::default()
            }
        }
    };
    let map = match parse_mapping(config.trim_start_matches('\u{feff}')) {
        Ok(map) => map,
        Err(e) => {
            return Wiring {
                unreadable: Some(format!("{e:#}")),
                ..Wiring::default()
            }
        }
    };
    let hooks = map.get("hooks");
    let termaxa = |event: &str| {
        hooks
            .map(|h| entries(h, event))
            .unwrap_or_default()
            .into_iter()
            .find(|e| crate::doctor::probe_allowed(&e.command))
    };
    let entry = termaxa("pre_tool_call");
    let auto_accept = match map.get("hooks_auto_accept") {
        Some(serde_yaml::Value::Bool(b)) => *b,
        Some(serde_yaml::Value::String(s)) => {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        }
        _ => false,
    };
    let approved = auto_accept
        || entry.as_ref().is_some_and(|e| {
            fs::read_to_string(home.join(ALLOWLIST))
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(t.trim_start_matches('\u{feff}')).ok())
                .and_then(|v| v.get("approvals").and_then(|a| a.as_array()).cloned())
                .is_some_and(|approvals| {
                    approvals.iter().any(|a| {
                        a.get("event").and_then(|v| v.as_str()) == Some("pre_tool_call")
                            && a.get("command").and_then(|v| v.as_str()) == Some(e.command.as_str())
                    })
                })
        });
    Wiring {
        post: termaxa("post_tool_call").is_some(),
        entry,
        approved,
        unreadable: None,
    }
}

/// Whether a matcher lets `tool`'s calls reach the hook: Hermes matches the
/// tool's whole name against it as a regex, and an entry without one gets
/// every tool. `None` when the matcher is more than names joined by `|`,
/// which this does not try to read.
pub fn matcher_covers(matcher: Option<&str>, tool: &str) -> Option<bool> {
    let Some(matcher) = matcher else {
        return Some(true);
    };
    if matcher
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '|'))
    {
        return None;
    }
    Some(matcher.split('|').any(|name| name == tool))
}

/// A hook command split into words as Hermes splits it
/// (`split_command_line`), after reading a leading `~` as the home
/// directory: shell words on Linux and macOS; on Windows, words where
/// quotes group and one layer of them is removed, and where a backslash is
/// part of a path, not an escape. `None` for an unclosed quote.
pub fn argv(command: &str, windows: bool) -> Option<Vec<String>> {
    let command = expand_home(command, windows);
    let mut words = Vec::new();
    let mut chars = command.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(&first) = chars.peek() else {
            return Some(words);
        };
        let mut word = String::new();
        if windows {
            if first == '"' || first == '\'' {
                chars.next();
                loop {
                    match chars.next()? {
                        c if c == first => break,
                        c => word.push(c),
                    }
                }
            } else {
                while let Some(c) = chars.next_if(|c| !c.is_whitespace()) {
                    word.push(c);
                }
            }
        } else {
            while let Some(c) = chars.next_if(|c| !c.is_whitespace()) {
                match c {
                    '\'' => loop {
                        match chars.next()? {
                            '\'' => break,
                            c => word.push(c),
                        }
                    },
                    '"' => loop {
                        match chars.next()? {
                            '"' => break,
                            '\\' if matches!(chars.peek(), Some('"' | '\\')) => {
                                word.push(chars.next()?)
                            }
                            c => word.push(c),
                        }
                    },
                    '\\' => word.push(chars.next()?),
                    c => word.push(c),
                }
            }
        }
        words.push(word);
    }
}

fn expand_home(command: &str, windows: bool) -> String {
    let home = std::env::var(if windows { "USERPROFILE" } else { "HOME" }).ok();
    match (command.strip_prefix('~'), home) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with(['/', '\\']) => {
            format!("{home}{rest}")
        }
        _ => command.to_string(),
    }
}

/// The verdict in what a `--hermes` hook printed: Hermes's block (either
/// spelling) is a deny, its `approve` an ask, and the empty object a probe
/// gets for an allow (every other allow is silence) an allow.
pub fn parse_answer(out: &str) -> Option<&'static str> {
    let v: Value = serde_json::from_str(out.trim()).ok()?;
    let m = v.as_object()?;
    let field = |k: &str| m.get(k).and_then(|x| x.as_str());
    if field("decision") == Some("block") || field("action") == Some("block") {
        return Some("deny");
    }
    if field("action") == Some("approve") {
        return Some("ask");
    }
    m.is_empty().then_some("allow")
}

/// How long a probe waits. Longer than `doctor`'s for the other agents:
/// Hermes gives a hook 30 seconds, a binary scanned on its first start can
/// take a few, and with `fail_closed` a hook reported dead in error would
/// send someone looking for a fault that is not there.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Run a registered command as Hermes would (its words, no shell) with a
/// `terminal` call to `rm -rf /` that marks itself as `doctor`'s probe, and
/// read the verdict. The probe writes nothing (`hook::PROBE_SESSION`), and
/// only a command whose program is named `termaxa` is run.
pub fn probe(command: &str, dir: &Path) -> Option<&'static str> {
    if !crate::doctor::probe_allowed(command) {
        return None;
    }
    let argv = argv(command, cfg!(windows))?;
    let (program, args) = argv.split_first()?;
    let mut run = std::process::Command::new(program);
    run.args(args);
    let payload = json!({
        "hook_event_name": "pre_tool_call",
        "tool_name": "terminal",
        "tool_input": { "command": "rm -rf /" },
        "session_id": crate::hook::PROBE_SESSION,
        "cwd": dir.display().to_string(),
        "profile": "default",
        "extra": { "tool_call_id": crate::hook::PROBE_SESSION },
    })
    .to_string();
    let out = crate::doctor::run_probe(run, &payload, dir, PROBE_TIMEOUT)?;
    parse_answer(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: &str = "termaxa hook --hermes";

    fn edited(original: &str) -> String {
        match config_with_hooks(original, CMD).unwrap() {
            ConfigEdit::Edited(text) => text,
            other => panic!("not edited: {other:?}"),
        }
    }

    fn pre_commands(text: &str) -> Vec<String> {
        let map = parse_mapping(text.trim_start_matches('\u{feff}')).unwrap();
        entries(map.get("hooks").unwrap(), "pre_tool_call")
            .into_iter()
            .map(|e| e.command)
            .collect()
    }

    /// A file with no `hooks:` key gets the block at its end, and keeps
    /// every byte it had; an empty file gets the block alone.
    #[test]
    fn hooks_are_appended_and_nothing_else_changes() {
        let original = "model:\n  default: claude-opus-5-5\n  provider: anthropic\n# a comment\nterminal:\n  backend: local";
        let text = edited(original);
        assert!(text.starts_with(original));
        assert_eq!(pre_commands(&text), [CMD]);
        let map = parse_mapping(&text).unwrap();
        let hook = &map.get("hooks").unwrap().get("pre_tool_call").unwrap()[0];
        assert_eq!(hook.get("matcher").unwrap().as_str(), Some(PRE_MATCHER));
        assert_eq!(hook.get("fail_closed").unwrap().as_bool(), Some(true));
        assert_eq!(hook.get("timeout").unwrap().as_u64(), Some(30));
        let post = &map.get("hooks").unwrap().get("post_tool_call").unwrap()[0];
        assert_eq!(post.get("matcher").unwrap().as_str(), Some(POST_MATCHER));
        assert_eq!(post.get("fail_closed"), None);
        assert_eq!(edited(""), hooks_block(CMD));
        let bom = edited("\u{feff}model: {}\n");
        assert!(bom.starts_with("\u{feff}model: {}\n\n# Added by"));
    }

    /// A `hooks:` line with nothing under it becomes the block; hooks of
    /// the person's own are not merged into, and the gate's entry already
    /// there is not added twice.
    #[test]
    fn hooks_of_its_own_are_left_alone() {
        for empty in ["hooks: {}", "hooks:", "hooks: null # off for now"] {
            let text = edited(&format!("model: {{}}\n{empty}\nterminal:\n  cwd: .\n"));
            assert_eq!(pre_commands(&text), [CMD]);
            assert!(text.ends_with("terminal:\n  cwd: .\n"));
        }
        let own = "hooks:\n  pre_tool_call:\n    - command: ~/.hermes/agent-hooks/guard.sh\n";
        assert_eq!(
            config_with_hooks(own, CMD).unwrap(),
            ConfigEdit::OwnHooks { termaxa: None }
        );
        let old = "hooks:\n  pre_tool_call:\n    - command: /opt/termaxa/termaxa hook --hermes\n";
        assert_eq!(
            config_with_hooks(old, CMD).unwrap(),
            ConfigEdit::OwnHooks {
                termaxa: Some("/opt/termaxa/termaxa hook --hermes".into())
            }
        );
        let wired = edited("model: {}\n");
        assert_eq!(config_with_hooks(&wired, CMD).unwrap(), ConfigEdit::Wired);
        assert!(config_with_hooks("model: [unclosed\n", CMD).is_err());
        assert!(config_with_hooks("- a list\n", CMD).is_err());
    }

    /// A Windows path survives YAML as written: in single quotes a
    /// backslash is itself.
    #[test]
    fn a_windows_path_is_written_as_itself() {
        let cmd = "C:\\Users\\Dev User\\.cargo\\bin\\termaxa.exe hook --hermes";
        let text = match config_with_hooks("model: {}\n", cmd).unwrap() {
            ConfigEdit::Edited(text) => text,
            other => panic!("not edited: {other:?}"),
        };
        assert_eq!(pre_commands(&text), [cmd]);
        let exe = Path::new("C:\\Program Files\\termaxa\\termaxa.exe");
        assert_eq!(
            command_for(exe, None, true),
            "\"C:\\Program Files\\termaxa\\termaxa.exe\" hook --hermes"
        );
        assert_eq!(
            argv(&command_for(exe, None, true), true).unwrap(),
            [
                "C:\\Program Files\\termaxa\\termaxa.exe",
                "hook",
                "--hermes"
            ]
        );
    }

    /// The approvals Hermes's `--accept-hooks` would write, once each,
    /// beside the ones already there; a file Hermes cannot read is kept.
    #[test]
    fn approvals_are_added_once_and_others_kept() {
        let now = "2026-11-20T00:00:00.000001Z";
        let fresh = allowlist_with(None, CMD, now).unwrap().unwrap();
        let v: Value = serde_json::from_str(&fresh).unwrap();
        let approvals = v["approvals"].as_array().unwrap();
        assert_eq!(approvals.len(), 2);
        assert_eq!(approvals[0]["event"], "pre_tool_call");
        assert_eq!(approvals[1]["event"], "post_tool_call");
        assert_eq!(approvals[0]["command"], CMD);
        assert_eq!(approvals[0]["approved_at"], now);
        assert!(approvals[0]["script_mtime_at_approval"].is_null());
        assert_eq!(allowlist_with(Some(&fresh), CMD, now).unwrap(), None);

        let other = r#"{"approvals":[{"event":"pre_tool_call","command":"guard.sh","approved_at":"x","script_mtime_at_approval":null}]}"#;
        let merged = allowlist_with(Some(other), CMD, now).unwrap().unwrap();
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(v["approvals"].as_array().unwrap().len(), 3);
        assert_eq!(v["approvals"][0]["command"], "guard.sh");

        assert!(allowlist_with(Some("not json"), CMD, now).is_err());
        assert!(allowlist_with(Some("[]"), CMD, now).is_err());
        assert!(allowlist_with(Some(r#"{"approvals":{}}"#), CMD, now).is_err());
        assert!(allowlist_with(Some("{}"), CMD, now).unwrap().is_some());
    }

    #[test]
    fn hermes_answers_are_read_and_others_are_not() {
        assert_eq!(
            parse_answer(r#"{"decision":"block","reason":"x"}"#),
            Some("deny")
        );
        assert_eq!(
            parse_answer(r#"{"action":"block","message":"x"}"#),
            Some("deny")
        );
        assert_eq!(
            parse_answer(r#"{"action":"approve","message":"x"}"#),
            Some("ask")
        );
        assert_eq!(parse_answer("{}\n"), Some("allow"));
        assert_eq!(parse_answer(""), None);
        assert_eq!(parse_answer(r#"{"hookSpecificOutput":{}}"#), None);
        assert_eq!(matcher_covers(Some(PRE_MATCHER), "terminal"), Some(true));
        assert_eq!(
            matcher_covers(Some("write_file|patch"), "terminal"),
            Some(false)
        );
        assert_eq!(matcher_covers(None, "terminal"), Some(true));
        assert_eq!(matcher_covers(Some("term.*"), "terminal"), None);
        assert_eq!(
            argv("'/opt/my tools/termaxa' hook --hermes", false).unwrap(),
            ["/opt/my tools/termaxa", "hook", "--hermes"]
        );
        assert_eq!(argv("termaxa \"hook", false), None);
    }
}
