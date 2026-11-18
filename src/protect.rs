//! The paths an agent's file-writing tool may not write to.
//!
//! Policy rules gate **shell commands**, and the starter policy's self-defence
//! block closes that path: `echo 'default: allow' > .termaxa/policy.yaml`
//! matches a deny. It closes only that path. An agent whose `rm` is denied and
//! which reaches for `Write` instead is routing around an obstacle in the most
//! ordinary way an agent does anything, and until this module existed nothing
//! was looking.
//!
//! Scope is deliberately narrow. This answers ONE question about ONE path:
//! does writing here disable the gate or erase its record? It is not a general
//! file-write policy. Gating every write would make Termaxa unusable and is
//! not what it is for, so a path this module does not recognise produces no
//! decision at all — not an `allow`. Declining to answer where we have no
//! opinion leaves the harness's own permission flow exactly as it was.
//!
//! Three assets, and only three:
//!
//! - **the policy and the state** — anything under a `.termaxa` directory,
//!   which covers `.termaxa/policy.yaml` in the repo and the logs, backups and
//!   fingerprint baseline under `$TERMAXA_HOME`;
//! - **the agent hook configuration** — the files that decide whether the hook
//!   runs at all, one per dialect, and Claude Code's `.claude/plugins/`, where
//!   a plugin's hooks are installed (v0.23.0);
//! - **the record**, which lives under `.termaxa` and so is covered by the
//!   first.
//!
//! Matching is on path *segments*, not substrings, so a file called
//! `termaxa-notes.md` is untouched while `/repo/.termaxa/policy.yaml` and
//! `C:\repo\.termaxa\policy.yaml` are both recognised. Comparison is
//! case-insensitive for the same reason policy matching is: the cost of
//! refusing a write to a strangely-cased `.TERMAXA` is one puzzled agent, and
//! the cost of missing one is the gate.
//!
//! A directory is known by its name, and three of these directories can be
//! given another: `CLAUDE_CONFIG_DIR` moves Claude Code's `~/.claude`,
//! `CODEX_HOME` moves Codex's `~/.codex`, and `TERMAXA_HOME` moves the gate's
//! own `~/.termaxa`. Until v0.22.0 nothing here followed them, so a settings
//! file under `~/.claude-work`, or a record under a state directory with a
//! name of its own, was a path this module did not recognise, and the path
//! rules of the starter did not either. A path inside a directory one of
//! those variables names is now read under the name the directory has by
//! default as well (`under_default_name`), here and by every path rule.

/// Why a write to this path is refused. `what` names the asset for the audit
/// log; `reason` is what the agent is told.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Protected {
    pub what: &'static str,
    pub reason: &'static str,
}

const POLICY_AND_RECORD: Protected = Protected {
    what: "termaxa-state",
    reason: "`.termaxa/` holds the gate's own policy and its record of what happened. \
             Writing to it from a file tool is not something a task needs. \
             Edit it yourself if the change is intended.",
};

const HOOK_CONFIG: Protected = Protected {
    what: "agent-hook-config",
    reason: "Agent hook configuration is off limits — editing it unhooks the gate. \
             Edit it yourself if the change is intended.",
};

/// Claude Code's plugins are hook configuration too: what is written under
/// `.claude/plugins/` decides which hooks run, the plugin's copy of this
/// gate's hook among them (v0.23.0).
const PLUGINS: Protected = Protected {
    what: "agent-hook-config",
    reason: "Claude Code's plugin files decide which hooks run, this gate's among them. \
             Change them yourself if the change is intended.",
};

/// Is `path` one of the gate's own files?
///
/// `cwd` is the agent's project directory from the hook payload, used only to
/// resolve a relative path. Agents send absolute paths in practice; this keeps
/// a relative one from reading as an unrecognised path and slipping through.
pub fn classify(cwd: &str, path: &str) -> Option<Protected> {
    let joined;
    let full = if is_absolute(path) || cwd.is_empty() {
        path
    } else {
        joined = format!("{}/{}", cwd.trim_end_matches(['/', '\\']), path);
        &joined
    };
    classify_segments(&segments(full))
}

/// Split on both separators and drop the noise `.` and empty segments, so
/// `./repo//.termaxa/policy.yaml` reads the same as `repo/.termaxa/policy.yaml`.
///
/// `..` is deliberately KEPT rather than resolved. Resolving it here would
/// mean re-implementing path normalisation for two platforms in the one place
/// where getting it wrong is silent; leaving it in means `.termaxa/../x` is
/// refused as if it were inside. That is an over-refusal, and an over-refusal
/// is loud.
pub(crate) fn segments(path: &str) -> Vec<String> {
    path.split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn is_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    if b.first() == Some(&b'/') || b.first() == Some(&b'\\') {
        return true;
    }
    // "C:\..." or "c:/..."
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

/// The directories a tool's own variable can move, and the name each has
/// when the variable is unset. The names are the ones every guard is
/// written against: this module's, the starter's path rules, a policy
/// somebody wrote.
const MOVED: [(&str, &str); 3] = [
    ("CLAUDE_CONFIG_DIR", ".claude"),
    ("CODEX_HOME", ".codex"),
    ("TERMAXA_HOME", ".termaxa"),
];

/// The default name of the directory `variable` moves, if it is one of the
/// three: `$CLAUDE_CONFIG_DIR/settings.json` names Claude Code's settings
/// whatever the variable holds, and is read as `.claude/settings.json` by
/// the readers that cannot expand it (`delete::readable_end`).
pub(crate) fn moved_name(variable: &str) -> Option<&'static str> {
    MOVED
        .iter()
        .find(|(v, _)| v.eq_ignore_ascii_case(variable))
        .map(|(_, name)| *name)
}

/// Where `variable` points in this process's environment: its value when it
/// is set to something, made absolute from the working directory.
pub(crate) fn moved_to(variable: &str) -> Option<std::path::PathBuf> {
    let value = std::env::var(variable).ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let path = std::path::PathBuf::from(value);
    if is_absolute(value) {
        Some(path)
    } else {
        Some(std::env::current_dir().ok()?.join(path))
    }
}

/// A variable spelled at `chars[at]`: `$NAME`, `${NAME}` (with a default
/// after the name or not), `%NAME%`, PowerShell's `$env:NAME`. Its name and
/// the index just past the spelling.
fn variable_at(chars: &[char], at: usize) -> Option<(String, usize)> {
    let is_name = |c: &char| c.is_ascii_alphanumeric() || *c == '_';
    let name_from =
        |from: usize| -> String { chars[from..].iter().take_while(|c| is_name(c)).collect() };
    match chars.get(at)? {
        '$' if chars.get(at + 1) == Some(&'{') => {
            let name = name_from(at + 2);
            let close = chars[at + 2..].iter().position(|c| *c == '}')?;
            (!name.is_empty()).then_some((name, at + 2 + close + 1))
        }
        '$' => {
            let name = name_from(at + 1);
            let after = at + 1 + name.chars().count();
            if name.eq_ignore_ascii_case("env") && chars.get(after) == Some(&':') {
                let inner = name_from(after + 1);
                let end = after + 1 + inner.chars().count();
                return (!inner.is_empty()).then_some((inner, end));
            }
            (!name.is_empty()).then_some((name, after))
        }
        '%' => {
            let name = name_from(at + 1);
            let after = at + 1 + name.chars().count();
            (!name.is_empty() && chars.get(after) == Some(&'%')).then_some((name, after + 1))
        }
        _ => None,
    }
}

/// `raw` with the variable it starts with put in: `$CLAUDE_CONFIG_DIR/x`,
/// `${CODEX_HOME}/hooks.json`, `%TERMAXA_HOME%\\projects`, `$env:CODEX_HOME\\x`,
/// for the three variables above and only where this process has a value for
/// the one named. The shell the command runs in has the same value, unless
/// the line itself assigns another, and then what it writes is not the
/// directory the tool reads. `None` for any other path, and for one of
/// these where the variable is unset: that one keeps its name
/// (`delete::readable_end`).
pub(crate) fn expand_moved(raw: &str) -> Option<String> {
    let chars: Vec<char> = raw.chars().collect();
    let (name, after) = variable_at(&chars, 0)?;
    let rest: String = chars[after..].iter().collect();
    if !(rest.is_empty() || rest.starts_with(['/', '\\'])) {
        return None;
    }
    let (variable, _) = MOVED.iter().find(|(v, _)| v.eq_ignore_ascii_case(&name))?;
    let dir = moved_to(variable)?;
    Some(format!("{}{}", dir.display(), rest))
}

/// Where each of those variables points in this process's environment, as
/// path segments, with the directory's default name. The environment is the
/// hook's own, which is the harness's and so the session's; a value that is
/// not absolute is taken from the hook's working directory, as the harness
/// took it from its own. A value that names no directory at all (`/`) is
/// not one to guard by.
///
/// Read once for the life of the process: every path a command touches is
/// asked about, a tree of thousands at a time, and the environment of a
/// hook or a supervisor does not change while it runs. Reading it at each
/// path doubled the time a 6,000-file delete took to judge. A test changes
/// these variables as it goes, so there it is read at each call.
fn moved_dirs() -> std::borrow::Cow<'static, [(Vec<String>, &'static str)]> {
    #[cfg(not(test))]
    {
        static DIRS: std::sync::OnceLock<Vec<(Vec<String>, &'static str)>> =
            std::sync::OnceLock::new();
        std::borrow::Cow::Borrowed(DIRS.get_or_init(read_moved_dirs).as_slice())
    }
    #[cfg(test)]
    {
        std::borrow::Cow::Owned(read_moved_dirs())
    }
}

fn read_moved_dirs() -> Vec<(Vec<String>, &'static str)> {
    let mut out = Vec::new();
    for (variable, name) in MOVED {
        let Some(dir) = moved_to(variable) else {
            continue;
        };
        let seg = segments(&dir.to_string_lossy());
        if !seg.is_empty() {
            out.push((seg, name));
        }
    }
    out
}

/// `seg` as it would read if the directory it lies in had its default name:
/// with `CLAUDE_CONFIG_DIR=/home/u/.claude-work`, the segments of
/// `/home/u/.claude-work/settings.json` become `.claude`, `settings.json`.
/// `None` for a path in none of the moved directories. The directory itself
/// is its default name alone, so removing it reads as removing `.claude`.
///
/// What stands before the directory is dropped, and nothing is lost by it:
/// every guard that names one of these directories matches it at any depth.
///
/// A name can be matched through a `..` it does not resolve (`segments`
/// keeps them, and `.termaxa/../x` is refused as if inside). A place cannot:
/// `/home/u/x/../.claude-work/settings.json` is that settings file, so the
/// path is also read with each `..` taken back, by its text alone.
pub(crate) fn under_default_name(seg: &[String]) -> Option<Vec<String>> {
    let dirs = moved_dirs();
    if dirs.is_empty() {
        return None;
    }
    let within = |seg: &[String]| {
        dirs.iter()
            .filter(|(dir, _)| seg.len() >= dir.len() && seg[..dir.len()] == dir[..])
            // The longest directory wins: one moved directory inside another
            // is read as the inner one.
            .max_by_key(|(dir, _)| dir.len())
            .map(|(dir, name)| {
                let mut renamed = vec![name.to_string()];
                renamed.extend_from_slice(&seg[dir.len()..]);
                renamed
            })
    };
    within(seg).or_else(|| {
        if !seg.iter().any(|s| s == "..") {
            return None;
        }
        let mut climbed: Vec<String> = Vec::new();
        for s in seg {
            if s == ".." {
                climbed.pop();
            } else {
                climbed.push(s.clone());
            }
        }
        within(&climbed)
    })
}

/// The same for a path the gate could read only the end of
/// (`delete::readable_end`): `"$HOME/.config/claude"/settings.json` ends in
/// `.config`, `claude`, `settings.json`, and with
/// `CLAUDE_CONFIG_DIR=/home/u/.config/claude` that end starts with the
/// directory's own last components, so it is read as `.claude`,
/// `settings.json`.
///
/// One component is enough: `${XDG_CONFIG_HOME:-$HOME/.config}/claude` ends
/// in `claude` alone. That is the reading a default name has always had
/// (whatever stands before `.claude/settings.json`, it is a settings file),
/// applied to a name that says less: an end that starts with `claude` under
/// some other directory is refused too, where a session has moved its
/// configuration to a directory called `claude`. The path written out in
/// full is not read this way.
pub(crate) fn end_under_default_name(end: &[String]) -> Option<Vec<String>> {
    let mut best: Option<(usize, &'static str)> = None;
    for (dir, name) in moved_dirs().iter() {
        let longest = (1..=dir.len().min(end.len()))
            .rev()
            .find(|k| end[..*k] == dir[dir.len() - k..]);
        if let Some(k) = longest {
            if best.is_none_or(|(b, _)| k > b) {
                best = Some((k, *name));
            }
        }
    }
    let (k, name) = best?;
    let mut renamed = vec![name.to_string()];
    renamed.extend_from_slice(&end[k..]);
    Some(renamed)
}

/// `command` with every moved directory spelled the way the string rules
/// were written to read it: `~/.claude`, `~/.codex`, `~/.termaxa`. `None`
/// when the command names none of them.
///
/// A string rule is a belt for the commands whose grammar the gate does not
/// model (`truncate`, an editor, `python -c`): `*.claude*settings*` refuses a
/// line that names the directory and then the file. A moved directory has
/// no `.claude` in its name, so the belt is given the line as it would read
/// under the default one (`Policy::evaluate`, for deny rules only). Read as
/// that directory:
///
/// - the variable, by its name, set or not: `$CLAUDE_CONFIG_DIR`,
///   `${CODEX_HOME:-…}`, `%TERMAXA_HOME%`, `$env:CODEX_HOME`, and the bare
///   word (`os.environ['CLAUDE_CONFIG_DIR']`);
/// - the directory's path written out, where the variable is set, after a
///   character that does not continue a path;
/// - the same path through `~`, or through any variable this process has an
///   absolute value for that the directory lies under (`$HOME/.config/claude`,
///   `%USERPROFILE%\\cfg\\claude`).
///
/// Compared without case and with either separator, quotes stepped over
/// (`"$HOME"/.config/claude`), and only where the next character does not
/// continue the last component (`~/.config/claude-old` is another
/// directory). A path that reaches the directory any other way (relative,
/// through a variable this process cannot see) is read by the path rules
/// where the gate can read the command's targets, and not here.
pub(crate) fn spelled_by_default(command: &str) -> Option<String> {
    let plain = |text: &str| -> String {
        text.trim()
            .chars()
            .map(|c| {
                if c == '\\' {
                    '/'
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect::<String>()
            .trim_end_matches('/')
            .to_string()
    };
    let names: Vec<(String, &'static str)> = MOVED
        .iter()
        .map(|(v, name)| (v.to_ascii_lowercase(), *name))
        .collect();
    let mut moved: Vec<(String, &'static str)> = Vec::new();
    for (variable, name) in MOVED {
        let Some(dir) = moved_to(variable) else {
            continue;
        };
        let text = plain(&dir.to_string_lossy());
        if text.is_empty() {
            continue;
        }
        // Git Bash spells `C:\Users\x` as `/c/Users/x`.
        let b = text.as_bytes();
        if b.len() >= 3 && b[1] == b':' && b[2] == b'/' && b[0].is_ascii_alphabetic() {
            moved.push((format!("/{}{}", &text[..1], &text[2..]), name));
        }
        moved.push((text, name));
    }
    let lower = command.to_ascii_lowercase();
    if moved.is_empty() && !names.iter().any(|(v, _)| lower.contains(v.as_str())) {
        return None;
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()
        .map(|h| plain(&h))
        .filter(|h| is_absolute(h));
    let chars: Vec<char> = command.chars().collect();
    let read: Vec<char> = chars
        .iter()
        .map(|c| {
            if *c == '\\' {
                '/'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let continues = |c: char| is_name(c) || matches!(c, '.' | '-');
    // How much of `text` spells the rest of a moved directory that begins
    // with `start`, and which directory: the longest such.
    let rest_of = |start: &str, text: &[char]| -> Option<(usize, &'static str)> {
        let mut best: Option<(usize, &'static str)> = None;
        for (dir, name) in &moved {
            let Some(rest) = dir.strip_prefix(start) else {
                continue;
            };
            if !(start.is_empty() || rest.is_empty() || rest.starts_with('/')) {
                continue;
            }
            // A quote between a variable and what follows it is stepped
            // over; a path written out starts at its own first character.
            let mut at = 0;
            let spelled = rest.chars().all(|want| {
                while (at > 0 || !start.is_empty())
                    && matches!(text.get(at), Some('"') | Some('\''))
                {
                    at += 1;
                }
                let same = text.get(at) == Some(&want);
                at += 1;
                same
            });
            if spelled
                && text.get(at).is_none_or(|c| !continues(*c))
                && best.is_none_or(|(b, _)| at > b)
            {
                best = Some((at, name));
            }
        }
        best
    };
    let mut out = String::with_capacity(command.len());
    let mut changed = false;
    let mut i = 0;
    while i < chars.len() {
        let before = i.checked_sub(1).map(|p| read[p]);
        let starts_a_path = before.is_none_or(|c| !(continues(c) || c == '/' || c == '~'));
        let mut found: Option<(usize, &'static str)> = None;
        if let Some((name, after)) = variable_at(&chars, i) {
            if let Some((_, default)) = names.iter().find(|(v, _)| v.eq_ignore_ascii_case(&name)) {
                found = Some((after, default));
            } else if let Some(value) = std::env::var(&name)
                .ok()
                .map(|v| plain(&v))
                .filter(|v| is_absolute(v) || v.is_empty())
            {
                found = rest_of(&value, &read[after..]).map(|(len, d)| (after + len, d));
            }
        }
        if found.is_none() && chars[i] == '~' && starts_a_path {
            if let Some(home) = &home {
                found = rest_of(home, &read[i + 1..]).map(|(len, d)| (i + 1 + len, d));
            }
        }
        if found.is_none() && starts_a_path {
            found = rest_of("", &read[i..]).map(|(len, d)| (i + len, d));
        }
        if found.is_none() && before.is_none_or(|c| !is_name(c)) {
            found = names.iter().find_map(|(v, default)| {
                let end = i + v.len();
                (read.len() >= end
                    && read[i..end].iter().copied().eq(v.chars())
                    && read.get(end).is_none_or(|c| !is_name(*c)))
                .then_some((end, *default))
            });
        }
        match found {
            Some((end, default)) => {
                out.push_str("~/");
                out.push_str(default);
                changed = true;
                i = end;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    changed.then_some(out)
}

fn classify_segments(seg: &[String]) -> Option<Protected> {
    classify_named(seg).or_else(|| classify_named(&under_default_name(seg)?))
}

fn classify_named(seg: &[String]) -> Option<Protected> {
    if seg.iter().any(|s| s == ".termaxa") {
        return Some(POLICY_AND_RECORD);
    }

    let file = seg.last()?.as_str();
    let parent = seg.get(seg.len().checked_sub(2)?)?.as_str();

    // Claude Code reads `settings.json` and `settings.local.json` from
    // `.claude/`, in the project and in the home directory. The hook lives in
    // whichever one is present, so both are the control plane. Anything else
    // under `.claude/` (skills, agents, commands) is ordinary project content
    // and stays out of this.
    if parent == ".claude" && file.starts_with("settings") && file.ends_with(".json") {
        return Some(HOOK_CONFIG);
    }

    // Claude Code keeps what it installs from a marketplace under
    // `.claude/plugins/`: the registry of installed plugins, the
    // marketplaces it knows and its copy of each, and a copy of each plugin,
    // its `hooks/hooks.json` included. A plugin is enabled in a settings
    // file, which the rule above already holds; whether it is installed,
    // and what its hooks run, is decided here. So the directory and
    // everything in it, whichever plugin a file belongs to: any plugin's
    // hooks run as the session does, and one rewritten could undo this one.
    if seg
        .windows(2)
        .any(|w| w[0] == ".claude" && w[1] == "plugins")
    {
        return Some(PLUGINS);
    }

    if (parent == ".cursor" || parent == ".codex") && file == "hooks.json" {
        return Some(HOOK_CONFIG);
    }

    // Copilot CLI: `.github/hooks/hooks.json`. The `.github` check is what
    // keeps an ordinary `hooks/hooks.json` in someone's own tree out of it.
    if parent == "hooks" && file == "hooks.json" {
        let grandparent = seg.get(seg.len().checked_sub(3)?)?.as_str();
        if grandparent == ".github" {
            return Some(HOOK_CONFIG);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn what(cwd: &str, path: &str) -> Option<&'static str> {
        classify(cwd, path).map(|p| p.what)
    }

    #[test]
    fn policy_overwrite_is_refused_on_both_separators() {
        assert_eq!(
            what("/repo", "/repo/.termaxa/policy.yaml"),
            Some("termaxa-state")
        );
        assert_eq!(
            what("C:\\repo", "C:\\repo\\.termaxa\\policy.yaml"),
            Some("termaxa-state")
        );
    }

    #[test]
    fn audit_log_under_termaxa_home_is_refused() {
        // The record is the asset with the highest value and it lives outside
        // the repo, so the check has to reach it by segment rather than by
        // project-relative path.
        assert_eq!(
            what(
                "/repo",
                "/home/user/.termaxa/projects/abc123/logs/audit.jsonl"
            ),
            Some("termaxa-state")
        );
    }

    #[test]
    fn claude_settings_both_spellings_are_refused() {
        assert_eq!(
            what("/repo", "/repo/.claude/settings.json"),
            Some("agent-hook-config")
        );
        assert_eq!(
            what("/repo", "/repo/.claude/settings.local.json"),
            Some("agent-hook-config")
        );
        // doctor only inspects the project copy, but the hook is just as
        // disabled by rewriting the one in $HOME.
        assert_eq!(
            what("/repo", "/home/user/.claude/settings.json"),
            Some("agent-hook-config")
        );
    }

    #[test]
    fn every_dialects_hook_file_is_refused() {
        for path in [
            "/repo/.cursor/hooks.json",
            "/repo/.codex/hooks.json",
            "/repo/.github/hooks/hooks.json",
        ] {
            assert_eq!(what("/repo", path), Some("agent-hook-config"), "{}", path);
        }
    }

    /// Where Claude Code 2.1.327 put a plugin installed from a marketplace,
    /// read from an install into a configuration directory of its own: the
    /// registry, the marketplaces it knows, the marketplace's clone and the
    /// plugin's copy, whose `hooks/hooks.json` is what runs.
    #[test]
    fn claude_codes_plugin_files_are_hook_configuration() {
        for path in [
            "/home/u/.claude/plugins/installed_plugins.json",
            "/home/u/.claude/plugins/known_marketplaces.json",
            "/home/u/.claude/plugins/cache/termaxa/termaxa/0.1.0/hooks/hooks.json",
            "/home/u/.claude/plugins/cache/termaxa/termaxa/0.1.0/.claude-plugin/plugin.json",
            "/home/u/.claude/plugins/cache/other/formatter/1.2.0/hooks/format.sh",
            "/home/u/.claude/plugins/marketplaces/termaxa/claude-code-plugin/hooks/hooks.json",
            "/home/u/.claude/plugins/marketplaces/termaxa/.claude-plugin/marketplace.json",
            "/home/u/.claude/plugins/data/termaxa-termaxa/state.json",
            "/home/u/.claude/plugins",
            "C:\\Users\\Dev\\.claude\\plugins\\installed_plugins.json",
            "C:\\Users\\Dev\\.Claude\\Plugins\\cache\\termaxa\\termaxa\\0.1.0\\hooks\\hooks.json",
        ] {
            let p = classify("/repo", path).unwrap_or_else(|| panic!("{path}: not protected"));
            assert_eq!(p.what, "agent-hook-config", "{path}");
            assert!(p.reason.contains("plugin"), "{path}: {}", p.reason);
        }
        // Relative to the payload's directory, as every other guarded path.
        assert_eq!(
            what("/home/u/.claude", "plugins/installed_plugins.json"),
            Some("agent-hook-config")
        );
        // A plugin's own source, wherever it is kept, is not the installed
        // copy, and `.claude` beside a `plugins` directory is not this one.
        for path in [
            "/repo/claude-code-plugin/hooks/hooks.json",
            "/repo/.claude-plugin/marketplace.json",
            "/repo/plugins/termaxa/hooks/hooks.json",
            "/repo/.claude/skills/plugins/SKILL.md",
            "/home/u/.claude-plugins/installed_plugins.json",
        ] {
            assert_eq!(what("/repo", path), None, "{path}");
        }
    }

    /// With `CLAUDE_CONFIG_DIR` moving Claude Code's directory, its plugins
    /// move with it, and are read under the default name.
    #[test]
    fn plugin_files_in_a_moved_claude_directory_are_hook_configuration() {
        let mut env = crate::testutil::TestEnv::new("protect-moved-plugins");
        env.set_var("CLAUDE_CONFIG_DIR", "/tmx-moved/u/.config/claude");
        assert_eq!(
            what(
                "/repo",
                "/tmx-moved/u/.config/claude/plugins/installed_plugins.json"
            ),
            Some("agent-hook-config")
        );
        assert_eq!(
            what(
                "/repo",
                "/tmx-moved/u/.config/claude/plugins/cache/termaxa/termaxa/0.1.0/hooks/hooks.json"
            ),
            Some("agent-hook-config")
        );
        assert_eq!(
            what("/repo", "/tmx-moved/u/.config/other/plugins/x.json"),
            None
        );
    }

    #[test]
    fn relative_path_is_resolved_against_the_payload_cwd() {
        // Claude Code sends absolute paths. A dialect that does not must not
        // read as an unrecognised path.
        assert_eq!(what("/repo", ".termaxa/policy.yaml"), Some("termaxa-state"));
        assert_eq!(what("/repo/.termaxa", "policy.yaml"), Some("termaxa-state"));
    }

    #[test]
    fn ordinary_project_files_get_no_decision() {
        for path in [
            "/repo/src/main.rs",
            "/repo/termaxa-notes.md",
            "/repo/docs/termaxa/README.md",
            "/repo/.claude/skills/review/SKILL.md",
            "/repo/.claude/agents/reviewer.md",
            "/repo/.github/workflows/ci.yml",
            "/repo/hooks/hooks.json",
            "/repo/.termaxarc",
        ] {
            assert_eq!(what("/repo", path), None, "{}", path);
        }
    }

    #[test]
    fn segment_match_does_not_fire_on_a_substring() {
        // `*termaxa*` as a substring would refuse all of these. Segments do not.
        assert_eq!(what("/repo", "/repo/my-termaxa-fork/policy.yaml"), None);
        assert_eq!(what("/repo", "/repo/.termaxa-old/policy.yaml"), None);
    }

    #[test]
    fn case_is_ignored_so_a_respelling_does_not_slip_through() {
        assert_eq!(
            what("/repo", "/repo/.TERMAXA/policy.yaml"),
            Some("termaxa-state")
        );
        assert_eq!(
            what("/repo", "/repo/.Claude/Settings.json"),
            Some("agent-hook-config")
        );
    }

    #[test]
    fn traversal_through_a_protected_directory_is_refused() {
        // Documented over-refusal: `..` is not resolved, so this reads as
        // inside. Refusing too much here is the safe direction.
        assert_eq!(
            what("/repo", "/repo/.termaxa/../notes.md"),
            Some("termaxa-state")
        );
    }

    #[test]
    fn a_bare_filename_with_no_directory_is_not_protected() {
        assert_eq!(what("", "policy.yaml"), None);
        assert_eq!(what("", "settings.json"), None);
    }

    #[test]
    fn an_absolute_path_is_never_resolved_against_the_cwd() {
        // The cwd here is itself protected, so joining it onto an absolute
        // path would refuse a file that has nothing to do with the gate.
        assert_eq!(what("/repo/.termaxa", "/other/notes.md"), None);
        assert_eq!(what("C:\\repo\\.termaxa", "\\other\\notes.md"), None);
        // A drive letter makes a path absolute just as a leading separator does.
        assert_eq!(what("C:\\repo\\.termaxa", "D:\\other\\notes.md"), None);
    }

    #[test]
    fn separator_noise_does_not_shift_the_parent_directory() {
        // `.` and empty segments are dropped, or `.claude/./settings.json`
        // reads as a file whose parent is `.` and walks straight through.
        assert_eq!(
            what("/repo", "/repo/.claude/./settings.json"),
            Some("agent-hook-config")
        );
        assert_eq!(
            what("/repo", "/repo/.claude//settings.json"),
            Some("agent-hook-config")
        );
    }

    #[test]
    fn only_settings_json_under_dot_claude_is_control_plane() {
        // Both halves of the filename test matter, and so does the directory:
        // widen any one of them and ordinary project files start being refused.
        assert_eq!(what("/repo", "/repo/config/settings.json"), None);
        assert_eq!(what("/repo", "/repo/.claude/mcp.json"), None);
        assert_eq!(what("/repo", "/repo/.claude/settings.yaml"), None);
    }

    #[test]
    fn the_github_dialect_only_claims_its_own_hooks_file() {
        // `.github/hooks/` is not wholesale off limits — one filename in it is.
        assert_eq!(what("/repo", "/repo/.github/hooks/config.json"), None);
        assert_eq!(
            what("/repo", "/repo/.github/hooks/hooks.json"),
            Some("agent-hook-config")
        );
    }

    /// Three of the directories this module knows by name can be given
    /// another: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, and the gate's own
    /// `TERMAXA_HOME`. Until v0.22.0 a settings file in `~/.claude-work`,
    /// or the record under a state directory with a name of its own, was a
    /// path nothing here recognised, and a file tool wrote it with no
    /// answer. A path inside a directory one of those variables names is
    /// read under the directory's default name.
    #[test]
    fn a_directory_its_tool_has_moved_is_guarded_as_under_its_default_name() {
        let mut env = crate::testutil::TestEnv::new("protect-moved");
        let claude = env.root().join("profiles").join("claude-work");
        let codex = env.root().join("cfg").join("codex");
        let at = |p: std::path::PathBuf| what("/repo", &p.display().to_string());

        // Not moved: these are paths like any other. (`TERMAXA_HOME` is,
        // by the guard itself, and the state under it is the gate's.)
        assert_eq!(at(claude.join("settings.json")), None);
        assert_eq!(at(codex.join("hooks.json")), None);
        assert_eq!(
            at(env
                .home()
                .join("projects")
                .join("abc")
                .join("logs")
                .join("audit.jsonl")),
            Some("termaxa-state")
        );
        assert_eq!(
            at(env.home()),
            Some("termaxa-state"),
            "the directory itself"
        );
        assert_eq!(
            at(env.root().join("home-old").join("projects")),
            None,
            "a directory beside it, by segments and not by its spelling"
        );

        env.set_var("CLAUDE_CONFIG_DIR", &claude);
        env.set_var("CODEX_HOME", &codex);
        assert_eq!(at(claude.join("settings.json")), Some("agent-hook-config"));
        assert_eq!(
            at(claude.join("settings.local.json")),
            Some("agent-hook-config")
        );
        assert_eq!(at(codex.join("hooks.json")), Some("agent-hook-config"));
        // What is ordinary content under the default name stays ordinary.
        assert_eq!(
            at(claude.join("skills").join("deploy").join("SKILL.md")),
            None
        );
        assert_eq!(at(claude.join("sub").join("settings.json")), None);
        assert_eq!(at(codex.join("config.toml")), None);
        assert_eq!(
            at(env
                .root()
                .join("profiles")
                .join("claude-work-old")
                .join("settings.json")),
            None
        );
        // The default names are guarded as they were.
        assert_eq!(
            what("/repo", "/home/u/.claude/settings.json"),
            Some("agent-hook-config")
        );

        // Windows' spelling of both, and a letter's case.
        env.set_var("CLAUDE_CONFIG_DIR", "C:\\Users\\Dev\\cfg\\claude");
        assert_eq!(
            what("C:\\repo", "c:/users/dev/CFG/claude/settings.json"),
            Some("agent-hook-config")
        );
        // A value that is not absolute is taken from the directory the
        // hook runs in, as the harness took it from its own.
        let proj = env.root().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        env.chdir(&proj);
        env.set_var("CLAUDE_CONFIG_DIR", ".claude-custom");
        assert_eq!(
            at(std::env::current_dir()
                .unwrap()
                .join(".claude-custom")
                .join("settings.json")),
            Some("agent-hook-config")
        );
        // An empty value is no directory.
        env.set_var("CLAUDE_CONFIG_DIR", "");
        assert_eq!(at(claude.join("settings.json")), None);
    }

    /// The variable's own name is the directory, wherever it points
    /// (`moved_name`), and where this process has a value for it a path
    /// that starts with it is that directory (`expand_moved`).
    #[test]
    fn a_path_spelled_with_the_variable_is_read_with_its_value() {
        let mut env = crate::testutil::TestEnv::new("protect-moved-spelled");
        assert_eq!(moved_name("CLAUDE_CONFIG_DIR"), Some(".claude"));
        assert_eq!(moved_name("codex_home"), Some(".codex"));
        assert_eq!(moved_name("TERMAXA_HOME"), Some(".termaxa"));
        assert_eq!(moved_name("HOME"), None);

        env.set_var("CLAUDE_CONFIG_DIR", "/tmx-moved/cfg/claude");
        env.set_var("CODEX_HOME", "/tmx-moved/cfg/codex");
        let to = |raw: &str| expand_moved(raw).map(|p| p.replace('\\', "/"));
        for raw in [
            "$CLAUDE_CONFIG_DIR/settings.json",
            "${CLAUDE_CONFIG_DIR}/settings.json",
            "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json",
            "%CLAUDE_CONFIG_DIR%/settings.json",
            "$env:CLAUDE_CONFIG_DIR/settings.json",
        ] {
            assert_eq!(
                to(raw).as_deref(),
                Some("/tmx-moved/cfg/claude/settings.json"),
                "{raw}"
            );
        }
        assert_eq!(to("$CODEX_HOME").as_deref(), Some("/tmx-moved/cfg/codex"));
        assert_eq!(
            to("%CODEX_HOME%\\hooks.json").as_deref(),
            Some("/tmx-moved/cfg/codex/hooks.json")
        );
        // Not the variable: a longer name, a name inside a word, another one.
        for raw in [
            "$CLAUDE_CONFIG_DIRX/settings.json",
            "$CLAUDE_CONFIG_DIR.bak/settings.json",
            "x$CLAUDE_CONFIG_DIR/settings.json",
            "$HOME/.claude/settings.json",
            "settings.json",
        ] {
            assert_eq!(to(raw), None, "{raw}");
        }
        // Unset, there is no value to put in: the path keeps its name.
        env.set_var("CODEX_HOME", "");
        assert_eq!(to("$CODEX_HOME/hooks.json"), None);
    }

    /// A place, unlike a name, can be reached through a `..`: the path is
    /// read with each one taken back as well.
    #[test]
    fn a_moved_directory_is_found_through_a_dotdot() {
        let mut env = crate::testutil::TestEnv::new("protect-moved-dotdot");
        env.set_var("CLAUDE_CONFIG_DIR", "/tmx-moved/cfg/claude");
        assert_eq!(
            what("/repo", "/tmx-moved/cfg/other/../claude/settings.json"),
            Some("agent-hook-config")
        );
        assert_eq!(
            what("/tmx-moved/cfg/other", "../claude/settings.json"),
            Some("agent-hook-config")
        );
        assert_eq!(
            what("/repo", "/tmx-moved/cfg/claude/../settings.json"),
            None
        );
        // One moved directory inside another is the inner one.
        env.set_var("CODEX_HOME", "/tmx-moved/cfg/claude/codex");
        assert_eq!(
            what("/repo", "/tmx-moved/cfg/claude/codex/hooks.json"),
            Some("agent-hook-config")
        );
        assert_eq!(
            what("/repo", "/tmx-moved/cfg/claude/codex/settings.json"),
            None
        );
    }

    /// A path the gate reads only the end of is inside a moved directory
    /// when its end starts with the directory's own last components.
    #[test]
    fn an_end_that_starts_with_the_directorys_last_components_is_inside_it() {
        let mut env = crate::testutil::TestEnv::new("protect-moved-end");
        let v = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // `TestEnv` has moved the gate's own state to `<root>/home`.
        assert_eq!(
            end_under_default_name(&v(&["home", "projects", "k"])),
            Some(v(&[".termaxa", "projects", "k"]))
        );
        assert_eq!(end_under_default_name(&v(&["settings.json"])), None);
        env.set_var("CLAUDE_CONFIG_DIR", "/tmx-moved/u/.config/claude");
        for (end, want) in [
            // `"$HOME/.config/claude"/settings.json`
            (
                v(&[".config", "claude", "settings.json"]),
                Some(v(&[".claude", "settings.json"])),
            ),
            // `${XDG_CONFIG_HOME:-$HOME/.config}/claude/settings.json`
            (
                v(&["claude", "settings.json"]),
                Some(v(&[".claude", "settings.json"])),
            ),
            // `/home/$USER/.config/claude`, the directory itself
            (v(&["u", ".config", "claude"]), Some(v(&[".claude"]))),
            // Another directory's `settings.json`, and a longer name.
            (v(&[".config", "other", "settings.json"]), None),
            (v(&["claude-old", "settings.json"]), None),
            (v(&[".config"]), None),
        ] {
            assert_eq!(end_under_default_name(&end), want, "{end:?}");
        }
    }

    /// The string rules name a directory by its default name, so a command
    /// that names a moved one is read for them as it would be spelled under
    /// that name.
    #[test]
    fn a_command_is_respelled_with_the_default_names() {
        let mut env = crate::testutil::TestEnv::new("protect-moved-spelling");
        env.set_var("CLAUDE_CONFIG_DIR", "/tmx-moved/u/.config/claude");
        env.set_var("CODEX_HOME", "C:\\Users\\Dev\\cfg\\codex");
        // A variable of this test's own, for a directory the moved one
        // lies under: `$HOME` and `$XDG_CONFIG_HOME` are other tests' too.
        env.set_var("TERMAXA_TEST_CONFIG_ROOT", "/tmx-moved/u/.config");
        for (command, want) in [
            // By its variable, set or not, however it is dressed.
            (
                "truncate -s 0 $CLAUDE_CONFIG_DIR/settings.json",
                "truncate -s 0 ~/.claude/settings.json",
            ),
            (
                "truncate -s 0 \"${CLAUDE_CONFIG_DIR:-$HOME/.claude}\"/settings.json",
                "truncate -s 0 \"~/.claude\"/settings.json",
            ),
            ("del %CODEX_HOME%\\hooks.json", "del ~/.codex\\hooks.json"),
            (
                "Remove-Item $env:TERMAXA_HOME\\projects -Recurse",
                "Remove-Item ~/.termaxa\\projects -Recurse",
            ),
            (
                "python3 -c \"open(os.environ['CLAUDE_CONFIG_DIR']+'/settings.json','w')\"",
                "python3 -c \"open(os.environ['~/.claude']+'/settings.json','w')\"",
            ),
            // By its path, written out.
            (
                "python3 -c \"open('/tmx-moved/u/.config/claude/settings.json','w')\"",
                "python3 -c \"open('~/.claude/settings.json','w')\"",
            ),
            (
                "chmod 000 c:/users/dev/CFG/codex/hooks.json",
                "chmod 000 ~/.codex/hooks.json",
            ),
            (
                "chmod 000 /c/Users/Dev/cfg/codex/hooks.json",
                "chmod 000 ~/.codex/hooks.json",
            ),
            (
                "dd of=/tmx-moved/u/.config/claude/settings.json",
                "dd of=~/.claude/settings.json",
            ),
            // Through a variable this process has a value for, with the
            // quote that closes it stepped over.
            (
                "touch ${TERMAXA_TEST_CONFIG_ROOT}/claude/settings.json",
                "touch ~/.claude/settings.json",
            ),
            (
                "touch \"$TERMAXA_TEST_CONFIG_ROOT\"/claude/settings.json",
                "touch \"~/.claude/settings.json",
            ),
            (
                "touch %TERMAXA_TEST_CONFIG_ROOT%\\claude\\settings.json",
                "touch ~/.claude\\settings.json",
            ),
        ] {
            assert_eq!(
                spelled_by_default(command).as_deref(),
                Some(want),
                "{command}"
            );
        }
        // Another directory, a longer name, a path that only contains it.
        for command in [
            "touch /tmx-moved/u/.config/claude-old/settings.json",
            "touch /tmx-moved/u/.config/claude.d/settings.json",
            "touch /mnt/tmx-moved/u/.config/claude/settings.json",
            "touch $TERMAXA_TEST_CONFIG_ROOT/other/settings.json",
            "echo $CLAUDE_CONFIG_DIRX $MY_CLAUDE_CONFIG_DIR",
            "ls -la",
        ] {
            assert_eq!(spelled_by_default(command), None, "{command}");
        }
        // Through `~`: this process's own home, wherever that is.
        if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
            let under_home = std::path::PathBuf::from(&home).join("tmx-moved-claude");
            env.set_var("CLAUDE_CONFIG_DIR", &under_home);
            assert_eq!(
                spelled_by_default("touch ~/tmx-moved-claude/settings.json").as_deref(),
                Some("touch ~/.claude/settings.json")
            );
            assert_eq!(
                spelled_by_default("touch ~/tmx-moved-claude-2/settings.json"),
                None
            );
            assert_eq!(spelled_by_default("touch a~/tmx-moved-claude/x"), None);
        }
    }
}
