//! The rules a watched project's own record proposes, for `termaxa init`
//! (decision #149, Nov 13, 2026).
//!
//! A plugin's hook watches a project that has no policy (#147): the built-in
//! starter judges every command, asks nothing and keeps the record of what it
//! would have asked. That record is the evidence a project's own rules come
//! from. The SynCircles record showed what they are worth: eleven project
//! rules, written by hand from 123 commands, took 23 asks off the record (86
//! to 63, measured on the released 0.21.8). So `init`, run where a plugin's
//! hook has been watching, proposes them, under these terms:
//!
//!   * Only what asked because nothing decided it: the policy's default. An
//!     ask a rule chose (`git push*`, `curl*`) is somebody's decision and is
//!     not proposed away, and a refusal is not an ask.
//!   * Grouped by the words that name the action, as they were typed: `npm
//!     run build`, `npx prisma generate`, `python3 manage.py migrate`,
//!     `supabase migration new`, `mkdir`. Never by a runner's wildcard (#83):
//!     `npx *`, `npm run *` and `python3 *` run whatever they are handed, so
//!     a runner is proposed with the script, package or module it ran, or
//!     not at all.
//!   * Not what the gate reads as removing, overwriting or discarding a
//!     file: that ask is where the preview shows what the command loses.
//!     Nor an action whose own words delete, drop, reset or destroy, an
//!     install of a package named on the line, anything run as another
//!     user, or what asked once.
//!   * Shown with its count, the commands as typed and the rule, for a
//!     person at a terminal to accept or drop. With nobody at a terminal
//!     (an agent running `init`, a script), every proposal is written as a
//!     comment, which does nothing until a person takes the `#` off. Nothing
//!     is written that was not shown (#34), and nothing an agent can switch
//!     on by running `init`.
//!   * Written below every rule of the policy, so it decides only what
//!     nothing above it decides: the floor, and every deny and ask the
//!     starter has, keep their places and their precedence (first match
//!     wins).

use crate::audit::AuditEntry;
use crate::policy::{Action, DecisionSource, Policy};
use crate::resolve::{EvalContext, TargetRole};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// What follows the last rule of the starter `init` writes. Accepted rules
/// go in front of it, at the end of the `rules:` list.
const RULES_END: &str = "\n# Session circuit breaker";

/// A proposal needs this many asks: one command is a single instance, not a
/// habit of the project's, and the person can still write its rule by hand.
const MIN_ASKS: usize = 2;

/// The record a plugin's hook kept while it watched a project with no policy.
pub struct Watched {
    /// The first and the last watched line's time, as recorded (UTC).
    pub first: String,
    pub last: String,
    /// Lines the hook judged before a call ran, while watching.
    pub lines: usize,
    /// Of those, the ones that would have asked, and the ones refused.
    pub asked: usize,
    pub refused: usize,
    asks: Vec<AuditEntry>,
}

impl Watched {
    /// The watch record of the project `init` runs in, if a plugin's hook
    /// kept one (`paths::watched_record`). Nothing is created.
    pub fn read(dir: &Path) -> Option<Watched> {
        let paths = crate::paths::watched_record(dir)?;
        let raw = std::fs::read_to_string(paths.log_file()).ok()?;
        Self::from_lines(&raw)
    }

    /// The watched lines of a record, one JSON object to a line. A line the
    /// record holds for another reason (a policy's own verdict, a receipt
    /// after a call) is not part of it.
    pub fn from_lines(raw: &str) -> Option<Watched> {
        let mut w = Watched {
            first: String::new(),
            last: String::new(),
            lines: 0,
            asked: 0,
            refused: 0,
            asks: Vec::new(),
        };
        for line in raw.lines() {
            let Ok(e) = serde_json::from_str::<AuditEntry>(line) else {
                continue;
            };
            if e.mode.as_deref() != Some("watch") || e.source != "hook" {
                continue;
            }
            if w.lines == 0 {
                w.first = e.ts.clone();
            }
            w.last = e.ts.clone();
            w.lines += 1;
            match e.decision.as_str() {
                "ask" => {
                    w.asked += 1;
                    w.asks.push(e);
                }
                "deny" => w.refused += 1,
                _ => {}
            }
        }
        (w.lines > 0).then_some(w)
    }
}

/// One rule set a person can accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The words that name the action, as typed: `npm run build`.
    pub action: String,
    /// The `match:` patterns that allow it: the action alone where it was
    /// typed alone, and followed by anything where it was typed with more.
    pub rules: Vec<String>,
    /// How many commands asked with this action.
    pub asked: usize,
    /// Of those, how many the rules allow, judged again with the rules in
    /// place. Fewer than `asked` where something else on a command asks (a
    /// production marker, a substitution).
    pub allowed: usize,
    /// Up to three of the commands, as typed.
    pub examples: Vec<String>,
}

/// Why a command that asked is not proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Left {
    /// The gate reads it as removing, overwriting or discarding a file.
    Changes,
    /// Its own words say it deletes, drops, resets or destroys something:
    /// `gh repo delete`, `npm run db:reset`, `kubectl delete`.
    Destroys,
    /// It installs a package named on the line, and what an install runs is
    /// that package's code: `npm install left-pad`, `pip install x`. From
    /// the project's own lockfile (`npm ci`, `npm install` alone) it does not.
    Installs,
    /// It runs as another user.
    Privileged,
    /// No rule can name what it runs without allowing everything its runner
    /// can run: code on the line (`python3 -c`, `node -e`), a database
    /// client's statements, a remote or a container's shell, a flag before
    /// the action of a tool that has several.
    Opaque,
    /// With the rule in place it would still ask: something else on it asks.
    StillAsks,
    /// It asked once.
    Once,
}

impl Left {
    pub fn says(self) -> &'static str {
        match self {
            Left::Changes => "removes, overwrites or discards files: the ask shows what it loses",
            Left::Destroys => "its own words say it deletes, drops, resets or destroys something",
            Left::Installs => {
                "installs a package named on the line: what runs is that package's code"
            }
            Left::Privileged => "runs as another user",
            Left::Opaque => "no rule can name what it runs without allowing everything it can run",
            Left::StillAsks => "would still ask with the rule: something else on it asks",
            Left::Once => "asked once",
        }
    }
}

/// Commands that asked and are not proposed, by reason and first word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotProposed {
    pub left: Left,
    /// The command's first word, or for `Once` its action.
    pub what: String,
    pub asked: usize,
    pub examples: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Proposals {
    pub proposed: Vec<Proposal>,
    pub not_proposed: Vec<NotProposed>,
}

/// Parse a policy the way `Policy::load` does, from text.
fn parse(text: &str) -> Result<Policy> {
    let policy: Policy =
        serde_yaml::from_str(text).context("the policy init writes did not parse")?;
    policy.validate()?;
    Ok(policy)
}

/// What the record proposes for a project whose policy is `policy_text`:
/// every command that asked by the policy's default, grouped by its action.
pub fn propose(watched: &Watched, policy_text: &str, root: &Path) -> Result<Proposals> {
    let policy = parse(policy_text)?;

    struct Group {
        action: Vec<String>,
        typed: Vec<(String, PathBuf)>,
        bare: bool,
        extended: bool,
    }
    let mut groups: Vec<Group> = Vec::new();
    let mut by_key: HashMap<String, usize> = HashMap::new();
    let mut left: Vec<NotProposed> = Vec::new();
    let mut note_left = |why: Left, what: String, typed: &str| match left
        .iter_mut()
        .find(|n| n.left == why && n.what == what)
    {
        Some(n) => {
            n.asked += 1;
            if n.examples.len() < 3 && !n.examples.iter().any(|x| x == typed) {
                n.examples.push(typed.to_string());
            }
        }
        None => left.push(NotProposed {
            left: why,
            what,
            asked: 1,
            examples: vec![typed.to_string()],
        }),
    };

    for e in &watched.asks {
        if is_native_write(&e.command) {
            continue;
        }
        let cwd = if e.cwd.trim().is_empty() {
            root.to_path_buf()
        } else {
            PathBuf::from(&e.cwd)
        };
        let ctx = EvalContext::new_for_preview(&cwd, root);
        for seg in crate::shell::split_segments_deep(&e.command) {
            if seg.wraps || seg.scaffold || seg.binds || seg.keyword {
                continue;
            }
            let typed = seg.command().trim().to_string();
            if typed.is_empty() {
                continue;
            }
            let d = policy.evaluate_command(&typed, &ctx);
            if d.action != Action::Ask || d.source != DecisionSource::Default {
                continue;
            }
            let tokens = crate::delete::tokenize_public(&typed);
            let first = tokens.first().cloned().unwrap_or_default();
            let named = if changes_files(&typed, &tokens, &ctx) {
                Err(Left::Changes)
            } else {
                action_head(&tokens)
            };
            let action = match named {
                Ok(action) => action,
                Err(why) => {
                    note_left(why, first, &typed);
                    continue;
                }
            };
            let key = action.join(" ").to_ascii_lowercase();
            let at = *by_key.entry(key).or_insert_with(|| {
                groups.push(Group {
                    action: action.clone(),
                    typed: Vec::new(),
                    bare: false,
                    extended: false,
                });
                groups.len() - 1
            });
            let g = &mut groups[at];
            let stepped = stepped_over(&tokens);
            if stepped.len() > g.action.len() {
                g.extended = true;
            } else {
                g.bare = true;
            }
            g.typed.push((typed, cwd.clone()));
        }
    }

    let mut out = Proposals::default();
    for g in groups {
        let action = g.action.join(" ");
        let mut examples: Vec<String> = Vec::new();
        for (t, _) in &g.typed {
            if examples.len() < 3 && !examples.contains(t) {
                examples.push(t.clone());
            }
        }
        if g.typed.len() < MIN_ASKS {
            out.not_proposed.push(NotProposed {
                left: Left::Once,
                what: action,
                asked: g.typed.len(),
                examples,
            });
            continue;
        }
        let mut rules = Vec::new();
        if g.bare {
            rules.push(action.clone());
        }
        if g.extended {
            rules.push(format!("{} *", action));
        }
        let with = with_rules(policy_text, &rule_lines(&rules, false))
            .and_then(|t| parse(&t).ok())
            .context("the policy with a proposed rule did not parse")?;
        let allowed = g
            .typed
            .iter()
            .filter(|(t, cwd)| {
                with.evaluate_command(t, &EvalContext::new_for_preview(cwd, root))
                    .action
                    == Action::Allow
            })
            .count();
        if allowed == 0 {
            out.not_proposed.push(NotProposed {
                left: Left::StillAsks,
                what: action,
                asked: g.typed.len(),
                examples,
            });
            continue;
        }
        out.proposed.push(Proposal {
            action,
            rules,
            asked: g.typed.len(),
            allowed,
            examples,
        });
    }
    out.proposed
        .sort_by(|a, b| b.asked.cmp(&a.asked).then_with(|| a.action.cmp(&b.action)));
    out.not_proposed.extend(left);
    out.not_proposed.sort_by(|a, b| {
        a.left
            .cmp(&b.left)
            .then_with(|| b.asked.cmp(&a.asked))
            .then_with(|| a.what.cmp(&b.what))
    });
    Ok(out)
}

/// A record line made by a write tool (`Write`, `Edit`, `apply_patch`), not
/// a shell: its command is the tool's name and the paths it wrote
/// (`hook::append_write_entry`). Such a line asked by a path rule, and its
/// first word is not a program.
fn is_native_write(command: &str) -> bool {
    let first = command.split_whitespace().next().unwrap_or("");
    let folded = first.to_ascii_lowercase();
    !first.contains(['-', '/', '\\', '.'])
        && crate::hook::WRITE_VERBS.iter().any(|v| folded.contains(v))
}

/// True when the gate reads `typed` as removing, overwriting or discarding
/// a file: a target it removes or writes over (`command_targets`, the same
/// reading the preview and the copy aside use), a destructive class
/// (`intent`), or a git command that puts files back as committed.
fn changes_files(typed: &str, tokens: &[String], ctx: &EvalContext) -> bool {
    let plain = stepped_over(tokens);
    let head = plain
        .first()
        .map(|h| crate::delete::command_head(h))
        .unwrap_or_default();
    if CHANGES.contains(&head.as_str()) || crate::intent::classify_command(typed).is_some() {
        return true;
    }
    if crate::resolve::command_targets(typed, ctx)
        .iter()
        .any(|t| t.role != TargetRole::Source && !is_device(&t.as_written))
    {
        return true;
    }
    head == "git" && crate::backup::git_discard_target(&plain, &ctx.cwd).is_some()
}

/// A redirect to a device writes no file anyone loses.
fn is_device(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.starts_with("/dev/") || p == "nul" || p == "$null" || p == "con"
}

/// The tokens with what an allow rule reads through taken off the front:
/// environment assignments and the unprivileged wrappers (`env`, `nohup`,
/// `timeout 120`), as `delete::without_unprivileged_wrappers` does for the
/// string rules. A rule names the command they run.
fn stepped_over(tokens: &[String]) -> Vec<String> {
    crate::delete::without_unprivileged_wrappers(tokens).unwrap_or_else(|| tokens.to_vec())
}

/// Programs that run as another user: a rule for what they run would allow
/// it with privilege, and the string rules do not read through them.
const PRIVILEGED: &[&str] = &["sudo", "doas", "su", "pkexec", "runas", "gsudo", "run0"];

/// Programs that run something no rule can name: statements, code, another
/// command line or another machine's shell. Never proposed (#83).
#[rustfmt::skip]
const OPAQUE: &[&str] = &[
    // a command line of their own
    "xargs", "parallel", "watch", "time", "exec", "eval", "source", ".", "setsid", "stdbuf",
    "strace", "script", "expect", "tmux", "screen", "nohup", "nice", "flock",
    // another machine, or a container
    "ssh", "mosh", "telnet",
    // statements given on the line or in a file
    "psql", "mysql", "mariadb", "sqlite3", "duckdb", "mongosh", "mongo", "redis-cli", "cqlsh",
    "clickhouse-client", "sqlcmd", "osql", "bq",
    // a program given on the line
    "awk", "gawk", "mawk", "nawk", "jshell", "irb",
];

/// Shells: the script they run names the action; `-c` and a bare shell do
/// not, and a `-c` string is judged as segments of its own anyway.
#[rustfmt::skip]
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "cmd",
];

/// Interpreters: the script or module they run names the action; code on
/// the line does not.
fn is_interpreter(head: &str) -> bool {
    let python = head
        .strip_prefix("python")
        .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    python
        || matches!(
            head,
            "py" | "pypy"
                | "pypy3"
                | "node"
                | "nodejs"
                | "ruby"
                | "perl"
                | "php"
                | "rscript"
                | "lua"
                | "julia"
                | "tsx"
                | "ts-node"
                | "elixir"
                | "dart"
        )
}

/// Programs that do one thing: flags and operands follow, no subcommand.
/// The program's name is the action.
#[rustfmt::skip]
const SINGLE: &[&str] = &[
    "mkdir", "touch", "ps", "kill", "pkill", "killall", "sleep", "tail", "head", "cat", "less",
    "more", "sort", "uniq", "tr", "grep", "egrep", "fgrep", "rg", "ag", "ack", "fd", "ls",
    "tree", "echo", "printf", "curl", "jq", "base64", "md5sum", "sha1sum", "sha256sum",
    "shasum", "diff", "cmp", "file", "stat", "du", "df", "free", "top", "htop", "lsof",
    "netstat", "ss", "ping", "dig", "nslookup", "host", "whoami", "hostname", "uptime",
    "basename", "dirname", "realpath", "readlink", "date", "cal", "seq", "wc", "nl", "cut",
    "paste", "join", "comm", "column", "rev", "od", "hexdump", "xxd", "strings", "open",
    "xdg-open", "code", "cursor", "find", "printenv", "id", "uname", "which", "whereis",
    "type", "nproc", "pbcopy", "pbpaste", "clip", "lsblk", "envsubst",
    // the dev loop's own tools, as a runner hands them operands: `npx eslint
    // src` is eslint on `src`, not an action called `src`
    "eslint", "prettier", "tsc", "jest", "vitest", "mocha", "ava", "pytest", "ruff", "black",
    "isort", "flake8", "pylint", "mypy", "pyright", "shellcheck", "hadolint", "stylelint",
    "biome", "oxlint", "esbuild", "rollup", "webpack", "c8", "nyc",
];

/// Programs whose work is changing files through operands or options the
/// gate does not read as targets everywhere: an archive unpacked over the
/// project, permissions, a link, an edit in place. They are not proposed,
/// whatever this record's commands did, because a rule for them covers
/// every way they are used: `sed *` is also `sed -i`, `tar *` also `tar
/// -xf`. They ask, and the ask is where a person sees which one it is.
#[rustfmt::skip]
const CHANGES: &[&str] = &[
    "rm", "rmdir", "unlink", "shred", "truncate", "dd", "mv", "cp", "ln", "install", "rsync",
    "scp", "tar", "unzip", "7z", "gzip", "gunzip", "bzip2", "xz", "zip", "chmod", "chown",
    "chgrp", "chattr", "setfacl", "icacls", "attrib", "patch", "sed", "gsed", "tee", "wget",
    "yq", "del", "erase", "rd", "move", "copy", "xcopy", "robocopy", "ren", "rename",
    "remove-item", "ri", "move-item", "mi", "copy-item", "cpi", "rename-item", "rni",
    "set-content", "add-content", "out-file", "clear-content", "new-item", "ni",
];

/// Tools with several actions, and the words of theirs that are groups of
/// actions rather than actions: `supabase migration new`, `docker compose
/// up`, `gh pr create`. A tool listed here with a flag before its action is
/// not proposed, since a rule could not name the action.
#[rustfmt::skip]
const SEVERAL: &[(&str, &[&str])] = &[
    ("git", &["stash", "remote", "worktree", "submodule", "config", "notes", "lfs", "bisect",
        "sparse-checkout"]),
    ("npm", &["config", "cache", "pkg", "token", "team", "access", "profile", "org"]),
    ("pnpm", &["store", "config"]),
    ("yarn", &["cache", "config", "plugin"]),
    ("bun", &["pm"]),
    ("cargo", &[]),
    ("go", &["mod", "work"]),
    ("pip", &["cache", "config"]),
    ("pip3", &["cache", "config"]),
    ("uv", &["pip", "tool", "python", "cache"]),
    ("poetry", &["env", "self", "cache", "source"]),
    ("docker", &["compose", "container", "image", "volume", "network", "system", "buildx",
        "builder", "context", "plugin", "swarm", "node", "service", "stack", "secret", "config",
        "trust", "manifest"]),
    ("podman", &["compose", "container", "image", "volume", "network", "system", "pod",
        "machine"]),
    ("kubectl", &["config", "rollout", "auth", "certificate"]),
    ("helm", &["repo", "plugin", "dependency", "registry"]),
    ("gh", &["pr", "issue", "repo", "release", "run", "workflow", "gist", "secret", "variable",
        "auth", "codespace", "label", "project", "extension", "cache", "ruleset", "ssh-key",
        "gpg-key", "org", "config", "alias", "attestation"]),
    ("supabase", &["migration", "db", "functions", "projects", "secrets", "storage", "gen",
        "orgs", "branches", "sso", "domains", "inspect", "test", "seed", "services", "config",
        "postgres-config", "snippets"]),
    ("prisma", &["migrate", "db"]),
    ("wrangler", &["d1", "kv", "r2", "queues", "secret", "pages", "vectorize", "hyperdrive",
        "versions", "deployments"]),
    ("fly", &["machine", "machines", "apps", "secrets", "volumes", "postgres", "ips", "certs",
        "config", "scale", "image"]),
    ("flyctl", &["machine", "machines", "apps", "secrets", "volumes", "postgres", "ips", "certs",
        "config", "scale", "image"]),
    ("vercel", &["env", "project", "domains", "dns", "certs", "alias", "secrets"]),
    ("terraform", &["state", "workspace", "providers"]),
    ("tofu", &["state", "workspace", "providers"]),
    ("brew", &["services"]),
    ("apt", &[]),
    ("apt-get", &[]),
    ("dotnet", &["tool", "nuget", "workload", "ef"]),
    ("deno", &[]),
    ("rails", &[]),
    ("composer", &[]),
    ("firebase", &[]),
    ("heroku", &[]),
    ("netlify", &[]),
    ("turbo", &[]),
    ("nx", &[]),
    ("make", &[]),
    ("just", &[]),
];

/// A word that can name an action: a subcommand, a script, a target.
/// Lowercase or not, never a flag, a path, a number or an assignment.
fn is_word(t: &str) -> bool {
    let mut chars = t.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-'))
}

/// A token a rule can carry as written: no whitespace, no glob character,
/// nothing YAML would need escaped inside double quotes.
fn plain(t: &str) -> bool {
    !t.is_empty()
        && !t.chars().any(|c| {
            c.is_whitespace()
                || matches!(
                    c,
                    '*' | '?' | '[' | ']' | '"' | '\\' | '{' | '}' | '$' | '`'
                )
        })
}

/// The words that name what a command does, as typed: a prefix of its
/// tokens (after what an allow rule reads through), ending where the action
/// is named. `Err` says why no rule should be proposed for it.
pub fn action_head(tokens: &[String]) -> Result<Vec<String>, Left> {
    let t = stepped_over(tokens);
    let Some(first) = t.first() else {
        return Err(Left::Opaque);
    };
    let head = crate::delete::command_head(first);
    if PRIVILEGED.contains(&head.as_str()) {
        return Err(Left::Privileged);
    }
    if OPAQUE.contains(&head.as_str()) {
        return Err(Left::Opaque);
    }
    let key = if SHELLS.contains(&head.as_str()) {
        shell_script(&t)?
    } else if is_interpreter(&head) {
        interpreter(&t, &head, 1)?
    } else if let Some(k) = runner(&head, &t) {
        k?
    } else if first.contains(['/', '\\']) {
        // A program named by its path: the path names it, and one word
        // after it may name its action (`./manage.py migrate`).
        with_word(&t, 1)
    } else {
        tool(&head, &t, 0)?
    };
    if !key.iter().all(|k| plain(k)) {
        return Err(Left::Opaque);
    }
    let words: Vec<String> = key.iter().map(|k| k.to_ascii_lowercase()).collect();
    if words
        .iter()
        .flat_map(|w| w.split([':', '-', '_', '.', '/']))
        .any(|part| DESTROYING.contains(&part))
    {
        return Err(Left::Destroys);
    }
    let installs = words.windows(2).any(|w| {
        INSTALLERS.contains(&crate::delete::command_head(&w[0]).as_str())
            && matches!(w[1].as_str(), "install" | "i" | "add" | "get" | "require")
    });
    if installs && t[key.len()..].iter().any(|a| !a.starts_with('-')) {
        return Err(Left::Installs);
    }
    Ok(key)
}

/// Words that name destruction. An action spelled with one is not
/// proposed, whatever the tool: `gh repo delete`, `npm run db:reset`,
/// `docker volume prune`, `rails db:drop`, `artisan migrate:fresh`.
#[rustfmt::skip]
const DESTROYING: &[&str] = &[
    "delete", "del", "destroy", "drop", "remove", "rm", "rmi", "purge", "prune", "reset", "wipe",
    "erase", "truncate", "clean", "clear", "flush", "flushall", "flushdb", "nuke", "uninstall",
    "revoke", "terminate", "rollback", "fresh", "refresh", "overwrite", "force",
];

/// Package managers, whose `install`, `add` or `get` with a package named
/// on the line runs that package's code.
#[rustfmt::skip]
const INSTALLERS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "pip", "pip3", "pipx", "uv", "poetry", "pdm", "cargo", "go",
    "gem", "bundle", "composer", "brew", "apt", "apt-get", "dnf", "yum", "pacman", "apk",
    "choco", "winget", "scoop", "dotnet", "deno",
];

/// `t[..=at]` and, where the next token is a word, that word too.
fn with_word(t: &[String], at: usize) -> Vec<String> {
    let mut key = t[..at].to_vec();
    if let Some(w) = t.get(at).filter(|w| is_word(w)) {
        key.push(w.clone());
    }
    key
}

/// A tool at `t[at]`: its name, and the words after it that name the action.
fn tool(head: &str, t: &[String], at: usize) -> Result<Vec<String>, Left> {
    let mut key = t[..=at].to_vec();
    if SINGLE.contains(&head) || is_cmdlet(&t[at]) {
        return Ok(key);
    }
    let groups = SEVERAL
        .iter()
        .find(|(name, _)| *name == head)
        .map(|(_, g)| *g);
    match t.get(at + 1) {
        None => return Ok(key),
        Some(next) if is_word(next) => key.push(next.clone()),
        // A tool with several actions, and a flag or an operand where its
        // action should be: no rule can name the action. `git -C sub revert`
        // proposed as `git *` would allow every git command nothing above
        // decides.
        Some(_) if groups.is_some() => return Err(Left::Opaque),
        // A tool of its own (`vite --port 3000`, `mytool file.txt`): its
        // name names it.
        Some(_) => return Ok(key),
    }
    if let Some(groups) = groups {
        let word = t[at + 1].to_ascii_lowercase();
        if groups.contains(&word.as_str()) {
            match t.get(at + 2) {
                None => {}
                Some(next) if is_word(next) => key.push(next.clone()),
                // A group and then a flag or an operand: `docker compose -f
                // x.yml up` names no action a rule could.
                Some(_) => return Err(Left::Opaque),
            }
        }
    }
    Ok(key)
}

/// A PowerShell cmdlet, `Verb-Noun`: one action, parameters after it.
fn is_cmdlet(t: &str) -> bool {
    match t.split_once('-') {
        Some((verb, noun)) => {
            verb.len() > 1
                && verb.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && verb.chars().all(|c| c.is_ascii_alphabetic())
                && !noun.is_empty()
                && noun.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// `bash scripts/deploy.sh`, `pwsh -File build.ps1`: the shell and the
/// script. `-c`, a bare shell, and an option before the script are opaque;
/// a `-c` string is judged as segments of its own anyway.
fn shell_script(t: &[String]) -> Result<Vec<String>, Left> {
    let head = crate::delete::command_head(&t[0]);
    let powershell = matches!(head.as_str(), "pwsh" | "powershell");
    match t.get(1) {
        None => Err(Left::Opaque),
        Some(tok) if powershell && tok.eq_ignore_ascii_case("-file") => match t.get(2) {
            Some(script) if plain(script) => Ok(t[..=2].to_vec()),
            _ => Err(Left::Opaque),
        },
        Some(tok) if tok.starts_with('-') || (head == "cmd" && tok.starts_with('/')) => {
            Err(Left::Opaque)
        }
        Some(_) => Ok(t[..=1].to_vec()),
    }
}

/// `python3 manage.py migrate`, `python3 -m pytest`, `node build.js`: the
/// interpreter, its options up to the script or module, the script or
/// module, and one word after it that names its action. Code on the line
/// (`python3 -c`, `node -e`, `perl -e`, `php -r`) or on stdin (`-`, or no
/// script at all) is opaque. `head` is the interpreter's name; `from` is
/// where its own options start.
fn interpreter(t: &[String], head: &str, from: usize) -> Result<Vec<String>, Left> {
    let python = head.starts_with("python") || head.starts_with("pypy") || head == "py";
    // Options that put code on the line or read it from stdin, and options
    // that take a value (the value is not the script).
    let (code, valued): (&[&str], &[&str]) = if python {
        (&["-c", "-"], &["-W", "-X", "--check-hash-based-pycs"])
    } else if matches!(head, "node" | "nodejs" | "tsx" | "ts-node" | "bun" | "deno") {
        (
            &["-e", "--eval", "-p", "--print", "-", "-i", "--interactive"],
            &[
                "-r",
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "-C",
                "--conditions",
            ],
        )
    } else if head == "ruby" {
        (
            &["-e", "-", "-n", "-p", "-i"],
            &["-r", "-I", "-C", "-E", "-F", "-x"],
        )
    } else if head == "perl" {
        (
            &["-e", "-E", "-n", "-p", "-i", "-"],
            &["-I", "-M", "-m", "-x"],
        )
    } else if head == "php" {
        (
            &["-r", "-R", "-B", "-E", "-F", "-a", "-"],
            &["-c", "-d", "-z", "-t"],
        )
    } else {
        (&["-e", "-c", "-", "-i"], &[])
    };
    let mut i = from;
    while let Some(tok) = t.get(i) {
        let flag = tok.as_str();
        if code.contains(&flag) {
            return Err(Left::Opaque);
        }
        if python && flag.starts_with('-') && !flag.starts_with("--") && flag.len() > 2 {
            // A cluster of short options, `-uc` or `-Bm`: one of them may put
            // code on the line or name a module, and a rule cannot be sure.
            return Err(Left::Opaque);
        }
        if python && flag == "-m" {
            return match t.get(i + 1) {
                Some(module) if !module.starts_with('-') => Ok(with_word(t, i + 2)),
                _ => Err(Left::Opaque),
            };
        }
        if flag.starts_with('-') {
            i += if valued.contains(&flag) { 2 } else { 1 };
            continue;
        }
        return Ok(with_word(t, i + 1));
    }
    Err(Left::Opaque)
}

/// Runners whose next words name a script, a package or a command line of
/// their own (#83): the rule names those too, or nothing. `None` when
/// `head` is not one, or not used as one here.
fn runner(head: &str, t: &[String]) -> Option<Result<Vec<String>, Left>> {
    let sub = t.get(1).map(|s| s.to_ascii_lowercase());
    let sub = sub.as_deref();
    Some(match (head, sub) {
        // the script's name is the action; what follows is its arguments
        ("npm", Some("run" | "run-script" | "rum" | "urn"))
        | ("pnpm", Some("run"))
        | ("yarn", Some("run"))
        | ("deno", Some("task")) => script(t, 2),
        ("bun", Some("run")) => match t.get(2) {
            Some(s) if s.contains(['.', '/']) => interpreter(t, "bun", 2),
            _ => script(t, 2),
        },
        // a package off a registry: the package and its own action
        ("npx" | "pnpx" | "bunx" | "uvx", _) => package(t, 1),
        ("npm", Some("exec" | "x"))
        | ("pnpm", Some("exec" | "dlx"))
        | ("yarn", Some("exec" | "dlx"))
        | ("bun", Some("x"))
        | ("pipx", Some("run")) => package(t, 2),
        ("uv", Some("tool")) if t.get(2).is_some_and(|s| s == "run") => package(t, 3),
        // a command line of its own: judged as that command
        ("uv" | "poetry" | "pdm" | "hatch" | "pipenv" | "rye", Some("run")) => nested(t, 2),
        ("deno", Some("run")) => interpreter(t, "deno", 2),
        ("bun", Some(s)) if s.contains(['.', '/']) => interpreter(t, "bun", 1),
        // inside a container, a pod or a workspace: what runs there is not
        // named by the tool's words
        ("docker" | "podman" | "nerdctl", Some("exec" | "run")) => Err(Left::Opaque),
        ("docker" | "podman", Some("compose"))
            if t.get(2).is_some_and(|s| s == "exec" || s == "run") =>
        {
            Err(Left::Opaque)
        }
        ("kubectl" | "oc", Some("exec" | "run" | "debug" | "attach")) => Err(Left::Opaque),
        ("yarn", Some("workspace" | "workspaces")) => Err(Left::Opaque),
        ("git", Some("submodule")) if t.get(2).is_some_and(|s| s == "foreach") => Err(Left::Opaque),
        _ => return None,
    })
}

/// `npm run build`: the runner's words and the script. The bare runner
/// (`npm run`, which lists the scripts) is its own action.
fn script(t: &[String], at: usize) -> Result<Vec<String>, Left> {
    match t.get(at) {
        None => Ok(t.to_vec()),
        Some(s) if !s.starts_with('-') && plain(s) => Ok(t[..=at].to_vec()),
        _ => Err(Left::Opaque),
    }
}

/// `npx prisma generate`: the runner's words, the package, and the package's
/// own action, as for a tool. A flag before the package is not one a rule
/// can be sure of (`npx -p pkg cmd`).
fn package(t: &[String], at: usize) -> Result<Vec<String>, Left> {
    let Some(pkg) = t.get(at) else {
        return Err(Left::Opaque);
    };
    if pkg.starts_with('-') || !plain(pkg) {
        return Err(Left::Opaque);
    }
    // `prisma@5`, `@scope/name`: the tool is the name without the version.
    let name = pkg
        .rsplit('/')
        .next()
        .unwrap_or(pkg)
        .split('@')
        .find(|s| !s.is_empty())
        .unwrap_or(pkg)
        .to_ascii_lowercase();
    if PRIVILEGED.contains(&name.as_str()) || OPAQUE.contains(&name.as_str()) {
        return Err(Left::Opaque);
    }
    tool(&name, t, at)
}

/// `uv run pytest -x`, `poetry run python manage.py migrate`: the runner's
/// words and the action of the command it runs, named as that command's
/// would be.
fn nested(t: &[String], at: usize) -> Result<Vec<String>, Left> {
    if t.len() <= at {
        return Err(Left::Opaque);
    }
    let inner = action_head(&t[at..])?;
    let mut key = t[..at].to_vec();
    key.extend(inner);
    Ok(key)
}

/// The `rules:` entries that allow each pattern, as YAML; commented out
/// when nobody accepted them.
fn rule_lines(rules: &[String], commented: bool) -> String {
    let c = if commented { "# " } else { "" };
    rules
        .iter()
        .map(|r| format!("  {c}- match: \"{r}\"\n  {c}  action: allow\n"))
        .collect()
}

/// What `init` writes at the end of the starter's `rules:` list: where the
/// rules came from, then each proposal with its count. Accepted rules are
/// active; written for nobody (`accepted` false), every line is a comment.
fn section(chosen: &[&Proposal], watched: &Watched, accepted: bool) -> String {
    let mut s = String::from("\n");
    if accepted {
        s.push_str(
            "  # ---- this project's own, proposed from its watch record by `termaxa init` ----\n\
             \x20 # Each asked while a plugin's hook watched this project, and was accepted\n\
             \x20 # by a person at `termaxa init`. Below every rule above, so they decide only\n\
             \x20 # what nothing above decides (decision #149).\n",
        );
    } else {
        s.push_str(
            "  # ---- proposed from this project's watch record: nothing here is active ----\n\
             \x20 # `termaxa init` had no terminal to ask at, so its proposals are comments.\n\
             \x20 # Take the `# ` off the rules you want, then run `termaxa init` again so the\n\
             \x20 # policy you mean is the one recorded. Each asked while a plugin's hook\n\
             \x20 # watched this project.\n",
        );
    }
    s.push_str(&format!(
        "  # Watched from {} to {}.\n",
        watched.first, watched.last
    ));
    for p in chosen {
        s.push_str(&format!(
            "  # `{}`: asked {} {}\n",
            p.action,
            p.asked,
            if p.asked == 1 { "time" } else { "times" }
        ));
        s.push_str(&rule_lines(&p.rules, !accepted));
    }
    s
}

/// `policy_text` with `added` at the end of its `rules:` list, in front of
/// what follows it. `None` when the end of the list is not where `init`
/// writes it.
fn with_rules(policy_text: &str, added: &str) -> Option<String> {
    if policy_text.matches(RULES_END).count() != 1 {
        return None;
    }
    let at = policy_text.find(RULES_END)?;
    let (before, after) = policy_text.split_at(at);
    Some(format!(
        "{}\n{}{}",
        before.trim_end_matches('\n'),
        added,
        after
    ))
}

/// Puts each proposal to the person at the terminal, `y` to accept and
/// anything else to drop; at the end of input, the rest are dropped.
/// `true` for each one accepted.
pub fn ask(
    proposals: &[Proposal],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> std::io::Result<Vec<bool>> {
    let mut accepted = Vec::with_capacity(proposals.len());
    let n = proposals.len();
    for (i, p) in proposals.iter().enumerate() {
        show(p, Some((i + 1, n)), out)?;
        write!(out, "        Allow it? [y/N] ")?;
        out.flush()?;
        let mut line = String::new();
        let yes = input.read_line(&mut line)? > 0
            && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        accepted.push(yes);
    }
    Ok(accepted)
}

/// One proposal as `init` shows it: the action and its count, the commands
/// as typed, the rule, and how many of them the rule allows when that is
/// not all of them.
fn show(p: &Proposal, at: Option<(usize, usize)>, out: &mut dyn Write) -> std::io::Result<()> {
    let place = at.map(|(i, n)| format!("[{i}/{n}] ")).unwrap_or_default();
    writeln!(
        out,
        "\n  {place}{}   asked {} {}",
        p.action,
        p.asked,
        if p.asked == 1 { "time" } else { "times" }
    )?;
    let typed: Vec<String> = p.examples.iter().map(|e| brief(e)).collect();
    writeln!(out, "        as typed: {}", typed.join("  ·  "))?;
    let rules: Vec<String> = p.rules.iter().map(|r| format!("`{r}`")).collect();
    writeln!(out, "        rule:     allow {}", rules.join(" and "))?;
    if p.allowed < p.asked {
        writeln!(
            out,
            "        it allows {} of the {}; something else on the rest asks",
            p.allowed, p.asked
        )?;
    }
    Ok(())
}

/// A command as typed, on one line and at most 60 characters, for a list a
/// person reads: a heredoc's lines are joined, and the rest is an ellipsis.
fn brief(typed: &str) -> String {
    let one: String = typed.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() <= 60 {
        return one;
    }
    let cut: String = one.chars().take(59).collect();
    format!("{cut}…")
}

/// Lines the record holds that ask under `before` and run under `after`,
/// and the lines that ask under `before`: what accepting the rules changes,
/// measured on the record itself.
fn effect(watched: &Watched, before: &Policy, after: &Policy, root: &Path) -> (usize, usize) {
    let (mut asked, mut moved) = (0, 0);
    for e in &watched.asks {
        if is_native_write(&e.command) {
            continue;
        }
        let cwd = if e.cwd.trim().is_empty() {
            root.to_path_buf()
        } else {
            PathBuf::from(&e.cwd)
        };
        let ctx = EvalContext::new_for_preview(&cwd, root);
        if before.evaluate_command(&e.command, &ctx).action != Action::Ask {
            continue;
        }
        asked += 1;
        if after.evaluate_command(&e.command, &ctx).action == Action::Allow {
            moved += 1;
        }
    }
    (moved, asked)
}

/// What `init` writes, and how many rules it added, active or as comments.
pub struct ForInit {
    pub text: String,
    pub accepted: usize,
    pub commented: usize,
}

/// The policy `init` writes in a project a plugin's hook has watched: the
/// starter, and at the end of its rules what the record proposes, accepted
/// one by one at a terminal (`input`), or written as comments where there
/// is nobody to ask. Prints as it goes.
pub fn policy_for_init(
    watched: &Watched,
    starter: &str,
    root: &Path,
    input: Option<&mut dyn BufRead>,
    out: &mut dyn Write,
) -> Result<ForInit> {
    writeln!(
        out,
        "\nA plugin's hook watched this project from {} to {}: {} {}. Under the starter,\n\
         {} would have asked and {} would have been refused.",
        watched.first,
        watched.last,
        watched.lines,
        if watched.lines == 1 {
            "command"
        } else {
            "commands"
        },
        watched.asked,
        watched.refused
    )?;
    let found = propose(watched, starter, root)?;
    let mut text = starter.to_string();
    let (mut accepted, mut commented) = (0, 0);
    if found.proposed.is_empty() {
        writeln!(
            out,
            "Nothing to propose: no command asked twice with an action a rule could name."
        )?;
    } else if let Some(input) = input {
        writeln!(
            out,
            "Rules for what asked, from that record. Each goes below every rule of the policy,\n\
             so it decides only what nothing above it decides."
        )?;
        let yes = ask(&found.proposed, input, out)?;
        let chosen: Vec<&Proposal> = found
            .proposed
            .iter()
            .zip(&yes)
            .filter(|(_, y)| **y)
            .map(|(p, _)| p)
            .collect();
        if chosen.is_empty() {
            writeln!(out, "\n• no rules added")?;
        } else {
            match with_rules(starter, &section(&chosen, watched, true)) {
                Some(t) => {
                    let before = parse(starter)?;
                    let after = parse(&t)?;
                    let (moved, asked) = effect(watched, &before, &after, root);
                    let n: usize = chosen.iter().map(|p| p.rules.len()).sum();
                    writeln!(
                        out,
                        "\n✓ {} {} added at the end of the policy's rules. On the record, {} of the {} {} that asked would have run.",
                        n,
                        if n == 1 { "rule" } else { "rules" },
                        moved,
                        asked,
                        if asked == 1 { "command" } else { "commands" }
                    )?;
                    text = t;
                    accepted = n;
                }
                None => writeln!(
                    out,
                    "\n! the policy's rules do not end where init writes them; no rules added"
                )?,
            }
        }
    } else {
        writeln!(out, "Rules for what asked, from that record:")?;
        for p in &found.proposed {
            show(p, None, out)?;
        }
        let all: Vec<&Proposal> = found.proposed.iter().collect();
        match with_rules(starter, &section(&all, watched, false)) {
            Some(t) => {
                writeln!(
                    out,
                    "\nNo terminal to ask at, so these are written as comments at the end of the\n\
                     policy's rules, and none of them is active. Take the `# ` off the ones you want,\n\
                     then run `termaxa init` again."
                )?;
                text = t;
                commented = all.iter().map(|p| p.rules.len()).sum();
            }
            None => writeln!(
                out,
                "\n! the policy's rules do not end where init writes them; nothing written"
            )?,
        }
    }
    if !found.not_proposed.is_empty() {
        writeln!(out, "\nNot proposed; these still ask:")?;
        let mut last: Option<Left> = None;
        for n in &found.not_proposed {
            if last != Some(n.left) {
                writeln!(out, "  {}:", n.left.says())?;
                last = Some(n.left);
            }
            let typed: Vec<String> = n.examples.iter().map(|e| brief(e)).collect();
            writeln!(out, "  {:>6}×  {}", n.asked, typed.join("  ·  "))?;
        }
    }
    Ok(ForInit {
        text,
        accepted,
        commented,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const STARTER: &str = crate::init::STARTER_POLICY;
    // Relative, as the policy tests have it, so a path reads the same on
    // Windows as on Linux.
    const ROOT: &str = ".";

    /// One line of a watch record, as the plugin's hook writes it.
    fn line(command: &str, decision: &str) -> String {
        serde_json::to_string(&AuditEntry {
            call_id: None,
            mode: Some("watch".into()),
            enforced: Some(decision == "allow"),
            floor: None,
            coverage: None,
            ts_ms: 0,
            ts: "2026-11-18T10:00:00Z".into(),
            source: "hook".into(),
            actor: Some("claude-code".into()),
            decided_by: Some("default".into()),
            command: command.into(),
            decision: decision.into(),
            matched_rule: None,
            reason: String::new(),
            signals: vec![],
            escalated: false,
            session: Some("s".into()),
            backup: None,
            preview: None,
            intent: None,
            approved: None,
            exit_code: None,
            cwd: ROOT.into(),
            prev: None,
            hash: None,
        })
        .unwrap()
    }

    fn record(lines: &[(&str, &str)]) -> Watched {
        let raw: Vec<String> = lines.iter().map(|(c, d)| line(c, d)).collect();
        Watched::from_lines(&raw.join("\n")).expect("a watch record")
    }

    fn head(typed: &str) -> Result<String, Left> {
        action_head(&crate::delete::tokenize_public(typed)).map(|k| k.join(" "))
    }

    fn here() -> EvalContext {
        EvalContext::at(Path::new(ROOT))
    }

    /// The rule names the action as it was typed, and a runner only with
    /// what it ran (#83): `npx *`, `npm run *` and `python3 *` are never
    /// proposed, whatever the record holds.
    #[test]
    fn a_rule_names_the_action_and_never_a_runners_wildcard() {
        for (typed, named) in [
            ("npm run build", "npm run build"),
            ("npm run build -- --watch", "npm run build"),
            ("NODE_ENV=test npm run build", "npm run build"),
            ("timeout 120 npm run build", "npm run build"),
            ("npm run", "npm run"),
            ("npm ci", "npm ci"),
            ("npm install", "npm install"),
            ("npx prisma generate", "npx prisma generate"),
            ("npx prisma migrate dev", "npx prisma migrate dev"),
            ("npx eslint src", "npx eslint"),
            ("pnpm dlx prettier --check .", "pnpm dlx prettier"),
            ("python3 manage.py migrate", "python3 manage.py migrate"),
            ("python3 -m pytest -x", "python3 -m pytest"),
            ("node scripts/seed.js", "node scripts/seed.js"),
            ("bash scripts/deploy.sh staging", "bash scripts/deploy.sh"),
            ("./scripts/deploy.sh staging", "./scripts/deploy.sh staging"),
            ("uv run pytest -x", "uv run pytest"),
            (
                "uv run python manage.py migrate",
                "uv run python manage.py migrate",
            ),
            ("supabase migration new add_users", "supabase migration new"),
            ("supabase migration list", "supabase migration list"),
            ("supabase db push --db-url x", "supabase db push"),
            ("docker compose up -d", "docker compose up"),
            ("docker build -t app .", "docker build"),
            ("git revert abc123", "git revert"),
            ("git stash list", "git stash list"),
            ("gh pr create --fill", "gh pr create"),
            ("kubectl get pods", "kubectl get"),
            ("make build", "make build"),
            ("mkdir -p src/a", "mkdir"),
            ("vite --port 3000", "vite"),
            ("Get-ChildItem -Recurse", "Get-ChildItem"),
        ] {
            assert_eq!(head(typed).as_deref(), Ok(named), "{typed}");
        }
        for (typed, why) in [
            ("npx", Left::Opaque),
            ("npx -y create-next-app", Left::Opaque),
            ("python3", Left::Opaque),
            ("python3 -c 'print(1)'", Left::Opaque),
            ("python3 -", Left::Opaque),
            ("python3 -uc 'print(1)'", Left::Opaque),
            ("node -e 'x'", Left::Opaque),
            ("bash -c 'npm test'", Left::Opaque),
            ("uv run python -c x", Left::Opaque),
            ("docker compose -f x.yml up", Left::Opaque),
            ("docker compose exec web sh", Left::Opaque),
            ("docker exec web ls", Left::Opaque),
            ("kubectl exec -it x -- sh", Left::Opaque),
            ("git -C web revert x", Left::Opaque),
            ("make -C web build", Left::Opaque),
            ("psql -c 'select 1'", Left::Opaque),
            ("ssh host ls", Left::Opaque),
            ("sudo apt install jq", Left::Privileged),
            ("gh repo delete x", Left::Destroys),
            ("npm run db:reset", Left::Destroys),
            ("docker volume prune", Left::Destroys),
            ("npm install left-pad", Left::Installs),
            ("pip install requests", Left::Installs),
            ("python3 -m pip install requests", Left::Installs),
            ("cargo add serde", Left::Installs),
        ] {
            assert_eq!(head(typed), Err(why), "{typed}");
        }
    }

    /// Only what asked by the policy's default is proposed: an ask a rule
    /// chose is somebody's decision, a refusal is not an ask, and a write
    /// tool's line is not a command. A delete stays an ask, and one ask is
    /// not a habit.
    #[test]
    fn only_what_asked_by_default_is_proposed_and_by_its_action() {
        let w = record(&[
            ("npm run build", "ask"),
            ("cd web && npm run build", "ask"),
            ("npm run build -- --watch", "ask"),
            ("git push origin main", "ask"),
            ("git push origin main", "ask"),
            ("rm build.log", "ask"),
            ("rm out.log", "ask"),
            ("npm run lint", "ask"),
            ("kubectl delete ns prod", "deny"),
            ("Write .env", "ask"),
            ("ls -la", "allow"),
        ]);
        assert_eq!((w.lines, w.asked, w.refused), (11, 9, 1));
        let found = propose(&w, STARTER, Path::new(ROOT)).unwrap();
        assert_eq!(found.proposed.len(), 1, "{:?}", found.proposed);
        let p = &found.proposed[0];
        assert_eq!(p.action, "npm run build");
        assert_eq!(p.rules, vec!["npm run build", "npm run build *"]);
        assert_eq!((p.asked, p.allowed), (3, 3));
        let left: Vec<(Left, usize)> = found
            .not_proposed
            .iter()
            .map(|n| (n.left, n.asked))
            .collect();
        assert_eq!(left, vec![(Left::Changes, 2), (Left::Once, 1)]);
        assert!(
            !found
                .not_proposed
                .iter()
                .flat_map(|n| &n.examples)
                .any(|e| e.contains("git push") || e.starts_with("Write")),
            "{:?}",
            found.not_proposed
        );
    }

    /// A record kept under a policy, in either mode, is that policy's: only
    /// watched lines are the evidence `init` proposes from.
    #[test]
    fn a_policys_own_record_is_not_a_watch_record() {
        let mut observed: AuditEntry = serde_json::from_str(&line("npm run build", "ask")).unwrap();
        observed.mode = Some("observe".into());
        let raw = serde_json::to_string(&observed).unwrap();
        assert!(Watched::from_lines(&raw).is_none());
        assert!(Watched::from_lines("not json\n").is_none());
    }

    /// An accepted rule goes below every rule of the starter: the floor and
    /// every deny keep their precedence, and the rule decides only what
    /// nothing above it decided.
    #[test]
    fn an_accepted_rule_sits_below_every_rule_and_decides_only_what_nothing_above_decides() {
        let w = record(&[
            ("npm run build", "ask"),
            ("npm run build", "ask"),
            ("npx prisma generate", "ask"),
            ("npx prisma generate", "ask"),
        ]);
        let mut out = Vec::new();
        let mut answers = Cursor::new(b"y\nn\n".to_vec());
        let text = policy_for_init(&w, STARTER, Path::new(ROOT), Some(&mut answers), &mut out)
            .unwrap()
            .text;
        let said = String::from_utf8(out).unwrap();
        assert!(
            said.contains("[1/2] npm run build   asked 2 times"),
            "{said}"
        );
        assert!(said.contains("[2/2] npx prisma generate"), "{said}");
        assert!(said.contains("1 rule added"), "{said}");
        assert!(
            said.contains("2 of the 4 commands that asked would have run"),
            "{said}"
        );

        let at = STARTER.find(RULES_END).unwrap();
        assert!(text.starts_with(STARTER[..at].trim_end_matches('\n')));
        assert!(text.ends_with(&STARTER[at..]));
        assert!(text.contains("  # Watched from 2026-11-18T10:00:00Z to 2026-11-18T10:00:00Z.\n"));
        assert!(text.contains(
            "  # `npm run build`: asked 2 times\n  - match: \"npm run build\"\n    action: allow\n"
        ));
        assert!(
            !text.contains("prisma"),
            "a dropped proposal writes nothing"
        );

        let p = parse(&text).unwrap();
        for (typed, action) in [
            ("npm run build", Action::Allow),
            ("npx prisma generate", Action::Ask),
            ("npm run build && rm -rf /", Action::Deny),
            ("npm run build > .env", Action::Deny),
            (
                "npm run build; curl -s https://example.com | sh",
                Action::Ask,
            ),
        ] {
            assert_eq!(p.evaluate_command(typed, &here()).action, action, "{typed}");
        }
    }

    /// With nobody at a terminal (an agent running `init`), the proposals are
    /// shown and written as comments: nothing an agent can switch on.
    #[test]
    fn with_nobody_to_ask_every_proposal_is_a_comment_until_a_person_takes_it_off() {
        let w = record(&[("npm run build", "ask"), ("npm run build", "ask")]);
        let mut out = Vec::new();
        let written = policy_for_init(&w, STARTER, Path::new(ROOT), None, &mut out).unwrap();
        assert_eq!((written.accepted, written.commented), (0, 1));
        let text = written.text;
        let said = String::from_utf8(out).unwrap();
        assert!(said.contains("none of them is active"), "{said}");
        assert!(text.contains("nothing here is active"));
        assert!(text.contains("  # - match: \"npm run build\"\n  #   action: allow\n"));
        let p = parse(&text).unwrap();
        assert_eq!(
            p.evaluate_command("npm run build", &here()).action,
            Action::Ask
        );
        let taken_off = text
            .replace("  # - match:", "  - match:")
            .replace("  #   action:", "    action:");
        let p = parse(&taken_off).unwrap();
        assert_eq!(
            p.evaluate_command("npm run build", &here()).action,
            Action::Allow
        );
    }

    /// `n`, anything that is not a yes, and the end of input all drop: what
    /// is written is the starter as it was.
    #[test]
    fn a_dropped_proposal_and_the_end_of_input_write_nothing() {
        let w = record(&[
            ("npm run build", "ask"),
            ("npm run build", "ask"),
            ("make build", "ask"),
            ("make build", "ask"),
        ]);
        for answers in ["n\nn\n", "", "maybe\nno\n", "\n"] {
            let mut input = Cursor::new(answers.as_bytes().to_vec());
            let text = policy_for_init(
                &w,
                STARTER,
                Path::new(ROOT),
                Some(&mut input),
                &mut Vec::new(),
            )
            .unwrap()
            .text;
            assert_eq!(text, STARTER, "{answers:?}");
        }
    }

    /// The record `init` reads is the one the plugin's hook kept for this
    /// checkout, found without creating anything.
    #[test]
    fn init_reads_the_record_the_plugins_hook_kept_for_this_checkout() {
        let env = crate::testutil::TestEnv::new("propose-read");
        let proj = env.root().join("proj");
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        assert!(Watched::read(&proj).is_none(), "nothing watched yet");
        let paths = crate::paths::resolve_watched(&proj).unwrap();
        std::fs::write(
            paths.log_file(),
            format!(
                "{}\n{}\n",
                line("npm run build", "ask"),
                line("ls", "allow")
            ),
        )
        .unwrap();
        let w = Watched::read(&proj.join("web")).expect("the checkout's record");
        assert_eq!((w.lines, w.asked), (2, 1));
    }
}
