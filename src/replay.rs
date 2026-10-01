//! `termaxa replay`: every command an agent ran on this machine, judged
//! by the policy, executing nothing.
//!
//! Claude Code keeps a transcript per session under `~/.claude/projects/`,
//! Codex under `~/.codex/sessions/`; both are JSONL and both carry each shell
//! call as a `command` field somewhere in the line (Claude Code inside the
//! tool call's `input`, Codex inside a function call's `arguments`, itself a
//! JSON string, as `["bash","-lc","…"]`). Replaying them through the policy
//! answers the question a person asks before installing a gate: how often
//! would it have asked about my ordinary work? Every ask is a rule to add or
//! a reason it should stay an ask (the Sep 20, 2026 replay found six of the
//! former and fixed them).
//!
//! No previews, no insurance, no audit lines: the verdict only, the way
//! `check` would decide it, context and readable substitutions included.

use crate::context;
use crate::policy::{Action, Policy};
use crate::resolve::EvalContext;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where the harnesses keep their transcripts, under the home directory.
pub fn default_roots() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
    else {
        return Vec::new();
    };
    vec![
        home.join(".claude").join("projects"),
        home.join(".codex").join("sessions"),
    ]
}

/// Every `.jsonl` under the given roots (a root may be a file).
pub fn transcripts(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        if root.is_file() {
            out.push(root.clone());
            continue;
        }
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "jsonl") {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

/// The `command` values in one JSON value, wherever they sit: a string as
/// is, an array joined the way a shell would quote it (Codex's
/// `["bash","-lc","…"]` becomes `bash -lc '…'`, which the reader opens as
/// the wrapper it is), and a string that is itself JSON descended into
/// (Codex's `arguments`).
pub fn commands_in(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if k == "command" {
                    match val {
                        serde_json::Value::String(s) if !s.trim().is_empty() => out.push(s.clone()),
                        serde_json::Value::Array(items) => {
                            let joined: Vec<String> = items
                                .iter()
                                .map(|i| match i {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .collect();
                            if !joined.is_empty() {
                                out.push(crate::runner::shell_join(&joined));
                            }
                        }
                        _ => {}
                    }
                } else if k == "arguments" {
                    // Codex: the call's arguments are a JSON string. Only
                    // here is a string parsed; a file an agent WROTE that
                    // happens to contain `"command":` is not a call (the
                    // first run of --against-record flagged a hooks file's
                    // `termaxa hook` as a shell call, Oct 1, 2026).
                    if let serde_json::Value::String(s) = val {
                        if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s) {
                            commands_in(&inner, out);
                        }
                    }
                } else {
                    commands_in(val, out);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| commands_in(i, out)),
        _ => {}
    }
}

/// The script inside a shell wrapper: `["bash","-lc",S]`, `["sh","-c",S]`,
/// `["powershell.exe","-Command",S]`, `["cmd","/c",S]` → `S`. What the gate
/// judges and records is the inner command (the Codex dialect unwraps it),
/// so the transcript's call has to be read the same way to match.
pub fn unwrap_shell(argv: &[String]) -> Option<String> {
    let shell = argv
        .first()?
        .rsplit(['/', '\\'])
        .next()?
        .to_ascii_lowercase();
    let known = matches!(
        shell.as_str(),
        "bash"
            | "sh"
            | "zsh"
            | "dash"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "cmd"
            | "cmd.exe"
    );
    if !known || argv.len() < 3 {
        return None;
    }
    let flag = argv[argv.len() - 2].to_ascii_lowercase();
    let is_flag = matches!(
        flag.as_str(),
        "-c" | "-lc" | "-command" | "-c," | "/c" | "-file"
    ) && !argv[..argv.len() - 2][1..]
        .iter()
        .any(|a| !a.starts_with('-') && !a.starts_with('/'));
    if is_flag {
        Some(argv[argv.len() - 1].clone())
    } else {
        None
    }
}

/// Every command in one transcript, in order. Lines that are not JSON are
/// skipped; a transcript that cannot be read is skipped and counted.
pub fn commands_in_file(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains("command") {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            commands_in(&v, &mut out);
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct Tally {
    pub transcripts: usize,
    pub commands: usize,
    pub allowed: usize,
    pub asked: usize,
    pub denied: usize,
    /// Distinct asked commands with how often, and the reason for the first.
    pub asks: BTreeMap<String, (usize, String)>,
    pub denies: BTreeMap<String, (usize, String)>,
}

/// Judge every command the way `check` would: the policy, then context,
/// with a substitution the policy explicitly allows read as readable.
pub fn replay(policy: &Policy, ctx: &EvalContext, roots: &[PathBuf]) -> Tally {
    let files = transcripts(roots);
    let mut t = Tally {
        transcripts: files.len(),
        ..Default::default()
    };
    for f in &files {
        for cmd in commands_in_file(f) {
            if cmd.len() > 4096 {
                continue;
            }
            t.commands += 1;
            let base = policy.evaluate_command(&cmd, ctx);
            let signals = context::gather_with(&cmd, &|inner| policy.allows_explicitly(inner, ctx));
            let (d, _) = context::apply(base, &signals);
            let key = cmd.replace('\n', " ");
            match d.action {
                Action::Allow => t.allowed += 1,
                Action::Ask => {
                    t.asked += 1;
                    let e = t.asks.entry(key).or_insert((0, d.reason.clone()));
                    e.0 += 1;
                }
                Action::Deny => {
                    t.denied += 1;
                    let e = t.denies.entry(key).or_insert((0, d.reason.clone()));
                    e.0 += 1;
                }
            }
        }
    }
    t
}

fn ranked(map: &BTreeMap<String, (usize, String)>) -> Vec<(&String, &(usize, String))> {
    let mut v: Vec<_> = map.iter().collect();
    v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
    v
}

fn short(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        out.push('…');
    }
    out
}

/// The report `termaxa replay` prints.
pub fn render(t: &Tally, roots: &[PathBuf], all: bool) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "replayed {} command(s) from {} transcript(s) under {}\n",
        t.commands,
        t.transcripts,
        roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if t.commands == 0 {
        o.push_str("nothing to replay: no `command` fields found\n");
        return o;
    }
    let pct = |n: usize| (n as f64 * 100.0 / t.commands as f64).round() as usize;
    o.push_str(&format!(
        "  allow {:>5}  ({}%)\n  ask   {:>5}  ({}%)\n  deny  {:>5}  ({}%)\n",
        t.allowed,
        pct(t.allowed),
        t.asked,
        pct(t.asked),
        t.denied,
        pct(t.denied)
    ));
    let limit = if all { usize::MAX } else { 25 };
    if !t.asks.is_empty() {
        o.push_str(&format!(
            "\nasked, most frequent first ({} distinct{}):\n",
            t.asks.len(),
            if t.asks.len() > limit {
                ", showing 25; --all for every one"
            } else {
                ""
            }
        ));
        for (cmd, (n, reason)) in ranked(&t.asks).into_iter().take(limit) {
            o.push_str(&format!(
                "  {:>4}  {}\n        {}\n",
                n,
                short(cmd, 110),
                short(reason, 120)
            ));
        }
    }
    if !t.denies.is_empty() {
        o.push_str(&format!("\ndenied ({} distinct):\n", t.denies.len()));
        for (cmd, (n, reason)) in ranked(&t.denies).into_iter().take(limit) {
            o.push_str(&format!(
                "  {:>4}  {}\n        {}\n",
                n,
                short(cmd, 110),
                short(reason, 120)
            ));
        }
    }
    o.push_str("\nevery ask is a rule to add to .termaxa/policy.yaml, or a reason it should stay an ask; nothing was executed\n");
    o
}

/// `termaxa replay [PATHS...]` with the current project's policy, or the
/// starter when there is none.
pub fn run(paths: Vec<PathBuf>, all: bool, against: bool) -> Result<i32> {
    let roots = if paths.is_empty() {
        default_roots()
    } else {
        paths
    };
    if roots.is_empty() {
        anyhow::bail!("no transcript directories given and no home directory to look under");
    }
    if against {
        let a = against_record(&roots);
        print!("{}", render_against(&a, &roots));
        return Ok(
            if a.fired_unrecorded.is_empty() && a.never_fired.is_empty() {
                0
            } else {
                1
            },
        );
    }
    let (policy, cwd) = match crate::paths::resolve() {
        Ok(p) => (Policy::load(&p.policy_file())?, std::env::current_dir()?),
        Err(_) => {
            eprintln!(
                "{}",
                crate::ui::dim("ℹ No project policy here; replaying against the built-in starter.")
            );
            (
                Policy::builtin().context("starter")?,
                std::env::current_dir()?,
            )
        }
    };
    let ctx = EvalContext::at(&cwd);
    let t = replay(&policy, &ctx, &roots);
    print!("{}", render(&t, &roots, all));
    Ok(0)
}

// ---------------------------------------------------------------------------
// --against-record: the replay inversion (Tim Schipper, Sep 2026)
// ---------------------------------------------------------------------------
//
// The record shows what the gate saw. The transcript shows what the agent
// ran. A transcript call with no record line is a measured bypass, and the
// witness the hook leaves first (witness.rs) says which kind: fired but
// unrecorded (a witness, no record line: the gate failed) or never fired (no
// witness: the wiring was bypassed). Only sessions where the gate was wired
// at all are judged; a session with neither a record line nor a witness ran
// before the gate was installed, on another machine, or under a harness
// with no hook, and is reported as such rather than as a bypass.

/// One tool call as the transcript records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub session: Option<String>,
    pub id: Option<String>,
    pub ts_ms: Option<u128>,
    pub command: String,
    /// False when the transcript's own result for this call says it was
    /// interrupted or rejected before it ran: no hook was due, so its
    /// absence from the record is not a bypass.
    pub executed: bool,
}

fn rfc3339_ms(s: &str) -> Option<u128> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp_millis().max(0) as u128)
}

/// The words of a `tool_result` that mean the call never ran.
fn result_says_not_run(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    [
        "interrupted",
        "rejected",
        "doesn't want to proceed",
        "does not want to proceed",
        "cancelled",
        "canceled",
        "aborted",
    ]
    .iter()
    .any(|m| t.contains(m))
}

fn text_of(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => items.iter().map(text_of).collect::<Vec<_>>().join(" "),
        serde_json::Value::Object(map) => map.values().map(text_of).collect::<Vec<_>>().join(" "),
        _ => String::new(),
    }
}

/// Every shell call in one transcript, with its session, id and time where
/// the harness wrote them. Claude Code: a `tool_use` block named `Bash`
/// with `input.command`, `sessionId` and `timestamp` on the line, and the
/// later `tool_result` for its id. Codex: a `function_call` of its shell
/// tool with `call_id` and `arguments`, the session from `session_meta` or
/// the rollout file's name, and a shell wrapper unwrapped to its script.
/// Nothing else counts: a file an agent wrote that mentions a command is
/// not a call.
pub fn calls_in_file(path: &Path) -> Vec<Call> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out: Vec<Call> = Vec::new();
    let mut not_run: std::collections::HashSet<String> = Default::default();
    let mut file_session: Option<String> = None;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string);
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("type").and_then(|t| t.as_str()) == Some("session_meta") {
            file_session = v
                .pointer("/payload/id")
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .or(file_session);
            continue;
        }
        let ts_ms = v
            .get("timestamp")
            .and_then(|t| t.as_str())
            .and_then(rfc3339_ms);
        let session = v
            .get("sessionId")
            .or_else(|| v.get("session_id"))
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .or_else(|| file_session.clone())
            .or_else(|| stem.clone());
        if let Some(blocks) = v.pointer("/message/content").and_then(|c| c.as_array()) {
            for b in blocks {
                match b.get("type").and_then(|t| t.as_str()) {
                    Some("tool_use") if b.get("name").and_then(|n| n.as_str()) == Some("Bash") => {
                        if let Some(cmd) = b.pointer("/input/command").and_then(|c| c.as_str()) {
                            if !cmd.trim().is_empty() {
                                out.push(Call {
                                    session: session.clone(),
                                    id: b.get("id").and_then(|x| x.as_str()).map(str::to_string),
                                    ts_ms,
                                    command: cmd.to_string(),
                                    executed: true,
                                });
                            }
                        }
                    }
                    Some("tool_result") => {
                        if let Some(id) = b.get("tool_use_id").and_then(|x| x.as_str()) {
                            if result_says_not_run(&text_of(b)) {
                                not_run.insert(id.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        // Codex: a function call of the shell tool, at the top level or
        // under `payload`.
        let item = v.get("payload").unwrap_or(&v);
        let is_call = item.get("type").and_then(|t| t.as_str()) == Some("function_call");
        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if !is_call
            || !matches!(
                name,
                "shell" | "exec_command" | "local_shell" | "shell_command" | "container.exec"
            )
        {
            continue;
        }
        let id = item
            .get("call_id")
            .and_then(|x| x.as_str())
            .map(str::to_string);
        let Some(args) = item.get("arguments") else {
            continue;
        };
        let parsed: serde_json::Value = match args {
            serde_json::Value::String(s) => {
                serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
            }
            other => other.clone(),
        };
        let command = match parsed.get("command") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(items)) => {
                let argv: Vec<String> = items
                    .iter()
                    .map(|i| match i {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect();
                unwrap_shell(&argv).unwrap_or_else(|| crate::runner::shell_join(&argv))
            }
            _ => continue,
        };
        if command.trim().is_empty() {
            continue;
        }
        out.push(Call {
            session: session.clone(),
            id,
            ts_ms,
            command,
            executed: true,
        });
    }
    for c in &mut out {
        if c.id.as_deref().is_some_and(|id| not_run.contains(id)) {
            c.executed = false;
        }
    }
    out
}

/// A record line or a witness line, reduced to what matching needs.
#[derive(Debug, Clone)]
pub struct Seen {
    ts_ms: u128,
    session: Option<String>,
    call_id: Option<String>,
    command: String,
    /// `Some(decision)` for a record line, `None` for a witness.
    decision: Option<String>,
}

fn seen_lines(path: &Path, decision_field: bool) -> Vec<Seen> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| {
            // Receipts and breaker events are not judgements of a call.
            let src = v.get("source").and_then(|s| s.as_str()).unwrap_or("");
            !decision_field || matches!(src, "hook" | "run" | "supervise" | "wrap")
        })
        .map(|v| Seen {
            ts_ms: v
                .get("ts_ms")
                .and_then(|t| t.as_u64())
                .map(u128::from)
                .unwrap_or(0),
            session: v
                .get("session")
                .and_then(|s| s.as_str())
                .map(str::to_string),
            call_id: v
                .get("call_id")
                .and_then(|s| s.as_str())
                .map(str::to_string),
            command: v
                .get("command")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            decision: if decision_field {
                v.get("decision")
                    .and_then(|d| d.as_str())
                    .map(str::to_string)
            } else {
                None
            },
        })
        .collect()
}

/// Everything the gate saw on this machine: every project's record and
/// witness file under the Termaxa home.
pub fn everything_seen(home: &Path) -> (Vec<Seen>, Vec<Seen>) {
    let mut records = Vec::new();
    let mut witnesses = Vec::new();
    if let Ok(projects) = std::fs::read_dir(home.join("projects")) {
        for p in projects.flatten() {
            let logs = p.path().join("logs");
            records.extend(seen_lines(&logs.join("audit.jsonl"), true));
            witnesses.extend(seen_lines(&logs.join("seen.jsonl"), false));
        }
    }
    (records, witnesses)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fate {
    Judged(String),
    FiredUnrecorded,
    NeverFired,
}

fn norm(c: &str) -> String {
    c.split_whitespace().collect::<Vec<_>>().join(" ")
}

const WINDOW_MS: u128 = 180_000;

fn matches(call: &Call, s: &Seen) -> bool {
    if let (Some(a), Some(b)) = (&call.id, &s.call_id) {
        return a == b;
    }
    if call.session.is_some() && s.session.is_some() && call.session != s.session {
        return false;
    }
    if norm(&call.command) != norm(&s.command) {
        return false;
    }
    match call.ts_ms {
        Some(t) => t.abs_diff(s.ts_ms) <= WINDOW_MS,
        None => true,
    }
}

/// Sort one call: by id first, then by session, text and time.
pub fn fate(call: &Call, records: &[Seen], witnesses: &[Seen]) -> Fate {
    if let Some(r) = records.iter().find(|s| matches(call, s)) {
        return Fate::Judged(r.decision.clone().unwrap_or_default());
    }
    if witnesses.iter().any(|s| matches(call, s)) {
        return Fate::FiredUnrecorded;
    }
    Fate::NeverFired
}

#[derive(Debug, Default)]
pub struct Against {
    pub transcripts: usize,
    pub calls: usize,
    /// Sessions with neither a record line nor a witness: not wired.
    pub unwired_sessions: usize,
    pub unwired_calls: usize,
    pub judged: usize,
    /// Interrupted or rejected before running, per the transcript's own
    /// result: no hook was due.
    pub not_run: usize,
    pub fired_unrecorded: Vec<Call>,
    pub never_fired: Vec<Call>,
}

pub fn against_record(roots: &[PathBuf]) -> Against {
    let home = crate::paths::home_base().unwrap_or_default();
    against_record_in(&home, roots)
}

/// The same, reading the record and witnesses under `home`.
pub fn against_record_in(home: &Path, roots: &[PathBuf]) -> Against {
    let (records, witnesses) = everything_seen(home);
    let wired: std::collections::HashSet<&str> = records
        .iter()
        .chain(witnesses.iter())
        .filter_map(|s| s.session.as_deref())
        .collect();
    let mut a = Against::default();
    let mut unwired: std::collections::HashSet<String> = Default::default();
    for t in transcripts(roots) {
        let calls = calls_in_file(&t);
        if calls.is_empty() {
            continue;
        }
        a.transcripts += 1;
        for c in calls {
            a.calls += 1;
            let is_wired = c.session.as_deref().is_some_and(|s| wired.contains(s));
            if !is_wired {
                a.unwired_calls += 1;
                if let Some(s) = &c.session {
                    unwired.insert(s.clone());
                }
                continue;
            }
            match fate(&c, &records, &witnesses) {
                Fate::Judged(_) => a.judged += 1,
                Fate::FiredUnrecorded => a.fired_unrecorded.push(c),
                Fate::NeverFired if !c.executed => a.not_run += 1,
                Fate::NeverFired => a.never_fired.push(c),
            }
        }
    }
    a.unwired_sessions = unwired.len();
    a
}

pub fn render_against(a: &Against, roots: &[PathBuf]) -> String {
    use crate::ui::{bold, dim, green, red};
    let mut s = String::new();
    s.push_str(&format!(
        "{} {} transcript(s), {} shell call(s), under {}\n\n",
        bold("replay --against-record:"),
        a.transcripts,
        a.calls,
        roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let wired_calls = a.calls - a.unwired_calls;
    s.push_str(&format!(
        "  {:<22}{}   {}\n",
        "not wired",
        a.unwired_calls,
        dim(&format!(
            "in {} session(s) with no record and no witness: before the gate was installed, another machine, or a harness with no hook",
            a.unwired_sessions
        ))
    ));
    s.push_str(&format!(
        "  {:<22}{}   {}\n",
        "judged",
        a.judged,
        dim("a record line matches the call")
    ));
    s.push_str(&format!(
        "  {:<22}{}   {}\n",
        "not run",
        a.not_run,
        dim("interrupted or rejected before running, per the transcript: no hook was due")
    ));
    s.push_str(&format!(
        "  {:<22}{}   {}\n",
        "fired, unrecorded",
        a.fired_unrecorded.len(),
        dim("the hook left a witness and no record line: the gate failed after it fired")
    ));
    s.push_str(&format!(
        "  {:<22}{}   {}\n",
        "never fired",
        a.never_fired.len(),
        dim("no witness and no record in a wired session: the wiring was bypassed")
    ));
    if wired_calls > 0 && a.fired_unrecorded.is_empty() && a.never_fired.is_empty() {
        s.push_str(&format!(
            "\n{} every call in a wired session reached the gate and was recorded\n",
            green("✓")
        ));
    }
    for (title, list) in [
        ("fired, unrecorded", &a.fired_unrecorded),
        ("never fired", &a.never_fired),
    ] {
        if list.is_empty() {
            continue;
        }
        s.push_str(&format!("\n{} {}:\n", red("✗"), title));
        for c in list.iter().take(25) {
            s.push_str(&format!(
                "  {}  {}\n",
                dim(c
                    .session
                    .as_deref()
                    .map(|x| &x[..x.len().min(8)])
                    .unwrap_or("-")),
                short(&c.command, 100)
            ));
        }
        if list.len() > 25 {
            s.push_str(&dim(&format!("  … and {} more\n", list.len() - 25)));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempTree;

    /// The replay inversion (Tim Schipper, Sep 2026): a transcript call with
    /// no record line is a measured bypass, and the witness says which kind.
    /// Matched by call id when both sides have one, else by session, text
    /// and time; sessions the gate never saw are reported, not accused.
    #[test]
    fn against_record_sorts_calls_into_judged_unrecorded_and_never_fired() {
        let tmp = TempTree::new("against");
        let home = tmp.dir("home");
        let logs = home.join("projects").join("p-1").join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        // The record: one judged by id, one judged by text+time (an older
        // line with no id), in session S. And a witness for a call that has
        // no record line.
        std::fs::write(
            logs.join("audit.jsonl"),
            concat!(
                r#"{"ts_ms":1000000,"ts":"t","source":"hook","command":"git status","decision":"allow","matched_rule":null,"reason":"","signals":[],"escalated":false,"session":"S","cwd":"/p","call_id":"toolu_1"}"#, "\n",
                r#"{"ts_ms":1000000,"ts":"t","source":"hook","command":"rm -rf ./scratch","decision":"deny","matched_rule":"*rm -rf*","reason":"","signals":[],"escalated":false,"session":"S","cwd":"/p"}"#, "\n",
                r#"{"ts_ms":1000000,"ts":"t","source":"post","command":"ls","decision":"allow","matched_rule":null,"reason":"","signals":[],"escalated":false,"session":"S","cwd":"/p"}"#, "\n",
            ),
        )
        .unwrap();
        std::fs::write(
            logs.join("seen.jsonl"),
            concat!(r#"{"ts_ms":1000500,"ts":"t","session":"S","call_id":"toolu_3","command":"python3 crash.py","dialect":"claudecode"}"#, "\n"),
        )
        .unwrap();
        let root = tmp.dir("transcripts");
        let line = |sess: &str, id: &str, cmd: &str, ts: &str| {
            format!(
                r#"{{"type":"assistant","sessionId":"{sess}","timestamp":"{ts}","message":{{"content":[{{"type":"tool_use","id":"{id}","name":"Bash","input":{{"command":"{cmd}"}}}}]}}}}"#
            )
        };
        // 1970-01-01T00:16:40Z is 1,000,000 ms.
        std::fs::write(
            root.join("S.jsonl"),
            [
                line("S", "toolu_1", "git status", "1970-01-01T00:16:40Z"),
                line(
                    "S",
                    "toolu_2",
                    "rm  -rf   ./scratch",
                    "1970-01-01T00:17:00Z",
                ),
                line("S", "toolu_3", "python3 crash.py", "1970-01-01T00:16:41Z"),
                line(
                    "S",
                    "toolu_4",
                    "curl -X DELETE https://x/keys",
                    "1970-01-01T00:16:42Z",
                ),
                line("OLD", "toolu_9", "rm -rf /", "1970-01-01T00:00:01Z"),
            ]
            .join("\n"),
        )
        .unwrap();
        let a = against_record_in(&home, &[root]);
        assert_eq!(a.calls, 5);
        assert_eq!(
            (a.unwired_sessions, a.unwired_calls),
            (1, 1),
            "OLD was never seen by the gate"
        );
        assert_eq!(
            a.judged, 2,
            "by id, and by text and time with whitespace ignored"
        );
        assert_eq!(
            a.fired_unrecorded
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>(),
            vec!["python3 crash.py"]
        );
        assert_eq!(
            a.never_fired
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>(),
            vec!["curl -X DELETE https://x/keys"]
        );
        let out = render_against(&a, &[PathBuf::from("/t")]);
        assert!(
            out.contains("not run"),
            "every bucket renders, so the counts add up: {out}"
        );
        assert!(
            out.contains("never fired") && out.contains("curl -X DELETE"),
            "{out}"
        );
    }

    /// Both transcript shapes yield calls with what they carry: Claude Code's
    /// id and session per line; Codex's call_id and session from the meta.
    #[test]
    fn calls_carry_ids_sessions_and_times_from_both_shapes() {
        let tmp = TempTree::new("calls");
        let c = tmp.file(
            "c.jsonl",
            concat!(
                r#"{"type":"assistant","sessionId":"S","timestamp":"2026-09-30T21:24:55Z","message":{"content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"git status"}}]}}"#, "\n",
                r#"{"type":"user","sessionId":"S","message":{"content":[{"type":"tool_result","content":"ok"}]}}"#, "\n",
            ),
        );
        let calls = calls_in_file(&c);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id.as_deref(), Some("toolu_1"));
        assert_eq!(calls[0].session.as_deref(), Some("S"));
        assert!(calls[0].ts_ms.is_some());
        let x = tmp.file(
            "rollout-1.jsonl",
            concat!(
                r#"{"timestamp":"2026-09-30T21:00:00Z","type":"session_meta","payload":{"id":"X"}}"#, "\n",
                r#"{"timestamp":"2026-09-30T21:00:01Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_7","arguments":"{\"command\":[\"bash\",\"-lc\",\"ls -la\"]}"}}"#, "\n",
            ),
        );
        let calls = calls_in_file(&x);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id.as_deref(), Some("call_7"));
        assert_eq!(calls[0].session.as_deref(), Some("X"));
        assert_eq!(
            calls[0].command, "ls -la",
            "the wrapper is unwrapped to its script"
        );
    }

    /// What the first run on a real machine got wrong (Oct 1, 2026): a
    /// hooks file an agent WROTE is not a call; a call the transcript's own
    /// result says was interrupted never ran, so no hook was due; and
    /// Codex's `powershell.exe -Command` wrapper matches the inner command
    /// the gate recorded.
    #[test]
    fn a_written_file_is_not_a_call_and_an_interrupted_call_is_not_a_bypass() {
        let tmp = TempTree::new("phantoms");
        let c = tmp.file(
            "c.jsonl",
            concat!(
                r#"{"type":"assistant","sessionId":"S","timestamp":"2026-10-01T10:00:00Z","message":{"content":[{"type":"tool_use","id":"toolu_w","name":"Write","input":{"file_path":".claude/settings.json","content":"{\"hooks\":{\"PreToolUse\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"termaxa hook\"}]}]}}"}}]}}"#, "
",
                r#"{"type":"assistant","sessionId":"S","timestamp":"2026-10-01T10:00:01Z","message":{"content":[{"type":"tool_use","id":"toolu_a","name":"Bash","input":{"command":"termaxa log"}},{"type":"tool_use","id":"toolu_b","name":"Bash","input":{"command":"termaxa backups"}}]}}"#, "
",
                r#"{"type":"user","sessionId":"S","timestamp":"2026-10-01T10:00:02Z","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_b","is_error":true,"content":"[Request interrupted by user for tool use]"}]}}"#, "
",
            ),
        );
        let calls = calls_in_file(&c);
        let names: Vec<(&str, bool)> = calls
            .iter()
            .map(|x| (x.command.as_str(), x.executed))
            .collect();
        assert_eq!(
            names,
            vec![("termaxa log", true), ("termaxa backups", false)],
            "{calls:?}"
        );
        let x = tmp.file(
            "rollout-2.jsonl",
            concat!(
                r#"{"timestamp":"2026-09-05T18:49:39Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_1","arguments":"{\"command\":[\"powershell.exe\",\"-Command\",\"echo hi\"]}"}}"#, "
",
            ),
        );
        assert_eq!(calls_in_file(&x)[0].command, "echo hi");
        assert_eq!(
            unwrap_shell(&["bash".into(), "-lc".into(), "ls".into()]).as_deref(),
            Some("ls")
        );
        assert_eq!(
            unwrap_shell(&["C:\\x\\cmd.exe".into(), "/c".into(), "dir".into()]).as_deref(),
            Some("dir")
        );
        assert_eq!(unwrap_shell(&["rm".into(), "-rf".into(), "x".into()]), None);
        // A plain replay tally no longer counts the written file's command.
        assert_eq!(commands_in_file(&c), vec!["termaxa log", "termaxa backups"]);
    }

    /// Both harnesses' shapes, as captured: Claude Code's `input.command`,
    /// Codex's `arguments` string with a `command` array. Non-JSON lines and
    /// lines without a command are skipped; the replay counts and ranks.
    #[test]
    fn a_replay_reads_both_transcript_shapes_and_tallies_by_verdict() {
        let tmp = TempTree::new("replay");
        let root = tmp.dir("transcripts");
        let claude = root.join("proj").join("s1.jsonl");
        std::fs::create_dir_all(claude.parent().unwrap()).unwrap();
        std::fs::write(
            &claude,
            concat!(
                r#"{"type":"user","message":{"role":"user","content":"hi"}}"#, "\n",
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"git status"}}]}}"#, "\n",
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"rm -rf ./scratch"}}]}}"#, "\n",
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"git status"}}]}}"#, "\n",
                "not json at all\n",
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"chmod -R 777 ."}}]}}"#, "\n",
            ),
        )
        .unwrap();
        let codex = root.join("codex").join("rollout-1.jsonl");
        std::fs::create_dir_all(codex.parent().unwrap()).unwrap();
        std::fs::write(
            &codex,
            concat!(
                r#"{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"ls -la\"],\"workdir\":\"/p\"}"}"#, "\n",
                r#"{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"git push --force origin main\"]}"}"#, "\n",
            ),
        )
        .unwrap();
        assert_eq!(transcripts(std::slice::from_ref(&root)).len(), 2);
        let mut cmds = commands_in_file(&codex);
        assert_eq!(cmds.remove(0), "bash -lc \"ls -la\"");

        let starter = Policy::builtin().unwrap();
        let ctx = EvalContext::at(tmp.path());
        let t = replay(&starter, &ctx, std::slice::from_ref(&root));
        assert_eq!((t.transcripts, t.commands), (2, 6));
        assert_eq!((t.allowed, t.asked, t.denied), (3, 1, 2), "{t:?}");
        assert_eq!(t.asks.get("chmod -R 777 .").map(|e| e.0), Some(1));
        assert_eq!(t.denies.get("rm -rf ./scratch").map(|e| e.0), Some(1));
        assert_eq!(
            t.denies
                .get("bash -lc \"git push --force origin main\"")
                .map(|e| e.0),
            Some(1)
        );
        let text = render(&t, &[root], false);
        assert!(
            text.contains("replayed 6 command(s) from 2 transcript(s)"),
            "{text}"
        );
        assert!(text.contains("allow     3  (50%)"), "{text}");
        assert!(text.contains("chmod -R 777 ."), "{text}");
        assert!(text.contains("nothing was executed"), "{text}");
        // A missing root is zero transcripts, not an error.
        let empty = replay(&starter, &ctx, &[tmp.path().join("nowhere")]);
        assert_eq!(empty.commands, 0);
        assert!(render(&empty, &[], false).contains("nothing to replay"));
    }
}
