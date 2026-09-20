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
                } else {
                    commands_in(val, out);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| commands_in(i, out)),
        serde_json::Value::String(s) if s.trim_start().starts_with('{') => {
            if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s) {
                commands_in(&inner, out);
            }
        }
        _ => {}
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
pub fn run(paths: Vec<PathBuf>, all: bool) -> Result<i32> {
    let roots = if paths.is_empty() {
        default_roots()
    } else {
        paths
    };
    if roots.is_empty() {
        anyhow::bail!("no transcript directories given and no home directory to look under");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempTree;

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
