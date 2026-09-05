//! The Codex dialect as Codex actually speaks it.
//!
//! Every payload here is the shape captured live on Sep 5, 2026 (codex-cli
//! 0.153.4, Windows 11, PowerShell) with `TERMAXA_HOOK_DEBUG` — the first
//! real Codex session under the gate. Three things that session measured,
//! each pinned below:
//!
//! - Codex sends no `agent` or `source` tag. Its payload is the Claude Code
//!   shape plus `turn_id`, `model`, `permission_mode` and a transcript under
//!   `~/.codex/sessions`. Before this, the hook read it as Claude Code.
//! - Codex accepts exactly one PreToolUse verdict: `deny`. An explicit
//!   `allow` failed the hook ("unsupported permissionDecision:allow") and so
//!   did `ask`; a failed hook falls open to Codex's own prompt.
//! - A Termaxa deny, which exits 2 by design, reached Codex as "hook exited
//!   with code 1" — a failed hook, fail-open. The JSON on stdout is the
//!   channel Codex documents; for Codex the exit code stays 0.
//!
//! No `sh` is spawned, so this binary runs on every platform, Windows
//! included.

use std::path::Path;
use std::process::{Command, Stdio};

struct Out {
    stdout: String,
    stderr: String,
    code: i32,
}

fn termaxa(home: &Path, cwd: &Path, args: &[&str], stdin: &str) -> Out {
    use std::io::Write as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .args(args)
        .current_dir(cwd)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .env_remove("TERMAXA_HOOK_DEBUG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary must be runnable");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("stdin must be writable");
    let out = child.wait_with_output().expect("the binary must finish");
    Out {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// A scratch tree for one test, cleared before use so a crashed earlier run
/// cannot leak state into this one. The pid keeps two concurrent `cargo
/// test` runs apart.
fn scratch(tag: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("termaxa-codex-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("home")).expect("scratch root must be creatable");
    base
}

/// A project with a policy that names all three verdicts.
fn project(root: &Path) -> std::path::PathBuf {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
    std::fs::write(
        proj.join(".termaxa").join("policy.yaml"),
        "version: 1\ndefault: ask\nrules:\n  - match: \"rm -rf *\"\n    action: deny\n  - match: \"echo *\"\n    action: allow\n",
    )
    .expect("policy must be writable");
    proj
}

/// The captured payload, with the command and cwd of this test substituted.
/// Field names, order and the shape of every other value are as Codex sent
/// them; the ids are the real ones from the capture.
fn codex_payload(cwd: &Path, command: &str) -> String {
    let transcript = Path::new(".codex")
        .join("sessions")
        .join("2026")
        .join("09")
        .join("06")
        .join("rollout-2026-09-06T00-17-37-01a072e5-c9e6-7a42-97e9-df793d788aa9.jsonl");
    serde_json::json!({
        "session_id": "01a072e5-c9e6-7a42-97e9-df793d788aa9",
        "turn_id": "01a07361-cac3-7c61-ae64-517f324918d4",
        "transcript_path": transcript.display().to_string(),
        "cwd": cwd.display().to_string(),
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-terra",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": "exec-e8bb082d-094f-4e7b-b222-f852e21a06fd"
    })
    .to_string()
}

/// The same command in Claude Code's shape: no `turn_id`, no `model`.
fn claude_payload(cwd: &Path, command: &str) -> String {
    serde_json::json!({
        "session_id": "s-claude",
        "cwd": cwd.display().to_string(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

#[test]
fn a_matched_allow_is_silence_for_codex_and_an_explicit_allow_for_claude_code() {
    let tmp = scratch("allow");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    let out = termaxa(&home, &proj, &["hook"], &codex_payload(&proj, "echo hi"));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.trim().is_empty(),
        "Codex rejects an explicit allow; silence is the allow: {}",
        out.stdout
    );
    let out = termaxa(&home, &proj, &["hook"], &claude_payload(&proj, "echo hi"));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("\"permissionDecision\":\"allow\""),
        "Claude Code still gets the explicit allow for a matched rule: {}",
        out.stdout
    );
}

#[test]
fn an_ask_is_rendered_as_a_deny_that_says_the_gate_asked() {
    let tmp = scratch("ask");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    let out = termaxa(&home, &proj, &["hook"], &codex_payload(&proj, "make lint"));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("\"permissionDecision\":\"deny\""),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("asks:"),
        "the reason says the gate asked: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("allow rule"),
        "the reason says how to proceed: {}",
        out.stdout
    );
    // The audit log keeps what the policy decided, not what Codex was told.
    let log = termaxa(&home, &proj, &["log"], "");
    assert!(log.stdout.contains("make lint"), "{}", log.stdout);
    assert!(
        log.stdout
            .contains("no rule matched; policy default is `ask`"),
        "{}",
        log.stdout
    );
}

#[test]
fn a_deny_exits_zero_for_codex_and_two_for_claude_code() {
    let tmp = scratch("deny");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    std::fs::create_dir_all(proj.join("scratch")).unwrap();
    std::fs::write(proj.join("scratch").join("a.txt"), "x").unwrap();
    let out = termaxa(
        &home,
        &proj,
        &["hook"],
        &codex_payload(&proj, "rm -rf ./scratch"),
    );
    assert_eq!(
        out.code, 0,
        "the wrapper Codex runs hooks through flattens a non-zero exit to 1, which Codex reads as a failed hook: {}",
        out.stderr
    );
    assert!(
        out.stdout.contains("\"permissionDecision\":\"deny\""),
        "{}",
        out.stdout
    );
    assert!(
        proj.join("scratch").join("a.txt").exists(),
        "a hook decides; it does not execute"
    );
    let out = termaxa(
        &home,
        &proj,
        &["hook"],
        &claude_payload(&proj, "rm -rf ./scratch"),
    );
    assert_eq!(
        out.code, 2,
        "Claude Code keeps the belt under the JSON: {}",
        out.stderr
    );
    assert!(
        out.stdout.contains("\"permissionDecision\":\"deny\""),
        "{}",
        out.stdout
    );
}

#[test]
fn init_writes_the_hooks_file_codex_reads() {
    let tmp = scratch("init");
    let home = tmp.join("home");
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let out = termaxa(&home, &proj, &["init", "--codex"], "");
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let path = proj.join(".codex").join("hooks.json");
    let bytes = std::fs::read(&path).expect("init --codex writes .codex/hooks.json");
    assert_eq!(
        bytes[0], b'{',
        "no byte-order mark: Codex refuses a file that starts with one"
    );
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let group = &v["hooks"]["PreToolUse"][0];
    assert_eq!(group["matcher"], "Bash", "{v}");
    let hook = &group["hooks"][0];
    assert_eq!(hook["type"], "command", "{v}");
    assert_eq!(hook["command"], "termaxa hook", "{v}");
    assert!(hook["timeout"].is_number(), "timeout is in seconds: {v}");
    assert!(
        v.get("version").is_none(),
        "the flat pre-Sep-2026 shape with a top-level version was never one Codex read: {v}"
    );
}
