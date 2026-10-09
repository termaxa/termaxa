//! The Execution Report as a reader actually receives it.
//!
//! `report::run` prints; it returns only an exit code. A unit test can call it
//! and see `Ok(0)` while the whole rendering does nothing at all, so the
//! sections, the counts and the risk line are only really pinned by reading
//! the process' output — the same reason `colour_gate.rs` runs the binary.
//!
//! The log is seeded through the CLI rather than written by hand: that keeps
//! the fixture honest (it is whatever the gate really records) and means this
//! test also fails if `check` stops logging.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

fn termaxa(home: &Path, cwd: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .args(args)
        .current_dir(cwd)
        .env("TERMAXA_HOME", home)
        // The report prints marks and headings; colour would put escape
        // sequences in the middle of the strings asserted below.
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary must be runnable");
    String::from_utf8(out.stdout).expect("output must be UTF-8")
}

/// A scratch tree for one test, cleared before use so a crashed earlier run
/// cannot leak state into this one. Mirrors `probe_inertness.rs`: the pid
/// keeps two concurrent `cargo test` runs apart.
fn scratch(tag: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("termaxa-report-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("home")).expect("scratch root must be creatable");
    base
}

/// A project the gate will accept, plus a home for its state.
fn project(root: &Path) -> std::path::PathBuf {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
    std::fs::write(
        proj.join(".termaxa").join("policy.yaml"),
        "version: 1\ndefault: ask\nrules:\n  - match: \"rm -rf /*\"\n    action: deny\n  - match: \"ls*\"\n    action: allow\n",
    )
    .expect("policy must be writable");
    proj
}

#[test]
fn the_markdown_report_carries_the_counts_and_the_risk_formula() {
    let tmp = scratch("md");
    let home = tmp.join("home");
    let proj = project(&tmp);

    // Three decisions the policy above produces: one deny, two allows.
    termaxa(&home, &proj, &["check", "rm -rf /nonexistent-tmx-fixture"]);
    termaxa(&home, &proj, &["check", "ls -la"]);
    termaxa(&home, &proj, &["check", "ls"]);

    let out = termaxa(&home, &proj, &["report", "--md", "--all"]);

    assert!(
        out.contains("# Termaxa Execution Report"),
        "the report must render at all, got: {out:?}"
    );
    assert!(
        out.contains("- **Commands:** 3 — 2 allow / 0 ask / 1 deny"),
        "the counts line must reflect what was recorded, got: {out:?}"
    );
    assert!(
        out.contains("## Blocked") && out.contains("rm -rf /"),
        "a denied command has to appear under Blocked, got: {out:?}"
    );
    assert!(
        out.contains("Score 3 — transparent formula: deny×3 + escalation×2 + ask×1."),
        "the risk line prints its own inputs so nobody has to trust it, got: {out:?}"
    );
    assert!(
        out.contains("## Risk: Medium"),
        "one deny is three points, which is Medium, got: {out:?}"
    );
    assert!(
        out.contains("## Insurance") && out.contains("No insured operations in scope."),
        "the Insurance section states its absence rather than going missing, got: {out:?}"
    );
    assert!(out.contains("## Last 30 days"), "{out:?}");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn the_terminal_report_renders_the_same_facts_in_its_own_shape() {
    let tmp = scratch("term");
    let home = tmp.join("home");
    let proj = project(&tmp);

    termaxa(&home, &proj, &["check", "rm -rf /nonexistent-tmx-fixture"]);
    termaxa(&home, &proj, &["check", "ls"]);

    let out = termaxa(&home, &proj, &["report", "--all"]);

    assert!(!out.is_empty(), "the terminal report must print something");
    assert!(
        out.contains("rm -rf /"),
        "the blocked command belongs in the report, got: {out:?}"
    );
    assert!(
        out.contains('3') && out.to_lowercase().contains("risk"),
        "the risk score and its label are the point of the summary, got: {out:?}"
    );
    // The markdown heading syntax must NOT leak into the terminal rendering.
    assert!(
        !out.contains("# Termaxa Execution Report"),
        "terminal output should not be markdown, got: {out:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// A project whose breaker trips on the second destructive attempt, so a
/// handful of hook calls is enough to reach the Insight threshold.
fn project_with_a_hair_trigger(root: &Path) -> std::path::PathBuf {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
    std::fs::write(
        proj.join(".termaxa").join("policy.yaml"),
        "version: 1\ndefault: ask\nrules: []\ncircuit_breaker:\n  enabled: true\n  threshold: 1\n",
    )
    .expect("policy must be writable");
    proj
}

/// One PreToolUse hook call. The breaker only exists on this path — it needs
/// a session to count within — so the sections it feeds can only be set up
/// through the hook, not through `check`.
fn hook(home: &Path, proj: &Path, session: &str, command: &str) {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": proj.display().to_string(),
        "session_id": session,
        "tool_input": { "command": command }
    })
    .to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .arg("hook")
        .current_dir(proj)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the binary must be runnable");
    // See cli_surface.rs: a child that exits before reading closes the pipe,
    // and that is its answer rather than a plumbing failure.
    let _ = child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(payload.as_bytes());
    child.wait().expect("the hook must exit");
}

#[test]
fn repeated_blocked_attempts_raise_every_section_they_feed() {
    let tmp = scratch("sections");
    let home = tmp.join("home");
    let proj = project_with_a_hair_trigger(&tmp);

    // Four attempts at the same destructive intent in one session: the first
    // is merely asked about, the rest trip the breaker.
    for _ in 0..4 {
        hook(&home, &proj, "sess-insight", "rm -rf ./build");
    }

    let md = termaxa(&home, &proj, &["report", "--md", "--all"]);
    assert!(
        md.contains("## Destructive intents") && md.contains("**file-delete**"),
        "a classified intent must raise its section, got: {md:?}"
    );
    assert!(
        md.contains("## Impact at intervention points"),
        "an intervention with a preview must raise the impact section, got: {md:?}"
    );
    assert!(
        md.contains("## Insight"),
        "three blocked attempts of one intent is the Insight threshold, got: {md:?}"
    );
    assert!(
        md.contains("- **Top directories:**"),
        "entries carry a cwd, so the rollup has directories to rank, got: {md:?}"
    );

    let term = termaxa(&home, &proj, &["report", "--all"]);
    assert!(term.contains("Destructive intents"), "{term:?}");
    assert!(term.contains("Insight"), "{term:?}");
    assert!(term.contains("Top directories"), "{term:?}");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn a_quiet_session_raises_none_of_those_sections() {
    // The other side of every `if !…is_empty()` guard: absent sections must
    // stay absent rather than printing an empty heading.
    let tmp = scratch("quiet");
    let home = tmp.join("home");
    let proj = project(&tmp);

    termaxa(&home, &proj, &["check", "ls"]);

    let md = termaxa(&home, &proj, &["report", "--md", "--all"]);
    assert!(!md.contains("## Destructive intents"), "{md:?}");
    assert!(!md.contains("## Impact at intervention points"), "{md:?}");
    assert!(!md.contains("## Insight"), "{md:?}");
    assert!(md.contains("## Risk: Low"), "an allow alone is Low: {md:?}");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn the_risk_label_is_coloured_by_its_own_severity() {
    // Under NO_COLOR every label renders identically, so the mapping from
    // label to colour is only observable with colour turned on.
    let tmp = scratch("risk-colour");
    let home = tmp.join("home");
    let proj = project(&tmp);

    let coloured = |args: &[&str]| -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
            .args(args)
            .current_dir(&proj)
            .env("TERMAXA_HOME", &home)
            .env_remove("NO_COLOR")
            .env_remove("TERMAXA_NO_COLOR")
            .env("CLICOLOR_FORCE", "1")
            .output()
            .expect("the binary must be runnable");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    coloured(&["check", "ls"]);
    let low = coloured(&["report", "--all"]);
    assert!(
        low.contains("\x1b[32mLow"),
        "Low risk is green, got: {low:?}"
    );

    coloured(&["check", "rm -rf /nonexistent-tmx-fixture"]);
    let medium = coloured(&["report", "--all"]);
    assert!(
        medium.contains("\x1b[33mMedium"),
        "Medium risk is amber, got: {medium:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Max Petrusenko's field report (Oct 9, 2026): `log` and `report` exited 0
/// on a tampered chain; only `doctor` said "chain broken at entry N". Every
/// reader of the record now says so, with the same sentence, and exits 1.
/// The report carries the warning in its own text, because the markdown is
/// what gets handed to someone; `log --json` keeps its stdout as JSON and
/// says it on stderr.
#[test]
fn log_and_report_say_when_the_chain_does_not_verify() {
    let tmp = scratch("chain");
    let home = tmp.join("home");
    let proj = project(&tmp);
    for c in ["ls -la", "git status", "ls"] {
        hook(&home, &proj, "C", c);
    }
    let run = |args: &[&str]| -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
            .args(args)
            .current_dir(&proj)
            .env("TERMAXA_HOME", &home)
            .env("NO_COLOR", "1")
            .output()
            .expect("the binary must be runnable");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    // Intact: exit 0, no warning anywhere.
    let (code, out, err) = run(&["log"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!err.contains("chain broken"), "{err}");
    let (code, out, _) = run(&["report", "--all"]);
    assert_eq!(code, 0);
    assert!(!out.contains("chain broken"), "{out}");

    // Edit the second entry's command, hash left alone.
    let logs = std::fs::read_dir(home.join("projects"))
        .expect("the project state dir exists")
        .flatten()
        .map(|e| e.path().join("logs").join("audit.jsonl"))
        .find(|p| p.exists())
        .expect("an audit log");
    let raw = std::fs::read_to_string(&logs).unwrap();
    let mut lines: Vec<String> = raw.lines().map(String::from).collect();
    assert!(lines[1].contains("git status"), "{}", lines[1]);
    lines[1] = lines[1].replace("git status", "git stash");
    std::fs::write(&logs, lines.join("\n") + "\n").unwrap();

    let (code, out, err) = run(&["log"]);
    assert_eq!(code, 1, "a broken chain is exit 1: {out}{err}");
    assert!(err.contains("audit chain broken at entry 2"), "{err}");
    assert!(
        out.contains("git stash"),
        "the record is still printed: {out}"
    );
    let (code, out, err) = run(&["log", "--json"]);
    assert_eq!(code, 1);
    assert!(err.contains("audit chain broken at entry 2"), "{err}");
    for l in out.lines() {
        serde_json::from_str::<serde_json::Value>(l).expect("stdout stays JSON");
    }
    let (code, out, _) = run(&["report", "--all"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("audit chain broken at entry 2"), "{out}");
    let (code, out, _) = run(&["report", "--all", "--md"]);
    assert_eq!(code, 1);
    assert!(
        out.starts_with("> ⚠ audit chain broken at entry 2"),
        "the markdown carries the warning first: {out}"
    );
}

#[test]
fn a_home_with_no_log_reports_no_activity() {
    let tmp = scratch("empty");
    let home = tmp.join("home");
    let proj = project(&tmp);

    let out = termaxa(&home, &proj, &["report"]);
    assert!(
        out.contains("(no activity to report)"),
        "an empty log has to say so, got: {out:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
