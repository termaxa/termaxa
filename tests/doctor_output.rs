//! `termaxa doctor` as a reader receives it.
//!
//! doctor's answers depend on the WORLD: which agent directories exist, which
//! agent binaries are on PATH, and whether the registered hook answers when
//! invoked. None of that is reachable from a unit test on a helper, and the
//! function returns an exit code while saying everything else in print.
//!
//! So these drive the binary, and they hand it a PATH containing only a
//! handful of symlinks. That is the load-bearing part: `which("claude")` must
//! answer the same on a machine that happens to have Claude installed as on
//! one that does not, or the test asserts the developer's laptop rather than
//! the code.
//!
//! Liveness IS asserted here, and for a while it could not be. The probe
//! sends `rm -rf /` and waits PROBE_TIMEOUT (2s), and answering that command
//! means walking the filesystem to the delete preview's budget. That budget
//! was consulted only between directories, so one wide directory on a slow
//! mount ran to completion regardless: 5.8-7.1s measured here, the probe
//! timing out, and a correctly gated setup reported as `NOT firing`. With the
//! budget bound inside the directory as well, the same probe answers in
//! roughly 300ms and these tests can say what they mean.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Output {
    stdout: String,
    code: i32,
}

/// Run `termaxa doctor` in `proj`, with a PATH holding only `also` plus a
/// shell (the probe invokes the registered command through one).
fn doctor(home: &Path, proj: &Path, bin_dir: &Path) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .arg("doctor")
        .current_dir(proj)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .env("PATH", bin_dir)
        .output()
        .expect("the binary must be runnable");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("termaxa-doctor-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("home")).expect("scratch root must be creatable");
    base
}

/// A PATH directory holding a shell (the probe invokes through one) and
/// `which` (doctor asks it whether a tool exists), and nothing else. Agent
/// binaries are absent by construction, so their detection comes down to
/// exactly what each test puts here.
fn controlled_path(root: &Path) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir must be creatable");
    for tool in ["sh", "which"] {
        let real = ["/bin", "/usr/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("{tool} must exist somewhere standard"));
        std::os::unix::fs::symlink(&real, bin.join(tool)).expect("symlink must be creatable");
    }
    bin
}

/// A stub executable on the controlled PATH, so "this agent's CLI is
/// installed" becomes a fact the test sets rather than one it inherits.
fn stub_tool(bin: &Path, name: &str) {
    let path = bin.join(name);
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("stub must be writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("stub must be executable");
}

fn project(root: &Path, policy: &str) -> PathBuf {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
    std::fs::write(proj.join(".termaxa").join("policy.yaml"), policy)
        .expect("policy must be writable");
    proj
}

const DENIES: &str =
    "version: 1\ndefault: ask\nrules:\n  - match: \"rm -rf /*\"\n    action: deny\n";

/// Register the real test binary as the hook, in each agent's own shape.
fn wire_claude(proj: &Path) {
    let dir = proj.join(".claude");
    std::fs::create_dir_all(&dir).expect("agent dir must be creatable");
    std::fs::write(
        dir.join("settings.json"),
        serde_json::json!({
            "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
                { "type": "command", "command": format!("{} hook", env!("CARGO_BIN_EXE_termaxa")) }
            ] } ] }
        })
        .to_string(),
    )
    .expect("settings must be writable");
}

fn wire_copilot(proj: &Path) {
    let dir = proj.join(".github").join("hooks");
    std::fs::create_dir_all(&dir).expect("agent dir must be creatable");
    std::fs::write(
        dir.join("hooks.json"),
        serde_json::json!({
            "version": 1,
            "hooks": { "preToolUse": [
                { "type": "command", "command": format!("{} hook", env!("CARGO_BIN_EXE_termaxa")),
                  "failClosed": true }
            ] }
        })
        .to_string(),
    )
    .expect("hooks must be writable");
}

#[test]
fn a_directory_with_nothing_in_it_is_reported_as_such() {
    let tmp = scratch("bare");
    let bin = controlled_path(&tmp);
    let empty = tmp.join("empty");
    std::fs::create_dir_all(&empty).expect("dir must be creatable");

    let out = doctor(&tmp.join("home"), &empty, &bin);
    assert_eq!(out.code, 1, "a missing policy is something to fix");
    assert!(
        out.stdout.contains("no .termaxa/policy.yaml"),
        "{:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("no agent harness detected"),
        "with no agent directory and no agent binary, there is no harness: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("run `termaxa init`"),
        "{:?}",
        out.stdout
    );
}

#[test]
fn an_initialised_project_without_an_agent_has_nothing_to_fix() {
    let tmp = scratch("clean");
    let bin = controlled_path(&tmp);
    let proj = project(&tmp, DENIES);
    // `init` records the policy baseline, which is the remaining problem in
    // an otherwise healthy tree. It runs on the same controlled PATH as
    // `doctor` below: with the developer's PATH it found a `claude` on a box
    // that has one, wired the hook, and `doctor`, which cannot see that
    // `claude`, reported the hook as not firing (roadmap §2d item 5).
    Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .arg("init")
        .current_dir(&proj)
        .env("TERMAXA_HOME", tmp.join("home"))
        .env("NO_COLOR", "1")
        .env("PATH", &bin)
        .output()
        .expect("the binary must be runnable");

    let out = doctor(&tmp.join("home"), &proj, &bin);
    assert_eq!(out.code, 0, "nothing left to fix: {:?}", out.stdout);
    assert!(
        out.stdout.contains("Everything checks out"),
        "{:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("no agent harness detected"),
        "no agent directory and no agent binary means no harness: {:?}",
        out.stdout
    );
}

#[test]
fn a_wired_hook_reports_as_live_and_leaves_nothing_to_fix() {
    let tmp = scratch("live");
    let bin = controlled_path(&tmp);
    let proj = project(&tmp, DENIES);
    wire_claude(&proj);
    Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .arg("init")
        .current_dir(&proj)
        .env("TERMAXA_HOME", tmp.join("home"))
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary must be runnable");

    let out = doctor(&tmp.join("home"), &proj, &bin);
    assert!(
        out.stdout.contains("hook configured and live"),
        "the registered command answered when doctor invoked it: {:?}",
        out.stdout
    );
    // The policy denies `rm -rf /`, so the permissiveness note stays quiet.
    assert!(!out.stdout.contains("does not deny"), "{:?}", out.stdout);
    assert_eq!(out.code, 0, "nothing to fix: {:?}", out.stdout);
}

#[test]
fn a_live_hook_over_a_policy_that_denies_nothing_is_flagged() {
    // Live means "answered when doctor invoked it", which is not the same as
    // "will stop anything". A green tick over a policy that denies nothing is
    // worth one more line.
    let tmp = scratch("permissive");
    let bin = controlled_path(&tmp);
    let proj = project(&tmp, "version: 1\ndefault: allow\nrules: []\n");
    wire_claude(&proj);

    let out = doctor(&tmp.join("home"), &proj, &bin);
    assert!(
        out.stdout.contains("hook configured and live"),
        "{:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("does not deny `rm -rf /`"),
        "a gate that stops nothing has to say so next to its tick: {:?}",
        out.stdout
    );
}

#[test]
fn each_agent_is_detected_by_its_own_evidence() {
    // Claude Code and Cursor by their directories; Copilot by its CLI being
    // on PATH together with a registration. None of those binaries exist on
    // this PATH unless the test puts them there, so what is asserted is the
    // detection rule rather than the machine the suite runs on.
    let tmp = scratch("agents");
    let bin = controlled_path(&tmp);
    let proj = project(&tmp, DENIES);
    // Directories only for the two that are detected by one: a registration
    // would add a liveness probe, and each probe costs its whole timeout.
    std::fs::create_dir_all(proj.join(".claude")).expect("agent dir must be creatable");
    std::fs::create_dir_all(proj.join(".cursor")).expect("agent dir must be creatable");
    wire_copilot(&proj);
    stub_tool(&bin, "gh");

    let out = doctor(&tmp.join("home"), &proj, &bin);
    // The agent LINE and its state, not the bare name: every name also appears
    // in the list of things to fix, so `contains("Cursor")` is satisfied by the
    // output of NOT detecting it. Each agent here is detected a different way
    // and lands in a different state, and the assertion says which.
    for agent in ["Claude Code", "Cursor"] {
        assert!(
            out.stdout
                .contains(&format!("{agent:<13}detected, hook NOT configured")),
            "{agent} is detected by its directory alone, and is not wired: {:?}",
            out.stdout
        );
    }
    assert!(
        out.stdout
            .contains(&format!("{:<13}hook configured and live", "Copilot CLI")),
        "Copilot is detected by gh on PATH plus a registration, and that \
         registration answers: {:?}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("no agent harness detected"),
        "{:?}",
        out.stdout
    );
    // Cursor is detected here but not registered, and the restart advice
    // only makes sense once there is a registration to restart into.
    assert!(
        !out.stdout.contains("restart Cursor"),
        "nothing was wired, so there is nothing to restart for: {:?}",
        out.stdout
    );
}

#[test]
fn a_wired_cursor_is_told_to_restart() {
    // The counterpart to the silence asserted above. Without this, deleting
    // the hint from doctor entirely would break no test: an absence is only
    // meaningful next to a presence.
    let tmp = scratch("cursor-wired");
    let bin = controlled_path(&tmp);
    let proj = project(&tmp, DENIES);
    let dir = proj.join(".cursor");
    std::fs::create_dir_all(&dir).expect("agent dir must be creatable");
    std::fs::write(
        dir.join("hooks.json"),
        serde_json::json!({
            "beforeShellExecution": [
                { "command": format!("{} hook", env!("CARGO_BIN_EXE_termaxa")) }
            ]
        })
        .to_string(),
    )
    .expect("hooks must be writable");

    let out = doctor(&tmp.join("home"), &proj, &bin);
    assert!(
        out.stdout.contains("restart Cursor"),
        "a registration Cursor has not reloaded is a hook that does not fire: {:?}",
        out.stdout
    );
}

#[test]
fn a_hook_that_has_already_run_silences_the_warning() {
    // The warning pairs "an agent is present" with "the gate has never seen
    // one of its commands". Once an agent has actually reached the gate,
    // repeating it would be noise on a healthy install.
    let tmp = scratch("hooked");
    let bin = controlled_path(&tmp);
    let home = tmp.join("home");
    let proj = project(&tmp, DENIES);
    std::fs::create_dir_all(proj.join(".claude")).expect("agent dir must be creatable");

    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": proj.display().to_string(),
        "session_id": "sess-doctor",
        "tool_input": { "command": "ls -la" }
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .arg("hook")
        .current_dir(&proj)
        .env("TERMAXA_HOME", &home)
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the binary must be runnable");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("stdin must be piped")
            .write_all(payload.as_bytes())
            .expect("the payload must be writable");
    }
    child.wait().expect("the hook must exit");

    let out = doctor(&home, &proj, &bin);
    assert!(
        out.stdout.contains("audit entries (1 from hooks)"),
        "the entry came from a hook, and the count says which: {:?}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("no hook entries yet"),
        "the gate has seen an agent command, so the warning must stop: {:?}",
        out.stdout
    );
}

#[test]
fn an_unregistered_agent_directory_is_reported_as_not_wired() {
    // The directory is evidence the harness exists; the registration is a
    // separate question, and conflating them is how a green tick ends up
    // over an ungated session.
    let tmp = scratch("unwired");
    let bin = controlled_path(&tmp);
    let proj = project(&tmp, DENIES);
    std::fs::create_dir_all(proj.join(".claude")).expect("agent dir must be creatable");

    let out = doctor(&tmp.join("home"), &proj, &bin);
    assert!(
        out.stdout.contains(&format!(
            "{:<13}detected, hook NOT configured",
            "Claude Code"
        )),
        "{:?}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("no agent harness detected"),
        "the directory alone is enough to detect the harness: {:?}",
        out.stdout
    );
    assert_eq!(out.code, 1, "an unwired agent is something to fix");
}

#[test]
fn the_log_line_separates_hook_entries_from_the_rest() {
    let tmp = scratch("log");
    let bin = controlled_path(&tmp);
    let home = tmp.join("home");
    let proj = project(&tmp, DENIES);
    wire_claude(&proj);

    // A `check` is an audit entry, but it is not an agent reaching the gate.
    Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .args(["check", "rm -rf /nonexistent-tmx-fixture"])
        .current_dir(&proj)
        .env("TERMAXA_HOME", &home)
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary must be runnable");

    let out = doctor(&home, &proj, &bin);
    assert!(
        out.stdout.contains("audit entries (0 from hooks)"),
        "a check is not a hook entry: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("no hook entries yet"),
        "an agent is wired and has never reached the gate, which is the \
         pairing worth warning about: {:?}",
        out.stdout
    );
}
