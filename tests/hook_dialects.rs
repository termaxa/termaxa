//! `termaxa hook` against each agent's own payload shape.
//!
//! This is the path every gated command actually takes, and almost none of it
//! is reachable from a unit test: it reads stdin, resolves paths from the
//! payload, writes state, prints one dialect's JSON and exits with a code the
//! harness reads. So these run the binary and read what a harness would.
//!
//! The dialect matters as much as the verdict. A correct deny rendered in the
//! wrong shape is a deny nobody receives.

#![cfg(unix)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Out {
    stdout: String,
    code: i32,
}

fn hook(home: &Path, cwd: &Path, payload: &serde_json::Value, env: &[(&str, &str)]) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_termaxa"));
    cmd.arg("hook")
        .current_dir(cwd)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .env_remove("TERMAXA_HOOK_PROBE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("the binary must be runnable");
    // The hook reads its payload to EOF, but a build that fails earlier exits
    // first and closes the pipe under this write. Let the assertions report
    // that rather than an EPIPE from the plumbing.
    let _ = child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(payload.to_string().as_bytes());
    let out = child.wait_with_output().expect("the hook must exit");
    Out {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("termaxa-hookd-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("home")).expect("scratch root must be creatable");
    base
}

const DENIES: &str =
    "version: 1\ndefault: ask\nrules:\n  - match: \"rm -rf /*\"\n    action: deny\n";

/// A policy that denies something harmless. The built-in starter policy denies
/// `rm -rf` too, so a test asking "which policy answered?" cannot use it: both
/// the project's and the fallback's would say deny and the question would go
/// unasked. Nothing built in objects to `echo`.
const DENIES_AN_ECHO: &str =
    "version: 1\ndefault: ask\nrules:\n  - match: \"echo tmx-marker*\"\n    action: deny\n";
const PROJECT_ONLY: &str = "echo tmx-marker";

fn project(root: &Path, policy: &str) -> PathBuf {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
    std::fs::write(proj.join(".termaxa").join("policy.yaml"), policy)
        .expect("policy must be writable");
    proj
}

/// A command the fixture policy denies, and one it merely asks about.
const DENIED: &str = "rm -rf /nonexistent-tmx-fixture";

// ---------------------------------------------------------------------------
// Dialect detection. The response shape is how the harness learns the verdict.
// ---------------------------------------------------------------------------

fn is_claude_shape(out: &str) -> bool {
    out.contains("hookSpecificOutput") && out.contains("permissionDecision")
}

fn is_cursor_shape(out: &str) -> bool {
    out.contains("\"permission\"")
}

#[test]
fn cursor_is_recognised_by_its_tool_name_and_conversation_together() {
    let tmp = scratch("cursor-pair");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES));

    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "conversation_id": "conv-1",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": DENIED }
        }),
        &[],
    );
    assert!(
        is_cursor_shape(&out.stdout),
        "Shell plus a conversation id is Cursor: {:?}",
        out.stdout
    );

    // Either half alone is not Cursor. `Shell` without a conversation, and a
    // conversation with an ordinary tool name, both belong to Claude Code.
    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": DENIED }
        }),
        &[],
    );
    assert!(
        is_claude_shape(&out.stdout),
        "Shell alone is not Cursor: {:?}",
        out.stdout
    );

    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "conversation_id": "conv-1",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": DENIED }
        }),
        &[],
    );
    assert!(
        is_claude_shape(&out.stdout),
        "a conversation id with a Bash tool is not Cursor: {:?}",
        out.stdout
    );
}

#[test]
fn copilot_is_recognised_by_every_shell_tool_it_names() {
    let tmp = scratch("copilot");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES));

    // `powershell` is the name Copilot CLI actually sent on Windows (captured
    // Sep 9, 2026); the other three are the documented ones. A Copilot deny
    // is exit 0 with the verdict in the JSON: Copilot reads a non-zero exit
    // as "(hook errored)", which failClosed still blocks but with the reason
    // lost - so the gate is asserted through stdout here, not the exit code.
    for tool in [
        "shell",
        "bash",
        "run_in_terminal",
        "powershell",
        "pwsh",
        "cmd",
    ] {
        let out = hook(
            &home,
            &proj,
            &serde_json::json!({
                "hook_event_name": "PreToolUse",
                "toolName": tool,
                "toolArgs": serde_json::json!({ "command": DENIED }).to_string(),
                "cwd": proj.display().to_string(),
            }),
            &[],
        );
        assert_eq!(
            out.code, 0,
            "{tool}: Copilot must not see a non-zero exit: {:?}",
            out.stdout
        );
        assert!(
            out.stdout.contains("\"permissionDecision\":\"deny\""),
            "{tool} must be gated: {:?}",
            out.stdout
        );
    }

    // A tool that does not run a shell is not a shell, even carrying a command.
    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "toolName": "read_file",
            "toolArgs": serde_json::json!({ "command": DENIED }).to_string(),
            "cwd": proj.display().to_string(),
        }),
        &[],
    );
    assert_ne!(
        out.code, 2,
        "reading a file is not running one: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// The cwd the payload carries. The agent may spawn the hook anywhere.
// ---------------------------------------------------------------------------

#[test]
fn the_payload_cwd_decides_the_project_not_where_the_hook_was_spawned() {
    // The Cursor bug: Claude Code happened to spawn hooks inside the project,
    // which masked the assumption until another harness did not.
    let tmp = scratch("cwd-payload");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES_AN_ECHO));
    let elsewhere = tmp.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("dir must be creatable");

    let out = hook(
        &home,
        &elsewhere,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": PROJECT_ONLY }
        }),
        &[],
    );
    assert!(
        out.stdout.contains("\"deny\""),
        "the project named in the payload is the one that governs: {:?}",
        out.stdout
    );
    // Asserting the code alone would not do: a hook that resolved no policy
    // at all also exits 2, so the verdict has to be read from stdout.
    assert_eq!(out.code, 2);
}

#[test]
fn a_cwd_that_is_not_a_directory_falls_back_instead_of_being_trusted() {
    // A path that does not exist is not a project root, and resolving from it
    // would find no policy at all. Falling back to where the process is keeps
    // this project's rules in force.
    let tmp = scratch("cwd-bogus");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES_AN_ECHO));

    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": "/nonexistent-tmx-cwd",
            "tool_input": { "command": PROJECT_ONLY }
        }),
        &[],
    );
    assert!(
        out.stdout.contains("\"deny\""),
        "a cwd that is not a directory must not be trusted over the fallback: {:?}",
        out.stdout
    );
    assert_eq!(out.code, 2);
}

/// Every audit line recorded under any project in this home.
fn project_logs(home: &Path) -> String {
    let mut all = String::new();
    if let Ok(projects) = std::fs::read_dir(home.join("projects")) {
        for p in projects.flatten() {
            if let Ok(text) = std::fs::read_to_string(p.path().join("logs").join("audit.jsonl")) {
                all.push_str(&text);
            }
        }
    }
    all
}

#[test]
fn a_post_receipt_is_recorded_against_the_project_the_payload_names() {
    // A receipt carries no verdict, so where it is FILED is the whole of its
    // behaviour: a receipt written to the wrong project is a receipt the
    // report will never show.
    let tmp = scratch("post-cwd");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES_AN_ECHO));
    let elsewhere = tmp.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("dir must be creatable");

    hook(
        &home,
        &elsewhere,
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": "echo tmx-receipt" }
        }),
        &[],
    );

    let logs = project_logs(&home);
    assert!(
        logs.contains("tmx-receipt") && logs.contains("\"post\""),
        "the receipt belongs to the project the payload named: {logs:?}"
    );

    // And a cwd that cannot be used falls back rather than being trusted. A
    // receipt filed nowhere is one the breaker never sees, which is the whole
    // reason post receipts exist: they are what marks work as approved.
    let tmp = scratch("post-cwd-bogus");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES_AN_ECHO));
    hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "cwd": "/nonexistent-tmx-cwd",
            "tool_input": { "command": "echo tmx-fallback-receipt" }
        }),
        &[],
    );
    assert!(
        project_logs(&home).contains("tmx-fallback-receipt"),
        "the fallback is what keeps the receipt auditable"
    );
}

#[test]
fn a_refused_write_is_recorded_against_the_project_the_payload_names() {
    // Same question for the write path: a deny that went unrecorded is still
    // a deny, but it is one nobody can audit afterwards.
    let tmp = scratch("write-cwd");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES_AN_ECHO));
    let elsewhere = tmp.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("dir must be creatable");
    let policy = proj.join(".termaxa").join("policy.yaml");

    let out = hook(
        &home,
        &elsewhere,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "cwd": proj.display().to_string(),
            "tool_input": { "file_path": policy.display().to_string(), "content": "default: allow" }
        }),
        &[],
    );
    assert!(out.stdout.contains("\"deny\""), "{:?}", out.stdout);

    let logs = project_logs(&home);
    assert!(
        logs.contains("policy.yaml"),
        "the refusal belongs in the audit log of the project it protected: {logs:?}"
    );

    // And with a cwd that cannot be used, the record still lands: the refusal
    // is printed either way, so only the log says whether the fallback worked.
    let tmp = scratch("write-cwd-bogus");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES_AN_ECHO));
    let policy = proj.join(".termaxa").join("policy.yaml");
    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "cwd": "/nonexistent-tmx-cwd",
            "tool_input": { "file_path": policy.display().to_string(), "content": "default: allow" }
        }),
        &[],
    );
    assert!(out.stdout.contains("\"deny\""), "{:?}", out.stdout);
    assert!(
        project_logs(&home).contains("policy.yaml"),
        "the fallback is what makes the refusal auditable"
    );
}

// ---------------------------------------------------------------------------
// Silence, answers, and the exit code the harness reads.
// ---------------------------------------------------------------------------

#[test]
fn a_denied_command_answers_and_exits_two() {
    let tmp = scratch("deny");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES));

    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": DENIED }
        }),
        &[],
    );
    assert!(out.stdout.contains("\"deny\""), "{:?}", out.stdout);
    assert_eq!(out.code, 2, "the exit code is the belt to stdout's braces");
}

#[test]
fn an_unmatched_allow_says_nothing_at_all_to_claude_code() {
    // decline-not-allow: where no rule matched and the default is allow, the
    // gate has formed no opinion, and saying "allow" would assert one.
    let tmp = scratch("silent");
    let (home, proj) = (
        tmp.join("home"),
        project(&tmp, "version: 1\ndefault: allow\nrules: []\n"),
    );

    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": "ls -la" }
        }),
        &[],
    );
    assert!(
        out.stdout.trim().is_empty(),
        "no opinion means no output: {:?}",
        out.stdout
    );
    assert_eq!(out.code, 0);

    // A probe is the exception: doctor cannot tell silence from a dead hook.
    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "session_id": "termaxa-doctor-probe",
            "tool_input": { "command": "ls -la" }
        }),
        &[("TERMAXA_HOOK_PROBE", "1")],
    );
    assert!(
        !out.stdout.trim().is_empty(),
        "a probe must always answer: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// Insurance, and who is allowed to cause it.
// ---------------------------------------------------------------------------

fn backup_count(home: &Path) -> usize {
    let mut n = 0;
    if let Ok(projects) = std::fs::read_dir(home.join("projects")) {
        for p in projects.flatten() {
            if let Ok(entries) = std::fs::read_dir(p.path().join("backups")) {
                n += entries.flatten().count();
            }
        }
    }
    n
}

#[test]
fn insurance_is_taken_for_what_runs_and_for_nothing_else() {
    let tmp = scratch("insure");
    // A narrow deny: `rm -rf /*` would match every absolute path, including
    // the one this test is about to insure.
    let (home, proj) = (
        tmp.join("home"),
        project(
            &tmp,
            "version: 1\ndefault: ask\nrules:\n  - match: \"*doomed-denied*\"\n    action: deny\n",
        ),
    );
    let doomed = proj.join("doomed.txt");
    let denied_file = proj.join("doomed-denied.txt");

    let ask_to_delete = |file: &Path| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": format!("rm -rf {}", file.display()) }
        })
    };

    // A command that will run is insured first.
    std::fs::write(&doomed, "precious").expect("file must be writable");
    let out = hook(&home, &proj, &ask_to_delete(&doomed), &[]);
    assert_ne!(out.code, 2, "the fixture policy only denies rm -rf /*");
    assert!(
        backup_count(&home) > 0,
        "an insurable command that is about to run gets a backup"
    );

    // A probe runs nothing, so it insures nothing.
    let before = backup_count(&home);
    hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "session_id": "termaxa-doctor-probe",
            "tool_input": { "command": format!("rm -rf {}", doomed.display()) }
        }),
        &[("TERMAXA_HOOK_PROBE", "1")],
    );
    assert_eq!(
        backup_count(&home),
        before,
        "a probe must not cause insurance: nothing is going to happen"
    );

    // A denied command runs nothing either. The file exists, so the only
    // reason not to insure it is that nothing is going to happen to it.
    std::fs::write(&denied_file, "precious").expect("file must be writable");
    let before = backup_count(&home);
    let out = hook(&home, &proj, &ask_to_delete(&denied_file), &[]);
    assert_eq!(out.code, 2, "the fixture denies this one: {:?}", out.stdout);
    assert_eq!(
        backup_count(&home),
        before,
        "insuring a blocked command is insurance against nothing"
    );
}

// ---------------------------------------------------------------------------
// A denied command must not cause a subprocess (v0.14.2), on the hook path.
// ---------------------------------------------------------------------------

#[test]
fn a_denied_command_never_runs_its_preview() {
    let tmp = scratch("inert");
    let home = tmp.join("home");
    let proj = project(
        &tmp,
        "version: 1\ndefault: ask\nrules:\n  - match: \"terraform destroy*\"\n    action: deny\n",
    );
    let bin_dir = tmp.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("bin dir must be creatable");
    let marker = tmp.join("plan-was-run");
    let stub = bin_dir.join("terraform");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\ntouch '{}'\necho 'Plan: 0 to add, 0 to change, 1 to destroy.'\n",
            marker.display()
        ),
    )
    .expect("stub must be writable");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
        .expect("stub must be executable");

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let denied = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": "terraform destroy -auto-approve" }
        }),
        &[("PATH", &path)],
    );
    assert_eq!(denied.code, 2, "{:?}", denied.stdout);
    assert!(
        !marker.exists(),
        "denying is what used to make it run the plan"
    );

    // Not denied, so the preview is allowed to do its work.
    hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "tool_input": { "command": "terraform apply" }
        }),
        &[("PATH", &path)],
    );
    assert!(
        marker.exists(),
        "an undenied command still gets a live preview"
    );
}

// ---------------------------------------------------------------------------
// The write path: the gate's own files.
// ---------------------------------------------------------------------------

#[test]
fn writing_to_the_gates_own_configuration_is_denied_in_every_dialect() {
    let tmp = scratch("write");
    let (home, proj) = (tmp.join("home"), project(&tmp, DENIES));
    let policy = proj.join(".termaxa").join("policy.yaml");

    // Claude Code shape.
    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "cwd": proj.display().to_string(),
            "tool_input": { "file_path": policy.display().to_string(), "content": "default: allow" }
        }),
        &[],
    );
    assert!(is_claude_shape(&out.stdout), "{:?}", out.stdout);
    assert!(out.stdout.contains("\"deny\""), "{:?}", out.stdout);

    // Cursor identifies itself by its conversation id alone here.
    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "conversation_id": "conv-9",
            "cwd": proj.display().to_string(),
            "tool_input": { "file_path": policy.display().to_string(), "content": "default: allow" }
        }),
        &[],
    );
    assert!(
        is_cursor_shape(&out.stdout),
        "a conversation id is enough to know the dialect: {:?}",
        out.stdout
    );

    // An ordinary file is not the gate's business, and it says nothing.
    let out = hook(
        &home,
        &proj,
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "cwd": proj.display().to_string(),
            "tool_input": { "file_path": proj.join("src.rs").display().to_string(), "content": "x" }
        }),
        &[],
    );
    assert!(
        out.stdout.trim().is_empty(),
        "no opinion about ordinary files: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// The circuit breaker, and the commands it must not press against.
// ---------------------------------------------------------------------------

#[test]
fn an_ungated_overwrite_neither_accumulates_pressure_nor_trips_on_it() {
    // Agents redirect constantly. A default-ask `cargo build > build.log` is
    // the policy having no opinion, and if the breaker counted those, the
    // third build log of any real session would be denied. The pressure here
    // is real and belongs to another command entirely.
    let tmp = scratch("breaker");
    let home = tmp.join("home");
    let proj = project(
        &tmp,
        "version: 1\ndefault: ask\nrules:\n  - match: \"*secret.env*\"\n    action: ask\n\
         circuit_breaker:\n  enabled: true\n  threshold: 2\n",
    );

    let overwrite = |command: &str| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": proj.display().to_string(),
            "session_id": "sess-breaker",
            "tool_input": { "command": command }
        })
    };

    // Three attempts at the same GATED overwrite: a rule matched each one, so
    // each is pressure the breaker is meant to feel.
    let mut last = 0;
    for _ in 0..3 {
        last = hook(&home, &proj, &overwrite("echo x > secret.env"), &[]).code;
    }
    assert_eq!(
        last, 2,
        "three gated attempts past a threshold of two is what a breaker is for"
    );

    // Now an overwrite no rule objected to. It must neither be judged by the
    // pressure above nor add to it.
    let out = hook(&home, &proj, &overwrite("cargo build > build.log"), &[]);
    assert_ne!(
        out.code, 2,
        "a build log is not the .env attempts that came before it: {:?}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// Notifications. A diagnostic must not page anyone.
// ---------------------------------------------------------------------------

#[test]
fn a_probe_denial_notifies_nobody_while_a_real_one_does() {
    use std::io::Read as _;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("a local port must be bindable");
    let port = listener
        .local_addr()
        .expect("the port must be readable")
        .port();
    listener
        .set_nonblocking(true)
        .expect("the listener must be non-blocking");

    let tmp = scratch("notify");
    let home = tmp.join("home");
    let proj = project(
        &tmp,
        &format!(
            "version: 1\ndefault: ask\nrules:\n  - match: \"rm -rf /*\"\n    action: deny\n\
             notify:\n  webhook: http://127.0.0.1:{port}/hook\n  on: [deny]\n"
        ),
    );

    /// Anything that arrived within a short window, answered so the sender
    /// does not sit on its timeout.
    fn arrivals(listener: &TcpListener) -> usize {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        let mut seen = 0;
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let mut buf = [0u8; 512];
                    let _ = sock.read(&mut buf);
                    let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    seen += 1;
                    // The positive case is answered by the first arrival; only
                    // proving an absence needs the whole window.
                    return seen;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        seen
    }

    let denial = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": proj.display().to_string(),
        "tool_input": { "command": DENIED }
    });

    let out = hook(&home, &proj, &denial, &[]);
    assert_eq!(out.code, 2, "the fixture must actually deny");
    assert!(
        arrivals(&listener) > 0,
        "a real denial is what the webhook is configured for"
    );

    // The same denial as a probe. `termaxa doctor` invokes the hook once per
    // detected agent, and every one of those would page whoever is on call.
    let mut probe = denial.clone();
    probe["session_id"] = serde_json::Value::String("termaxa-doctor-probe".into());
    hook(&home, &proj, &probe, &[("TERMAXA_HOOK_PROBE", "1")]);
    assert_eq!(arrivals(&listener), 0, "a diagnostic must not page anyone");
}
