//! `check`, `log`, `stats` and `rollback` as a user drives them.
//!
//! These subcommands filter, count, confirm and preview — all of it inside
//! `dispatch`, which reads the process cwd and stdin and prints. There is no
//! seam to call, so the binary is the unit under test.
//!
//! Everything is seeded through the CLI: `run` is the only path that records
//! an approval and an exit code, which is what the outcome column renders.

#![cfg(unix)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

fn termaxa(home: &Path, cwd: &Path, args: &[&str], stdin: &str) -> Output {
    run_termaxa(home, cwd, args, stdin, None)
}

fn run_termaxa(
    home: &Path,
    cwd: &Path,
    args: &[&str],
    stdin: &str,
    extra_path: Option<&Path>,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_termaxa"));
    cmd.args(args)
        .current_dir(cwd)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Only the child's PATH is rewritten, so a stub binary cannot leak into
    // any other test in this process.
    if let Some(dir) = extra_path {
        let inherited = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{}", dir.display(), inherited));
    }
    let mut child = cmd.spawn().expect("the binary must be runnable");
    // A command may answer without reading stdin at all: `rollback` with an
    // unknown id refuses before it ever prompts. The child then exits while
    // this write is in flight and the pipe closes under it, which is the
    // child not needing what was offered rather than a failure of the test.
    // The assertions below carry the signal either way.
    let _ = child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(stdin.as_bytes());
    let out = child.wait_with_output().expect("the child must exit");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// A scratch tree, cleared first so a crashed earlier run cannot leak in.
/// Like `termaxa`, but gives up after `secs` and kills the child: the
/// wrapper used to recurse without end (#65), and a hung test is worse
/// than a failed one.
fn termaxa_within(home: &Path, cwd: &Path, args: &[&str], stdin: &str, secs: u64) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_termaxa"));
    cmd.args(args)
        .current_dir(cwd)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("the binary must be runnable");
    {
        let mut pipe = child.stdin.take().expect("stdin must be piped");
        let _ = pipe.write_all(stdin.as_bytes());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut timed_out = false;
    while child
        .try_wait()
        .expect("the child must be pollable")
        .is_none()
    {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("the child must exit");
    assert!(
        !timed_out,
        "termaxa {args:?} did not finish within {secs}s — the wrapper is recursing again (#65)"
    );
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("termaxa-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("home")).expect("scratch root must be creatable");
    base
}

/// `sh` runs silently, `rm` is insurable, and everything else is asked about.
fn project(root: &Path) -> PathBuf {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
    std::fs::write(
        proj.join(".termaxa").join("policy.yaml"),
        "version: 1\ndefault: ask\nrules:\n  - match: \"rm -rf /*\"\n    action: deny\n  \
         - match: \"sh*\"\n    action: allow\n  - match: \"exit*\"\n    action: allow\n",
    )
    .expect("policy must be writable");
    proj
}

/// A project that denies `terraform destroy` and asks about everything else.
fn project_gating_terraform(root: &Path) -> PathBuf {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
    std::fs::write(
        proj.join(".termaxa").join("policy.yaml"),
        "version: 1\ndefault: ask\nrules:\n  - match: \"terraform destroy*\"\n    action: deny\n",
    )
    .expect("policy must be writable");
    proj
}

/// A stub `terraform` that leaves a marker behind, so "did the preview spawn
/// anything?" is answerable as a fact rather than inferred from output.
fn stub_terraform(bin_dir: &Path, marker: &Path) {
    std::fs::create_dir_all(bin_dir).expect("stub dir must be creatable");
    let path = bin_dir.join("terraform");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\ntouch '{}'\necho 'Plan: 0 to add, 0 to change, 1 to destroy.'\n",
            marker.display()
        ),
    )
    .expect("stub must be writable");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("stub must be executable");
}

#[test]
fn a_denied_command_never_causes_the_preview_to_run_anything() {
    // v0.14.2, reported by Tim Schipper: `check` builds the preview before it
    // reports the decision, so DENYING a `terraform destroy` was the thing
    // that ran `terraform plan -destroy` in the working directory. The more
    // correctly the gate behaved, the more confidently it ran the plan.
    let tmp = scratch("deny-inert");
    let (home, proj) = (tmp.join("home"), project_gating_terraform(&tmp));
    let bin_dir = tmp.join("bin");
    let marker = tmp.join("plan-was-run");
    stub_terraform(&bin_dir, &marker);

    let denied = run_termaxa(
        &home,
        &proj,
        &["check", "terraform destroy -auto-approve"],
        "",
        Some(&bin_dir),
    );
    assert!(
        denied.stdout.contains("deny"),
        "the fixture must actually deny: {:?}",
        denied.stdout
    );
    assert!(
        !marker.exists(),
        "a denied command must not cause a subprocess"
    );

    // The other half: liveness is decided by the verdict, not switched off
    // altogether. A command that was not denied still gets a live preview.
    run_termaxa(
        &home,
        &proj,
        &["check", "terraform apply"],
        "",
        Some(&bin_dir),
    );
    assert!(
        marker.exists(),
        "an undenied command should still be previewed live"
    );
}

#[test]
fn log_filters_by_decision_and_by_source() {
    let tmp = scratch("log-filter");
    let (home, proj) = (tmp.join("home"), project(&tmp));

    termaxa(
        &home,
        &proj,
        &["check", "rm -rf /nonexistent-tmx-fixture"],
        "",
    );
    termaxa(&home, &proj, &["check", "cat notes.txt"], "");
    termaxa(&home, &proj, &["run", "--", "sh", "-c", "exit 0"], "");

    // The control leg: unfiltered, BOTH commands are there. Without it, a
    // filter test proves nothing when the seeding silently failed, because an
    // empty log excludes everything perfectly.
    let all = termaxa(&home, &proj, &["log", "-n", "50"], "").stdout;
    assert!(all.contains("rm -rf /"), "{all:?}");
    assert!(all.contains("cat notes.txt"), "{all:?}");

    let denied = termaxa(&home, &proj, &["log", "--decision", "deny"], "").stdout;
    assert!(denied.contains("rm -rf /"), "{denied:?}");
    assert!(
        !denied.contains("cat notes.txt"),
        "a filter that keeps everything is not a filter: {denied:?}"
    );

    let from_run = termaxa(&home, &proj, &["log", "--source", "run"], "").stdout;
    assert!(from_run.contains("exit 0"), "{from_run:?}");
    assert!(
        !from_run.contains("cat notes.txt"),
        "`check` entries are not `run` entries: {from_run:?}"
    );
}

#[test]
fn the_log_says_what_became_of_each_command() {
    let tmp = scratch("log-outcome");
    let (home, proj) = (tmp.join("home"), project(&tmp));

    // Allowed and executed: an exit code, but no approval to report.
    termaxa(&home, &proj, &["run", "--", "sh", "-c", "exit 3"], "");
    // Asked, and approved: both.
    termaxa(&home, &proj, &["run", "--", "echo", "yes-please"], "y\n");
    // Asked, and declined: nothing ran.
    termaxa(&home, &proj, &["run", "--", "echo", "no-thanks"], "n\n");

    let log = termaxa(&home, &proj, &["log", "-n", "50"], "").stdout;
    assert!(log.contains("→ exit 3"), "{log:?}");
    assert!(log.contains("→ approved, exit 0"), "{log:?}");
    assert!(log.contains("→ not run"), "{log:?}");
}

#[test]
fn stats_ranks_the_commands_that_were_denied() {
    let tmp = scratch("stats");
    let (home, proj) = (tmp.join("home"), project(&tmp));

    termaxa(
        &home,
        &proj,
        &["check", "rm -rf /nonexistent-tmx-fixture"],
        "",
    );
    termaxa(
        &home,
        &proj,
        &["check", "rm -rf /nonexistent-tmx-fixture"],
        "",
    );
    termaxa(
        &home,
        &proj,
        &["check", "rm -rf /nonexistent-tmx-other"],
        "",
    );
    termaxa(&home, &proj, &["check", "cat notes.txt"], "");

    // Same control: the allowed command is in the log, so its absence from the
    // denial ranking below is the ranking working rather than the log being
    // empty.
    let all = termaxa(&home, &proj, &["log", "-n", "50"], "").stdout;
    assert!(all.contains("cat notes.txt"), "{all:?}");

    let stats = termaxa(&home, &proj, &["stats"], "").stdout;
    assert!(stats.contains("top denied"), "{stats:?}");
    assert!(
        stats.contains("2× rm -rf /"),
        "the same denial twice is a count of two: {stats:?}"
    );
    assert!(
        !stats.contains("cat notes.txt"),
        "what was allowed is not a denial: {stats:?}"
    );
}

#[test]
fn stats_stays_quiet_about_denials_when_there_are_none() {
    let tmp = scratch("stats-quiet");
    let (home, proj) = (tmp.join("home"), project(&tmp));

    termaxa(&home, &proj, &["check", "cat notes.txt"], "");

    let stats = termaxa(&home, &proj, &["stats"], "").stdout;
    assert!(
        !stats.contains("top denied"),
        "an empty ranking is a heading with nothing under it: {stats:?}"
    );
}

/// Delete an insurable file through the gate and return the backup's id.
///
/// Insurance is best effort in production — `runner` prints "backup failed
/// (…); proceeding" and carries on — so a failure here must report what the
/// gate actually said, or the test just says "no backup" and leaves the cause
/// to guesswork.
fn take_a_backup(home: &Path, proj: &Path) -> String {
    std::fs::write(proj.join("doomed.txt"), "precious\n").expect("file must be writable");
    let deleted = termaxa(home, proj, &["run", "--", "rm", "doomed.txt"], "y\n");
    assert_eq!(
        deleted.code, 0,
        "the delete itself must succeed.\nstdout: {}\nstderr: {}",
        deleted.stdout, deleted.stderr
    );

    let listed = termaxa(home, proj, &["backups"], "").stdout;
    let id = listed
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        !id.is_empty() && !listed.contains("no backups yet"),
        "the delete should have been insured.\nbackups: {listed:?}\n\
         run stdout: {}\nrun stderr: {}",
        deleted.stdout,
        deleted.stderr
    );
    id
}

#[test]
fn rollback_refuses_an_id_it_does_not_have() {
    let tmp = scratch("rollback-unknown");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    take_a_backup(&home, &proj);

    // A backup exists, so "not found" cannot be reached by having none.
    let out = termaxa(&home, &proj, &["rollback", "definitely-not-an-id"], "y\n");
    assert_eq!(
        out.code,
        2,
        "an unknown id is an error: {out:?}",
        out = out.stderr
    );
    assert!(
        out.stderr.contains("no backup with id"),
        "and says so: {:?}",
        out.stderr
    );
}

#[test]
fn rollback_restores_nothing_unless_it_is_confirmed() {
    let tmp = scratch("rollback-declined");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    let id = take_a_backup(&home, &proj);

    let out = termaxa(&home, &proj, &["rollback", &id], "n\n");
    assert_eq!(out.code, 1, "a decline is not a success");
    assert!(out.stderr.contains("rollback declined"), "{:?}", out.stderr);
    assert!(
        !proj.join("doomed.txt").exists(),
        "declining must leave the file deleted, not restore it"
    );

    // And confirming does restore it, so the guard is a gate rather than a wall.
    let out = termaxa(&home, &proj, &["rollback", &id], "y\n");
    assert_eq!(
        out.code, 0,
        "a confirmed rollback succeeds: {:?}",
        out.stderr
    );
    assert!(
        proj.join("doomed.txt").exists(),
        "the insured file must come back"
    );
    // The mark is part of the assertion on purpose: "1 path(s) restored" is
    // also a substring of "-1 path(s) restored", so a count that went the
    // wrong way would read as correct.
    assert!(
        out.stdout.contains("✓ 1 path(s) restored"),
        "the count is the report of what happened: {:?}",
        out.stdout
    );
}

/// #65. Through the wrapper, an allowed command was never executed: the
/// runner's `sh` resolved to the shim again and the wrapper recursed until
/// killed. The residue test pinned a deny and a bypass; nothing pinned an
/// execution. The fixture allows `sh*` and `exit*`, so `sh -c "exit 3"` is
/// allowed at both levels, and its exit code must come back through the
/// wrapper and the shim.
#[test]
fn wrap_executes_what_it_allows() {
    let tmp = scratch("wrap-allow");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    let out = termaxa_within(&home, &proj, &["wrap", "--", "sh", "-c", "exit 3"], "", 30);
    assert_eq!(
        out.code, 3,
        "stdout: {}\nstderr: {}",
        out.stdout, out.stderr
    );
    assert!(
        !out.stderr.contains("not interactive"),
        "the gate must not ask twice: {}",
        out.stderr
    );
    // A shell nested inside the approved command is the real one, not the
    // shim: one gate, and the inner exit code comes back.
    let out = termaxa_within(
        &home,
        &proj,
        &["wrap", "--", "sh", "-c", "sh -c 'exit 5'"],
        "",
        30,
    );
    assert_eq!(
        out.code, 5,
        "stdout: {}\nstderr: {}",
        out.stdout, out.stderr
    );
}

/// #65, the asked half: through the wrapper an approved delete asked twice
/// and then refused for lack of stdin, leaving the file in place and no
/// backup. Now it asks once, insures, and executes.
#[test]
fn wrap_executes_what_it_approves_after_insuring_it() {
    let tmp = scratch("wrap-approve");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    std::fs::write(proj.join("doomed.txt"), "precious").unwrap();

    let out = termaxa_within(
        &home,
        &proj,
        &["wrap", "--", "sh", "-c", "rm -rf ./doomed.txt"],
        "y\n",
        30,
    );
    assert!(
        !proj.join("doomed.txt").exists(),
        "the approved delete must have run\nstdout: {}\nstderr: {}",
        out.stdout,
        out.stderr
    );
    let asks = out.stdout.matches("Proceed?").count() + out.stderr.matches("Proceed?").count();
    assert_eq!(
        asks, 1,
        "asked exactly once\nstdout: {}\nstderr: {}",
        out.stdout, out.stderr
    );
    let backups = termaxa(&home, &proj, &["backups"], "").stdout;
    assert!(
        backups.contains("rm -rf ./doomed.txt"),
        "the backup was taken before the delete ran: {backups}"
    );
}

/// #69. The shim forwarded only a leading, bare `-c`; `bash -lc` (Codex's
/// spelling), `bash -e -c`, `bash --norc -c` and `bash -o pipefail -c` ran
/// through the real shell ungated. Now every spelling is gated exactly once
/// and the shell's own options reach execution, while a script file and a
/// bare `-c` still pass through untouched.
#[test]
fn wrap_reads_a_c_wherever_the_shell_would() {
    let tmp = scratch("wrap-cluster");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    for spelling in [
        vec!["-c"],
        vec!["-lc"],
        vec!["-e", "-c"],
        vec!["--norc", "-c"],
        vec!["-o", "pipefail", "-c"],
    ] {
        let mut args = vec!["wrap", "--", "bash"];
        args.extend(spelling.iter().copied());
        args.push("exit 3");
        let out = termaxa_within(&home, &proj, &args, "", 30);
        let asks = out.stdout.matches("decision").count() + out.stderr.matches("decision").count();
        assert_eq!(
            out.code, 3,
            "{spelling:?}: stdout {}\nstderr {}",
            out.stdout, out.stderr
        );
        assert_eq!(
            asks, 1,
            "{spelling:?}: gated exactly once\n{}{}",
            out.stdout, out.stderr
        );
    }
    std::fs::write(proj.join("s.sh"), "exit 7\n").unwrap();
    let out = termaxa_within(&home, &proj, &["wrap", "--", "sh", "s.sh"], "", 30);
    assert_eq!(
        out.code, 7,
        "a script file is not read: {}{}",
        out.stdout, out.stderr
    );
    assert!(
        !out.stdout.contains("decision") && !out.stderr.contains("decision"),
        "no gate for a script file: {}{}",
        out.stdout,
        out.stderr
    );
}

/// The fail-mode knob. A payload that looks like a shell tool call but that
/// the reader cannot parse passes through by default (exit 0, no decision),
/// exactly as it always did; under `unrecognised: deny` it is refused with a
/// reason and exit 2. An unrelated payload is never refused, and a payload
/// the reader does understand is judged as before.
#[test]
fn an_unrecognised_shell_event_passes_through_by_default_and_is_refused_by_policy() {
    let tmp = scratch("unrecognised");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    let renamed = format!(
        r#"{{"cwd": {}, "event": "beforeShellRun", "tool": {{"name": "shell", "args": {{"command": "rm -rf /"}}}}}}"#,
        serde_json::to_string(&proj.display().to_string()).unwrap()
    );
    let unrelated = format!(
        r#"{{"cwd": {}, "event": "fileRead", "path": "src/main.rs"}}"#,
        serde_json::to_string(&proj.display().to_string()).unwrap()
    );
    let readable = format!(
        r#"{{"cwd": {}, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {{"command": "exit 3"}}}}"#,
        serde_json::to_string(&proj.display().to_string()).unwrap()
    );

    let out = termaxa(&home, &proj, &["hook"], &renamed);
    assert_eq!(
        out.code, 0,
        "default: pass through\nstdout {}\nstderr {}",
        out.stdout, out.stderr
    );
    assert!(
        out.stdout.trim().is_empty(),
        "default: no decision rendered: {}",
        out.stdout
    );

    let policy = proj.join(".termaxa").join("policy.yaml");
    let mut text = std::fs::read_to_string(&policy).unwrap();
    text.push_str("unrecognised: deny\n");
    std::fs::write(&policy, text).unwrap();

    let out = termaxa(&home, &proj, &["hook"], &renamed);
    assert_eq!(
        out.code, 2,
        "deny: refused\nstdout {}\nstderr {}",
        out.stdout, out.stderr
    );
    assert!(
        out.stdout.contains("\"deny\""),
        "deny rendered: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("not recognised"),
        "the reason says why: {}",
        out.stdout
    );

    let out = termaxa(&home, &proj, &["hook"], &unrelated);
    assert_eq!(
        out.code, 0,
        "an unrelated event is not a shell call: {}",
        out.stdout
    );
    assert!(out.stdout.trim().is_empty(), "{}", out.stdout);

    let out = termaxa(&home, &proj, &["hook"], &readable);
    assert_eq!(
        out.code, 0,
        "a readable payload is judged as before: {}{}",
        out.stdout, out.stderr
    );
    assert!(
        out.stdout.contains("\"allow\""),
        "exit* is allowed by the fixture: {}",
        out.stdout
    );
}

/// The insurance knob. A backup that cannot be taken proceeds with a warning
/// by default - the approved command runs uninsured; under `backup_failure:
/// deny` the command is refused and the target survives. A socket inside
/// the target is a copy that fails the way `/dev/null` did in #61.
#[cfg(unix)]
#[test]
fn a_failed_backup_proceeds_by_default_and_is_refused_by_policy() {
    let tmp = scratch("backup-failure");
    let (home, proj) = (tmp.join("home"), project(&tmp));
    let make_target = || {
        let junk = proj.join("junk");
        let _ = std::fs::remove_dir_all(&junk);
        std::fs::create_dir_all(&junk).unwrap();
        std::fs::write(junk.join("keep.txt"), "x").unwrap();
        // A socket: `fs::copy` cannot open it, so the copy fails at once.
        let sock = std::os::unix::net::UnixListener::bind(junk.join("sock"))
            .expect("the fixture needs a socket");
        std::mem::forget(sock);
        junk
    };

    let junk = make_target();
    let out = termaxa(&home, &proj, &["run", "--", "rm", "-rf", "./junk"], "y\n");
    assert!(
        !junk.exists(),
        "default: the approved delete ran uninsured\n{}{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("proceeding"),
        "default: the failure is reported: {}",
        out.stderr
    );

    let policy = proj.join(".termaxa").join("policy.yaml");
    let mut text = std::fs::read_to_string(&policy).unwrap();
    text.push_str("backup_failure: deny\n");
    std::fs::write(&policy, text).unwrap();

    let junk = make_target();
    let out = termaxa(&home, &proj, &["run", "--", "rm", "-rf", "./junk"], "y\n");
    assert!(
        junk.exists(),
        "deny: the uninsured delete did not run\n{}{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stderr.contains("backup_failure: deny"),
        "the refusal names the knob: {}",
        out.stderr
    );
}
