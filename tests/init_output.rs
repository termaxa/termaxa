//! What `termaxa init` tells you about the machine it just ran on.
//!
//! The detection block and the manual snippet are print-only: `run` returns
//! Ok(()) whether it found four harnesses or none. As in the doctor tests,
//! PATH is reduced to a shell and `which`, so "is Claude installed?" is a
//! fact each test sets rather than a property of the developer's laptop.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("termaxa-init-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("home")).expect("scratch root must be creatable");
    base
}

/// A PATH with a shell and `which` on it, and no agent CLI whatsoever.
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

fn init_in(home: &Path, dir: &Path, bin: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .arg("init")
        .current_dir(dir)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .env("PATH", bin)
        .output()
        .expect("the binary must be runnable");
    assert!(
        out.status.success(),
        "init should succeed: {:?}",
        out.status
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_harness_is_detected_by_its_directory_alone() {
    let tmp = scratch("detect");
    let bin = controlled_path(&tmp);
    let proj = tmp.join("proj");
    std::fs::create_dir_all(proj.join(".claude")).expect("agent dir must be creatable");

    let out = init_in(&tmp.join("home"), &proj, &bin);
    // The detection line specifically: "To wire Termaxa into Claude Code"
    // appears further down as advice whether or not anything was found.
    assert!(
        out.contains("✓ Claude Code"),
        "the directory is evidence even with no CLI on PATH: {out:?}"
    );
    assert!(
        !out.contains("none found"),
        "something was found, so it must not report otherwise: {out:?}"
    );
}

#[test]
fn an_empty_directory_is_told_it_has_no_harness() {
    let tmp = scratch("bare");
    let bin = controlled_path(&tmp);
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).expect("dir must be creatable");

    let out = init_in(&tmp.join("home"), &proj, &bin);
    assert!(
        out.contains("none found"),
        "an empty list needs saying, or the section just stops: {out:?}"
    );
    assert!(
        !out.contains("✓ Claude Code"),
        "nothing is installed here, so nothing may be ticked: {out:?}"
    );
}

#[test]
fn the_manual_snippet_is_printed_for_people_wiring_by_hand() {
    // The snippet is the fallback for anyone not using one of the --flags,
    // so it going missing would be silent.
    let tmp = scratch("snippet");
    let bin = controlled_path(&tmp);
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).expect("dir must be creatable");

    let out = init_in(&tmp.join("home"), &proj, &bin);
    assert!(out.contains(".claude/settings.json snippet:"), "{out:?}");
    assert!(
        out.contains("\"command\": \"termaxa hook\""),
        "the snippet has to carry the command it is telling you to paste: {out:?}"
    );
}

/// What a plugin's hook keeps of a project that has no policy: each command
/// judged by `termaxa hook --plugin`, sent the way Claude Code sends it.
fn watch(home: &Path, proj: &Path, commands: &[&str]) {
    use std::io::Write;
    for command in commands {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "session_id": "watched",
            "cwd": proj,
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_termaxa"))
            .args(["hook", "--plugin"])
            .current_dir(proj)
            .env("TERMAXA_HOME", home)
            .env("NO_COLOR", "1")
            .env_remove("TERMAXA_MODE")
            .env_remove("CLAUDE_PROJECT_DIR")
            .env_remove("CLAUDE_CONFIG_DIR")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the binary must be runnable");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        assert!(
            child.wait().unwrap().success(),
            "{command}: watched, not refused"
        );
    }
}

/// `termaxa check` in the project, under the policy `init` wrote: the verdict.
fn verdict(home: &Path, proj: &Path, command: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .args(["check", command])
        .current_dir(proj)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .env_remove("TERMAXA_MODE")
        .output()
        .expect("the binary must be runnable");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("decision").map(|d| d.trim().to_string()))
        .unwrap_or_default()
}

/// `init`, with its input a terminal a person types into (`openpty`): the
/// one way an answer to its questions is taken, as for `run`'s ask.
fn init_at_terminal(home: &Path, dir: &Path, bin: &Path, answers: &str) -> String {
    use std::io::Write;
    use std::os::unix::io::FromRawFd;
    use std::process::Stdio;
    let (mut master, mut slave) = (0i32, 0i32);
    // SAFETY: openpty writes two new descriptors into the two integers.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty must succeed on a unix test machine");
    // SAFETY: both descriptors were just created by openpty and are owned here.
    let slave_file = unsafe { std::fs::File::from_raw_fd(slave) };
    let mut master_file = unsafe { std::fs::File::from_raw_fd(master) };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_termaxa"));
    cmd.arg("init")
        .current_dir(dir)
        .env("TERMAXA_HOME", home)
        .env("NO_COLOR", "1")
        .env("PATH", bin)
        .stdin(Stdio::from(slave_file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("the binary must be runnable");
    drop(cmd);
    let _ = master_file.write_all(answers.as_bytes());
    let out = child.wait_with_output().expect("init must exit");
    drop(master_file);
    assert!(
        out.status.success(),
        "init should succeed: {:?}",
        out.status
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Two actions asked twice each, and what is not proposed: code on the
/// line, a delete, and an ask the starter's own rule chose.
const WATCHED: &[&str] = &[
    "npm run build",
    "cd web && npm run build",
    "npx prisma generate",
    "npx prisma generate",
    "python3 -c 'print(1)'",
    "python3 -c 'print(2)'",
    "rm build.log",
    "rm out.log",
    "git push origin main",
];

/// `init` where a plugin's hook has been watching, with nobody at a terminal
/// (an agent running it, a script): the proposals are shown, and written as
/// comments that change no verdict until a person takes them off (#149, #34).
#[test]
fn init_without_a_terminal_writes_the_watch_records_proposals_as_comments() {
    let tmp = scratch("watched-pipe");
    let bin = controlled_path(&tmp);
    let home = tmp.join("home");
    let proj = tmp.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    watch(&home, &proj, WATCHED);

    let out = init_in(&home, &proj, &bin);
    assert!(
        out.contains("A plugin's hook watched this project from"),
        "{out}"
    );
    assert!(
        out.contains(
            "9 commands. Under the starter,\n9 would have asked and 0 would have been refused."
        ),
        "{out}"
    );
    assert!(out.contains("npm run build   asked 2 times"), "{out}");
    assert!(out.contains("npx prisma generate   asked 2 times"), "{out}");
    assert!(out.contains("none of them is active"), "{out}");
    assert!(
        out.contains("python3 -c 'print(1)'"),
        "what was left is shown: {out}"
    );
    let proposals = &out[..out.find("✓ wrote").expect("the policy is written")];
    assert!(
        !proposals.contains("git push"),
        "an ask a rule chose is not proposed away: {out}"
    );
    let policy = std::fs::read_to_string(proj.join(".termaxa/policy.yaml")).unwrap();
    assert!(
        policy.contains("  # - match: \"npm run build\"\n"),
        "{policy}"
    );
    assert_eq!(verdict(&home, &proj, "npm run build"), "ask");
}

/// At a terminal each proposal is put to the person, and only what they
/// accept is written, below every rule of the starter.
#[test]
fn init_at_a_terminal_writes_only_what_the_person_accepted() {
    let tmp = scratch("watched-tty");
    let bin = controlled_path(&tmp);
    let home = tmp.join("home");
    let proj = tmp.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    watch(&home, &proj, WATCHED);

    let out = init_at_terminal(&home, &proj, &bin, "y\nn\n");
    assert!(out.contains("[1/2] npm run build"), "{out}");
    assert!(out.contains("Allow it? [y/N]"), "{out}");
    assert!(out.contains("1 rule added"), "{out}");
    let policy = std::fs::read_to_string(proj.join(".termaxa/policy.yaml")).unwrap();
    assert!(
        policy.contains("  - match: \"npm run build\"\n    action: allow\n"),
        "{policy}"
    );
    assert!(
        !policy.contains("prisma"),
        "a dropped proposal writes nothing"
    );
    assert_eq!(verdict(&home, &proj, "npm run build"), "allow");
    assert_eq!(verdict(&home, &proj, "npx prisma generate"), "ask");
    assert_eq!(verdict(&home, &proj, "npm run build && rm -rf /"), "deny");
}
