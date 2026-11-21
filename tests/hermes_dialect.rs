//! Hermes Agent's dialect, as Hermes speaks it.
//!
//! The payloads are the shape captured on Nov 19, 2026 from Hermes Agent
//! 0.23.2's own code path (a real session driven by a scripted model, its
//! shell hooks recording what they were sent). Four things that capture
//! measured, each pinned below:
//!
//! - Hermes names its events `pre_tool_call` and `post_tool_call`, its shell
//!   `terminal`, and reads a top-level `decision`/`action` only: a deny is
//!   `{"decision":"block","reason":...}` (with exit 2, which Hermes also
//!   reads as a block), an ask is `{"action":"approve","message":...}`,
//!   which Hermes hands to its own approval gate.
//! - The payload's `cwd` is the gateway process's own directory, not where
//!   the command runs; a terminal call's `workdir` is. So a Hermes call is
//!   judged by one policy, in termaxa's home, and never by one found from
//!   a directory the agent could pick (`termaxa hook --hermes`).
//! - Where nothing says where a command runs, it is judged with the
//!   directory unknown, and nothing is previewed or copied.
//! - `execute_code` runs Python the gate cannot read: an ask.
//!
//! No `sh` is spawned, so this binary runs on every platform.

use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Out {
    stdout: String,
    code: i32,
}

fn termaxa(home: &Path, hermes_home: &Path, cwd: &Path, args: &[&str], stdin: &str) -> Out {
    use std::io::Write as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .args(args)
        .current_dir(cwd)
        .env("TERMAXA_HOME", home)
        .env("HERMES_HOME", hermes_home)
        .env("NO_COLOR", "1")
        .env_remove("TERMAXA_HOOK_DEBUG")
        .env_remove("TERMAXA_MODE")
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
        code: out.status.code().unwrap_or(-1),
    }
}

/// A scratch tree: termaxa's home, Hermes's home with its gateway's
/// directory inside it (where Hermes 0.23.2 runs a hook and what it names
/// as `cwd`), and a project with a source file and no policy of its own.
struct Scene {
    root: PathBuf,
    home: PathBuf,
    hermes_home: PathBuf,
    gateway: PathBuf,
    proj: PathBuf,
}

fn scene(tag: &str) -> Scene {
    let root = std::env::temp_dir().join(format!("termaxa-hermes-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let hermes_home = root.join("hermes-home");
    let gateway = hermes_home.join("hermes-agent");
    let proj = root.join("proj");
    for d in [&home, &gateway, &proj.join("src")] {
        std::fs::create_dir_all(d).expect("scratch must be creatable");
    }
    std::fs::write(proj.join("src").join("main.rs"), "fn main() {}\n").expect("source file");
    Scene {
        root,
        home,
        hermes_home,
        gateway,
        proj,
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Scene {
    /// A Hermes payload in the captured shape, its `cwd` the gateway's.
    fn payload(&self, event: &str, tool: &str, input: serde_json::Value) -> String {
        json!({
            "hook_event_name": event,
            "tool_name": tool,
            "tool_input": input,
            "session_id": "local-2ac6a4c3",
            "cwd": self.gateway.display().to_string(),
            "profile": "default",
            "extra": {
                "task_id": "local-2ac6a4c3",
                "tool_call_id": "call_1",
                "middleware_trace": [],
                "telemetry_schema_version": "hermes.observer.v1",
                "kanban_task_id": ""
            }
        })
        .to_string()
    }

    fn hook(&self, args: &[&str], payload: &str) -> Out {
        termaxa(&self.home, &self.hermes_home, &self.gateway, args, payload)
    }

    /// Every line the hook recorded, from every state directory there is.
    fn record(&self) -> Vec<(String, serde_json::Value)> {
        let mut lines = Vec::new();
        let Ok(dirs) = std::fs::read_dir(self.home.join("projects")) else {
            return lines;
        };
        for dir in dirs.flatten() {
            let name = dir.file_name().to_string_lossy().into_owned();
            let log = dir.path().join("logs").join("audit.jsonl");
            for line in std::fs::read_to_string(log).unwrap_or_default().lines() {
                lines.push((
                    name.clone(),
                    serde_json::from_str(line).expect("a JSON line"),
                ));
            }
        }
        lines
    }
}

fn answer(out: &Out) -> serde_json::Value {
    serde_json::from_str(out.stdout.trim()).expect("the answer is JSON")
}

#[test]
fn a_hermes_call_is_judged_by_one_policy_and_answered_in_hermes_shape() {
    let s = scene("judged");
    let workdir = s.proj.display().to_string();

    // A deny where `workdir` says where the command runs: a block, its
    // reason and its preview of what the delete would take.
    let rm = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": "rm -rf src", "workdir": workdir }),
    );
    let out = s.hook(&["hook", "--hermes"], &rm);
    assert_eq!(out.code, 2, "{}", out.stdout);
    let v = answer(&out);
    assert_eq!(v["decision"], "block");
    let reason = v["reason"].as_str().unwrap();
    assert!(reason.contains("Recursive force delete"), "{reason}");
    assert!(reason.contains("src"), "{reason}");
    assert!(s.proj.join("src").join("main.rs").exists());

    // The same command where nothing says where it runs: still a block,
    // and the reason says why there is no preview.
    let rm_nowhere = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": "rm -rf src" }),
    );
    let out = s.hook(&["hook", "--hermes"], &rm_nowhere);
    assert_eq!(out.code, 2, "{}", out.stdout);
    let reason = answer(&out)["reason"].as_str().unwrap().to_string();
    assert!(
        reason.contains("Hermes did not say where this runs"),
        "{reason}"
    );

    // An allow is silence.
    let status = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": "git status", "workdir": workdir }),
    );
    let out = s.hook(&["hook", "--hermes"], &status);
    assert_eq!((out.code, out.stdout.trim()), (0, ""));

    // `execute_code` is an ask, in Hermes's shape.
    let code = s.payload(
        "pre_tool_call",
        "execute_code",
        json!({ "code": "import os" }),
    );
    let out = s.hook(&["hook", "--hermes"], &code);
    assert_eq!(out.code, 0, "{}", out.stdout);
    let v = answer(&out);
    assert_eq!(v["action"], "approve");
    assert!(v["message"].as_str().unwrap().contains("execute_code"));

    // A write to an agent's hook configuration is refused, whatever the
    // directory.
    let settings = s.payload(
        "pre_tool_call",
        "write_file",
        json!({ "path": ".claude/settings.json", "content": "{}" }),
    );
    let out = s.hook(&["hook", "--hermes"], &settings);
    assert_eq!(out.code, 2, "{}", out.stdout);
    assert_eq!(answer(&out)["decision"], "block");

    // A receipt says nothing.
    let receipt = s.payload(
        "post_tool_call",
        "terminal",
        json!({ "command": "git status", "workdir": workdir }),
    );
    let out = s.hook(&["hook", "--hermes"], &receipt);
    assert_eq!((out.code, out.stdout.trim()), (0, ""));

    // One record, named for Hermes and not for the gateway's directory or
    // the project, with every call in it.
    let record = s.record();
    let dirs: std::collections::BTreeSet<&str> = record.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(dirs.iter().all(|d| d.starts_with("hermes-")), "{dirs:?}");
    assert!(record.iter().all(|(_, e)| e["actor"] == "hermes"));
    let decisions: Vec<&str> = record
        .iter()
        .map(|(_, e)| e["decision"].as_str().unwrap_or(""))
        .collect();
    for d in ["deny", "allow", "ask", "executed"] {
        assert!(decisions.contains(&d), "{decisions:?}");
    }
}

#[test]
fn a_hermes_call_to_a_hook_without_the_flag_is_refused() {
    let s = scene("unflagged");
    let status = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": "git status", "workdir": s.proj.display().to_string() }),
    );
    let out = s.hook(&["hook"], &status);
    assert_eq!(out.code, 2, "{}", out.stdout);
    let v = answer(&out);
    assert_eq!(v["decision"], "block");
    assert!(v["reason"].as_str().unwrap().contains("--hermes"));
    assert!(s.record().is_empty());
}

#[test]
fn the_policy_in_termaxas_home_judges_every_hermes_call() {
    let s = scene("policy");
    let dir = s.home.join("hermes").join(".termaxa");
    std::fs::create_dir_all(&dir).expect("policy dir");
    std::fs::write(
        dir.join("policy.yaml"),
        "version: 1\ndefault: ask\nrules:\n  - match: \"git status*\"\n    action: deny\n    reason: \"the Hermes policy refuses git status\"\n",
    )
    .expect("policy file");
    let status = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": "git status", "workdir": s.proj.display().to_string() }),
    );
    let out = s.hook(&["hook", "--hermes"], &status);
    assert_eq!(out.code, 2, "{}", out.stdout);
    let reason = answer(&out)["reason"].as_str().unwrap().to_string();
    assert!(
        reason.contains("the Hermes policy refuses git status"),
        "{reason}"
    );
}

#[test]
fn a_path_given_in_full_is_previewed_and_copied_where_the_directory_is_unknown() {
    let s = scene("absolute");
    let abs = s.root.join("abs");
    std::fs::create_dir_all(abs.join("data")).expect("a directory");
    std::fs::write(abs.join("data").join("f.txt"), "x\n").expect("a file");
    std::fs::write(abs.join("conf.yml"), "a: 1\n").expect("a file");
    // Forward slashes: a full path as an agent writes it on every platform.
    let full = |p: &Path| p.display().to_string().replace('\\', "/");

    // A delete of a tree named in full: refused, with what it holds.
    let rm = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": format!("rm -rf {}", full(&abs.join("data"))) }),
    );
    let out = s.hook(&["hook", "--hermes"], &rm);
    assert_eq!(out.code, 2, "{}", out.stdout);
    let reason = answer(&out)["reason"].as_str().unwrap().to_string();
    assert!(reason.contains("1 files across"), "{reason}");
    assert!(
        reason.contains("Hermes did not say where this runs"),
        "{reason}"
    );

    // An overwrite of a file named in full that the policy allows: it runs,
    // and its file is copied aside first.
    let echo = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": format!("echo b > {}", full(&abs.join("conf.yml"))) }),
    );
    let out = s.hook(&["hook", "--hermes"], &echo);
    assert_eq!((out.code, out.stdout.trim()), (0, ""));
    let record = s.record();
    let copied = record
        .iter()
        .any(|(_, e)| e["decision"] == "allow" && e["backup"].is_string());
    assert!(copied, "{record:?}");

    // A relative path is neither previewed nor copied: nothing says what it
    // is.
    let rel = s.payload(
        "pre_tool_call",
        "terminal",
        json!({ "command": "rm -rf data" }),
    );
    let out = s.hook(&["hook", "--hermes"], &rel);
    assert_eq!(out.code, 2, "{}", out.stdout);
    let reason = answer(&out)["reason"].as_str().unwrap().to_string();
    assert!(!reason.contains("files across"), "{reason}");
}

/// An agent in a Hermes session cannot unhook the gate: a `write_file` or
/// a `patch` to the profile's `config.yaml` or `shell-hooks-allowlist.json`,
/// a command that writes either, and `hermes hooks revoke` are refused,
/// each with its reason. Reading them is not, nor writing the rest of
/// Hermes's home.
#[test]
fn a_hermes_session_cannot_unhook_the_gate() {
    let s = scene("unhook");
    let config = s.hermes_home.join("config.yaml").display().to_string();
    let allowlist = s
        .hermes_home
        .join("shell-hooks-allowlist.json")
        .display()
        .to_string();
    let workdir = s.proj.display().to_string();
    let refused = [
        s.payload(
            "pre_tool_call",
            "write_file",
            json!({ "path": config, "content": "model: {}\n" }),
        ),
        s.payload(
            "pre_tool_call",
            "write_file",
            json!({ "path": allowlist, "content": "{\"approvals\": []}\n" }),
        ),
        s.payload(
            "pre_tool_call",
            "patch",
            json!({ "mode": "replace", "path": config, "old_string": "hooks:", "new_string": "off:" }),
        ),
        s.payload(
            "pre_tool_call",
            "terminal",
            json!({ "command": format!("echo 'hooks: {{}}' > '{config}'"), "workdir": workdir }),
        ),
        s.payload(
            "pre_tool_call",
            "terminal",
            json!({ "command": "hermes hooks revoke 'termaxa hook --hermes'", "workdir": workdir }),
        ),
    ];
    for call in &refused {
        let out = s.hook(&["hook", "--hermes"], call);
        assert_eq!(out.code, 2, "{call}: {}", out.stdout);
        let v = answer(&out);
        assert_eq!(v["decision"], "block", "{call}");
        assert!(
            v["reason"].as_str().unwrap_or_default().contains("Hermes"),
            "{call}: {}",
            v["reason"]
        );
    }
    let let_through = [
        s.payload(
            "pre_tool_call",
            "terminal",
            json!({ "command": format!("cat '{config}'"), "workdir": workdir }),
        ),
        s.payload(
            "pre_tool_call",
            "write_file",
            json!({
                "path": s.hermes_home.join("memories").join("MEMORY.md").display().to_string(),
                "content": "a note\n"
            }),
        ),
    ];
    for call in &let_through {
        let out = s.hook(&["hook", "--hermes"], call);
        assert_eq!((out.code, out.stdout.trim()), (0, ""), "{call}");
    }
}
