//! The probe's write-nothing invariant, proven against the REAL binary.
//!
//! The first draft asserted this with a registered binary that never spawned,
//! which proved only that a probe that never runs writes nothing. This test
//! runs `termaxa hook` itself three ways:
//!
//!   1. probe (env + sentinel session)      -> answers, writes NOTHING
//!   2. env var alone, ordinary session     -> writes (the binding holds:
//!      a leaked TERMAXA_HOOK_PROBE is not an audit-and-insurance kill switch)
//!   3. no env at all                       -> writes (the CONTROL: proves
//!      this test can detect writes, i.e. it is not vacuous by construction)

use std::io::Write as _;
use std::process::{Command, Stdio};

// INCIDENT NOTE (2026-08-13): if this test ever fails in ways the source
// cannot explain, check `target/debug/termaxa(.exe)` against src mtimes
// before debugging the code. CARGO_BIN_EXE bakes that path in, and one
// Windows machine ran a two-day-stale binary through five debugging rounds
// while `cargo test` printed "Compiling termaxa" every time — likely a
// file lock during live agent sessions wedging the artifact copy.
// `cargo clean` cured it. Same class as everything else this release:
// the thing verified was not the thing changed.
fn run_hook(
    home: &std::path::Path,
    project: &std::path::Path,
    probe_env: bool,
    session: &str,
) -> String {
    // serde_json, NOT format!: a Windows temp path interpolated raw into a
    // JSON string turns every backslash into an invalid escape, the hook
    // (correctly) refuses to parse it, and the probe reads as unanswered.
    // That is the exact bug class this release exists for — a path losing
    // its meaning between serialization and consumption — and the first
    // version of this test shipped it. Caught on the incident platform.
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": project.display().to_string(),
        "session_id": session,
        "tool_input": { "command": "rm -rf /" }
    })
    .to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_termaxa"));
    cmd.arg("hook")
        .env("TERMAXA_HOME", home)
        .current_dir(project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if probe_env {
        cmd.env("TERMAXA_HOOK_PROBE", "1");
    } else {
        cmd.env_remove("TERMAXA_HOOK_PROBE");
    }
    let mut child = cmd.spawn().expect("binary spawns");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    format!(
        "{}\n--- child stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Every file under `root`, with the head of its contents. An assertion that
/// says "1 file appeared" without naming it is the `hook_configured` bug in
/// miniature — reporting a state without showing the thing. When this test
/// fails, the failure message IS the diagnosis: the path says which engine
/// wrote, and if it is the audit log, the entry's `session` field says
/// whether the sentinel survived the trip.
fn files_under(root: &std::path::Path) -> Vec<String> {
    fn walk(p: &std::path::Path, out: &mut Vec<String>) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    let head: String = std::fs::read_to_string(&path)
                        .unwrap_or_else(|_| "<unreadable>".into())
                        .chars()
                        .take(400)
                        .collect();
                    out.push(format!("{} :: {}", path.display(), head));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

fn file_count(root: &std::path::Path) -> usize {
    files_under(root).len()
}

fn scratch(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let base = std::env::temp_dir().join(format!("termaxa-inert-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let home = base.join("home");
    let project = base.join("proj");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(project.join(".termaxa")).unwrap();
    std::fs::write(
        project.join(".termaxa").join("policy.yaml"),
        "version: 1\ndefault: ask\nrules:\n  - match: \"*rm -rf*\"\n    action: deny\n    reason: \"blocked\"\n",
    )
    .unwrap();
    (home, project)
}

#[test]
fn the_probe_answers_and_writes_nothing_and_the_binding_holds() {
    // 1. A real probe: env + sentinel. Must answer with a decision and leave
    //    the state dir without a single file — no audit line, no backup,
    //    no session state.
    let (home, project) = scratch("probe");
    let before = file_count(&home);
    // Spelled literally because a binary crate exposes nothing to integration
    // tests: `hook::PROBE_SESSION` is the source of truth and cannot be
    // imported here. Three more literals live in tests/hook_dialects.rs. A
    // rename needs `grep termaxa-doctor-probe`, not the compiler.
    let out = run_hook(&home, &project, true, "termaxa-doctor-probe");
    assert!(
        out.contains("permissionDecision") && out.contains("deny"),
        "the probe must be ANSWERED — silence is indistinguishable from a dead hook; got: {out}"
    );
    let after = files_under(&home);
    assert_eq!(
        after.len(),
        before,
        "the probe wrote state — doctor has never created state and must not \
         start.\nWhat appeared, and its head:\n{}\nThe hook's own response \
         was:\n{}\nHome dir: {}",
        after.join("\n"),
        out,
        home.display()
    );

    // 2. The env var WITHOUT the sentinel session: an ordinary gated command.
    //    It must write — a leaked TERMAXA_HOOK_PROBE alone must not switch
    //    off the audit record and insurance.
    let (home2, project2) = scratch("leaked");
    run_hook(&home2, &project2, true, "ordinary-agent-session");
    assert!(
        file_count(&home2) > 0,
        "TERMAXA_HOOK_PROBE alone silenced the record — that is a kill \
         switch, not a probe. Home dir searched: {}",
        home2.display()
    );

    // 3. Control: no env at all. Must write, proving this test detects
    //    writes — the property the first draft's version lacked.
    let (home3, project3) = scratch("control");
    run_hook(&home3, &project3, false, "ordinary-agent-session");
    assert!(
        file_count(&home3) > 0,
        "the control run wrote nothing — the test cannot see writes and \
         proves nothing. Home dir searched: {}",
        home3.display()
    );
}
