//! `termaxa init --hermes` and `doctor`'s Hermes Agent section, run as a
//! person runs them, against a Hermes home in a scratch directory.
//!
//! What they write is what Hermes 0.23.2 reads (checked on Nov 20, 2026
//! with Hermes's own `agent/shell_hooks.py` against the files written
//! here): the hooks under `hooks:` in the profile's `config.yaml`, and the
//! approval of each event and command in `shell-hooks-allowlist.json`,
//! without which Hermes skips a hook in silence.
//!
//! No `sh` is spawned, so this binary runs on every platform.

use std::path::{Path, PathBuf};
use std::process::Command;

struct Out {
    stdout: String,
    stderr: String,
    code: i32,
}

fn termaxa(scene: &Scene, args: &[&str]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_termaxa"))
        .args(args)
        .current_dir(&scene.proj)
        .env("TERMAXA_HOME", &scene.home)
        .env("HERMES_HOME", &scene.hermes_home)
        .env("NO_COLOR", "1")
        .env_remove("TERMAXA_MODE")
        .env_remove("TERMAXA_HOOK_PROBE")
        .output()
        .expect("the binary must be runnable");
    Out {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// termaxa's home, a Hermes home set up the way `hermes setup` leaves one
/// (a `config.yaml` with no `hooks:` key), and a project to run from.
struct Scene {
    home: PathBuf,
    hermes_home: PathBuf,
    proj: PathBuf,
}

const SET_UP: &str =
    "model:\n  default: claude-opus-5-5\n  provider: anthropic\nterminal:\n  backend: local\n";

fn scene(tag: &str, config: Option<&str>) -> Scene {
    let root =
        std::env::temp_dir().join(format!("termaxa-hermes-init-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let scene = Scene {
        home: root.join("home"),
        hermes_home: root.join("hermes-home"),
        proj: root.join("proj"),
    };
    for d in [&scene.home, &scene.hermes_home, &scene.proj] {
        std::fs::create_dir_all(d).expect("scratch must be creatable");
    }
    if let Some(text) = config {
        std::fs::write(scene.hermes_home.join("config.yaml"), text)
            .expect("config must be writable");
    }
    scene
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `pre_tool_call` entries of a `config.yaml`, as Hermes reads them.
fn pre_tool_call(config: &str) -> Vec<serde_yaml::Value> {
    let v: serde_yaml::Value = serde_yaml::from_str(config).expect("config.yaml must stay YAML");
    v["hooks"]["pre_tool_call"]
        .as_sequence()
        .cloned()
        .unwrap_or_default()
}

fn approvals(scene: &Scene) -> Vec<(String, String)> {
    let text = read(&scene.hermes_home.join("shell-hooks-allowlist.json"));
    let v: serde_json::Value = serde_json::from_str(&text).expect("the allowlist must be JSON");
    v["approvals"]
        .as_array()
        .expect("approvals must be a list")
        .iter()
        .map(|a| {
            (
                a["event"].as_str().unwrap_or_default().to_string(),
                a["command"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// The hooks, their approval and the policy, written once: the profile's
/// own settings are kept as they were (and a copy of the file beside it),
/// the gate's entry refuses a call when termaxa cannot answer, both events
/// are approved for the exact command registered, and that command answers
/// a test call. Run again, it changes nothing.
#[test]
fn init_hermes_wires_the_profile_once() {
    let s = scene("once", Some(SET_UP));
    let out = termaxa(&s, &["init", "--hermes"]);
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);

    let config = read(&s.hermes_home.join("config.yaml"));
    assert!(
        config.starts_with(SET_UP),
        "the profile's settings are kept: {config}"
    );
    assert_eq!(
        read(&s.hermes_home.join("config.yaml.before-termaxa")),
        SET_UP
    );
    let pre = pre_tool_call(&config);
    assert_eq!(pre.len(), 1, "{config}");
    let command = pre[0]["command"].as_str().expect("a command").to_string();
    assert!(command.ends_with(" hook --hermes"), "{command}");
    assert_eq!(
        pre[0]["matcher"].as_str(),
        Some("terminal|write_file|patch|execute_code")
    );
    assert_eq!(pre[0]["fail_closed"].as_bool(), Some(true));
    assert_eq!(
        approvals(&s),
        [
            ("pre_tool_call".to_string(), command.clone()),
            ("post_tool_call".to_string(), command.clone())
        ]
    );
    assert!(
        s.home
            .join("hermes")
            .join(".termaxa")
            .join("policy.yaml")
            .is_file(),
        "the one policy for Hermes is written"
    );
    assert!(
        out.stdout.contains("a test call to `rm -rf /` was refused"),
        "the registered command answers: {}",
        out.stdout
    );

    let allowlist = read(&s.hermes_home.join("shell-hooks-allowlist.json"));
    let again = termaxa(&s, &["init", "--hermes"]);
    assert_eq!(again.code, 0, "{}{}", again.stdout, again.stderr);
    assert!(again.stdout.contains("already runs"), "{}", again.stdout);
    assert!(
        again.stdout.contains("already approves"),
        "{}",
        again.stdout
    );
    assert_eq!(read(&s.hermes_home.join("config.yaml")), config);
    assert_eq!(
        read(&s.hermes_home.join("shell-hooks-allowlist.json")),
        allowlist
    );
    assert!(!s.hermes_home.join("config.yaml.before-termaxa-2").exists());
}

/// A `hooks:` block of the person's own is not edited: the entries to add
/// are printed, nothing is approved, and the run says it did not wire.
#[test]
fn init_hermes_leaves_hooks_of_its_own() {
    let own = format!(
        "{SET_UP}hooks:\n  pre_tool_call:\n    - command: ~/.hermes/agent-hooks/guard.sh\n"
    );
    let s = scene("own", Some(&own));
    let out = termaxa(&s, &["init", "--hermes"]);
    assert_ne!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("Add these entries"), "{}", out.stdout);
    assert!(out.stdout.contains("hook --hermes"), "{}", out.stdout);
    assert_eq!(read(&s.hermes_home.join("config.yaml")), own);
    assert!(!s.hermes_home.join("shell-hooks-allowlist.json").exists());
}

/// Without a `config.yaml` there is no Hermes to wire: nothing is written,
/// in Hermes's home or in termaxa's.
#[test]
fn init_hermes_needs_hermes_set_up() {
    let s = scene("bare", None);
    let out = termaxa(&s, &["init", "--hermes"]);
    assert_ne!(out.code, 0, "{}", out.stdout);
    assert!(out.stderr.contains("hermes setup"), "{}", out.stderr);
    assert!(std::fs::read_dir(&s.hermes_home).unwrap().next().is_none());
    assert!(!s.home.join("hermes").exists());
}

/// `doctor` follows the wiring through each state a person can leave it
/// in: not there, there and live, there but not approved (Hermes skips it
/// in silence), and there with a matcher that leaves the shell out.
#[test]
fn doctor_reads_the_hermes_wiring() {
    let s = scene("doctor", Some(SET_UP));
    let line = |out: &Out| {
        out.stdout
            .lines()
            .find(|l| l.contains("Hermes Agent"))
            .unwrap_or_default()
            .to_string()
    };

    let before = termaxa(&s, &["doctor"]);
    assert!(
        line(&before).contains("hook NOT configured"),
        "{}",
        before.stdout
    );
    assert!(
        before.stdout.contains("termaxa init --hermes"),
        "{}",
        before.stdout
    );

    let init = termaxa(&s, &["init", "--hermes"]);
    assert_eq!(init.code, 0, "{}{}", init.stdout, init.stderr);
    let wired = termaxa(&s, &["doctor"]);
    assert!(
        line(&wired).contains("hook configured and live"),
        "{}",
        wired.stdout
    );
    assert!(wired.stdout.contains("unchanged since"), "{}", wired.stdout);

    let allowlist = s.hermes_home.join("shell-hooks-allowlist.json");
    std::fs::remove_file(&allowlist).expect("the allowlist was written");
    let unapproved = termaxa(&s, &["doctor"]);
    assert!(
        line(&unapproved).contains("NOT approved"),
        "{}",
        unapproved.stdout
    );

    termaxa(&s, &["init", "--hermes"]);
    let config = s.hermes_home.join("config.yaml");
    let narrowed =
        read(&config).replace("terminal|write_file|patch|execute_code", "write_file|patch");
    std::fs::write(&config, narrowed).expect("config must be writable");
    let narrow = termaxa(&s, &["doctor"]);
    assert!(
        line(&narrow).contains("leaves out `terminal`"),
        "{}",
        narrow.stdout
    );
}
