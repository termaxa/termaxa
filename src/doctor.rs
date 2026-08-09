//! `termaxa doctor` — the onboarding hub.
//!
//! Answers one question: **is Termaxa actually going to see my agent's
//! commands?** That question has a surprising number of ways to be "no"
//! (no policy, hook not installed, agent not restarted, dialect drift), and
//! until now the only way to find out was to run a destructive command and
//! see whether anything happened.
//!
//! Honesty rules, same as everywhere else:
//!   * We report what we can verify from the filesystem and PATH. We do NOT
//!     claim the hook *fires* — only that it is configured. Whether the agent
//!     honours it is the agent's business, and `termaxa log` is the proof.
//!   * Absence is stated plainly, with the exact command that fixes it.
//!   * No network calls. No version check phoning home.

use crate::paths;
use anyhow::Result;
use std::path::Path;

pub fn run(dir: &Path) -> Result<i32> {
    use crate::ui::{amber, bold, cyan, dim, green, red};

    println!();
    println!("{}", bold("Termaxa doctor"));
    println!("{}", dim("──────────────────────────────────────────"));

    // ---- 1. Binary ----
    let version = env!("CARGO_PKG_VERSION");
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "(unknown)".into());
    println!("{} termaxa {}", green("✓"), version);
    println!("  {}", dim(&exe));

    // ---- 2. Policy ----
    println!();
    println!("{}", bold("Policy"));
    // Read-only: a diagnostic observes, it never creates state (see
    // paths::resolve_readonly — resolve_from would make logs/ and backups/
    // and could silently run legacy migration).
    let resolved = paths::resolve_readonly(dir).ok();
    let mut problems: Vec<String> = Vec::new();

    match &resolved {
        Some(p) => {
            let pf = p.policy_file();
            println!("{} {}", green("✓"), pf.display());
            match crate::policy::Policy::load(&pf) {
                Ok(pol) => {
                    println!(
                        "  {} rule(s), default {}",
                        pol.rules.len(),
                        crate::ui::decision(&pol.default.to_string())
                    );
                }
                Err(e) => {
                    println!("{} policy will not parse: {}", red("✗"), e);
                    problems.push("fix .termaxa/policy.yaml (it does not parse)".into());
                }
            }
            report_fingerprint(&pf, &p.state_dir, &mut problems);
        }
        None => {
            println!(
                "{} no .termaxa/policy.yaml in this directory or any parent",
                amber("!")
            );
            println!(
                "  {} works anyway (built-in starter policy), but {} and {} need one.",
                cyan("termaxa check"),
                cyan("run"),
                cyan("hook")
            );
            problems.push("run `termaxa init` to create a policy".into());
        }
    }

    // ---- 3. Agents: installed, and wired? ----
    println!();
    println!("{}", bold("Agents"));

    let claude_settings = dir.join(".claude").join("settings.json");
    let cursor_hooks = dir.join(".cursor").join("hooks.json");
    let codex_hooks = dir.join(".codex").join("hooks.json");
    let copilot_hooks = dir.join(".github").join("hooks").join("hooks.json");

    let mut any_agent = false;

    // Claude Code
    let claude_present = dir.join(".claude").exists() || crate::init::which("claude");
    if claude_present {
        any_agent = true;
        let wired = hook_configured(&claude_settings);
        report_agent(
            "Claude Code",
            wired,
            "termaxa init --claude-code",
            &mut problems,
        );
    }

    // Cursor
    let cursor_present = dir.join(".cursor").exists() || crate::init::which("cursor");
    if cursor_present {
        any_agent = true;
        let wired = hook_configured(&cursor_hooks);
        report_agent("Cursor", wired, "termaxa init --cursor", &mut problems);
        if wired {
            println!(
                "    {}",
                dim("restart Cursor after wiring — it caches hook config at startup")
            );
        }
    }

    // Codex / Copilot: only mention when detected, and label them honestly.
    if crate::init::which("codex") {
        any_agent = true;
        let wired = hook_configured(&codex_hooks);
        report_agent("Codex CLI", wired, "termaxa init --codex", &mut problems);
        println!(
            "    {}",
            dim("dialect built, not yet verified end-to-end (issue #10)")
        );
    }
    if crate::init::which("copilot") || crate::init::which("gh") {
        let wired = hook_configured(&copilot_hooks);
        if wired || crate::init::which("copilot") {
            any_agent = true;
            report_agent(
                "Copilot CLI",
                wired,
                "termaxa init --copilot",
                &mut problems,
            );
            println!(
                "    {}",
                dim("dialect built, not yet verified end-to-end (issue #10)")
            );
        }
    }

    if !any_agent {
        println!("{} no agent harness detected in this directory", dim("·"));
        println!(
            "  {}",
            dim("that's fine — `termaxa check` and `termaxa run` work standalone")
        );
    }

    // ---- 4. Tools the previews depend on ----
    println!();
    println!("{}", bold("Preview support"));
    for (tool, what) in [
        ("git", "force-push previews and git backups"),
        ("psql", "Postgres blast radius"),
        ("pg_dump", "Postgres backups"),
        ("terraform", "plan previews"),
    ] {
        if crate::init::which(tool) {
            println!("{} {:<11}{}", green("✓"), tool, dim(what));
        } else {
            println!(
                "{} {:<11}{}",
                dim("·"),
                tool,
                dim(&format!("{} unavailable", what))
            );
        }
    }

    // ---- 5. State ----
    println!();
    println!("{}", bold("State"));
    match &resolved {
        Some(p) => {
            let exists = p.state_dir.exists();
            if exists {
                println!("{} {}", green("✓"), p.state_dir.display());
            } else {
                println!("{} {}", dim("·"), p.state_dir.display());
                println!("  {}", dim("not created yet — nothing has run here"));
            }
            let logfile = p.log_file();
            if logfile.is_file() {
                let (entries, hooks) = count_log(&logfile);
                println!("  {} audit entries ({} from hooks)", entries, hooks);
                if hooks == 0 && any_agent {
                    println!(
                        "  {} no hook entries yet — the gate has not seen an agent command",
                        amber("!")
                    );
                    println!(
                        "    {}",
                        dim("if your agent has run commands since wiring, suspect dialect drift:")
                    );
                    println!(
                        "    {}",
                        dim("set TERMAXA_HOOK_DEBUG=1 and check what arrives")
                    );
                }
            } else {
                println!("  {}", dim("no audit log yet — nothing has been evaluated"));
            }
        }
        None => println!("{}", dim("· (no project — state lives per-project)")),
    }

    // ---- verdict ----
    println!();
    println!("{}", dim("──────────────────────────────────────────"));
    if problems.is_empty() {
        println!("{} {}", green("✓"), bold("Everything checks out."));
        println!(
            "  {}",
            dim("proof is in the log: run your agent, then `termaxa report`")
        );
        println!();
        Ok(0)
    } else {
        println!("{} {} to fix:", amber("!"), problems.len());
        for p in &problems {
            println!("  · {}", p);
        }
        println!();
        Ok(1)
    }
}

/// Compare the policy on disk against the baseline `termaxa init` recorded.
///
/// Read-only, like everything else in `doctor`: it never records a baseline,
/// because a diagnostic that writes the value it is checking always reports
/// "unchanged". Re-recording is `termaxa init`'s job.
///
/// What this can and cannot say, stated plainly because the distinction is
/// the whole feature: it can say the bytes differ from the ones last
/// recorded. It cannot say who changed them, and it cannot see a change made
/// before the first baseline existed.
fn report_fingerprint(policy_file: &Path, state_dir: &Path, problems: &mut Vec<String>) {
    use crate::fingerprint;
    use crate::ui::{amber, cyan, dim, green};

    let Some(current) = fingerprint::of_file(policy_file) else {
        return; // unreadable policy is already reported above
    };
    println!("  fingerprint {}", dim(&fingerprint::short(&current)));

    match fingerprint::read_baseline(state_dir) {
        None => {
            println!(
                "  {} no baseline recorded — a change to this file would be invisible",
                amber("!")
            );
            println!("    {}", cyan("termaxa init"));
            problems.push("record a policy baseline — `termaxa init`".into());
        }
        Some(base) if base.sha256 == current => {
            println!("  {} unchanged since {}", green("✓"), dim(&base.recorded));
        }
        Some(base) => {
            println!(
                "  {} CHANGED since {} (was {})",
                amber("!"),
                base.recorded,
                fingerprint::short(&base.sha256)
            );
            println!(
                "    {}",
                dim("if you made this change, re-record it: `termaxa init`")
            );
            println!(
                "    {}",
                dim("if you did not, something edited the gate's own rules —")
            );
            println!(
                "    {}",
                dim("agent file-writing tools bypass the hook entirely (matcher: Bash)")
            );
            problems
                .push("review .termaxa/policy.yaml — it changed since the last baseline".into());
        }
    }
}

fn report_agent(name: &str, wired: bool, fix: &str, problems: &mut Vec<String>) {
    use crate::ui::{amber, cyan, dim, green};
    if wired {
        println!("{} {:<13}{}", green("✓"), name, dim("hook configured"));
    } else {
        println!(
            "{} {:<13}{}",
            amber("!"),
            name,
            dim("detected, hook NOT configured")
        );
        println!("    {}", cyan(fix));
        problems.push(format!("wire {} — `{}`", name, fix));
    }
}

/// Count audit entries without creating anything.
///
/// Deliberately does NOT go through `AuditLog::new`, which calls
/// `create_dir_all` — a diagnostic that creates the log directory it is
/// reporting on is lying by construction. Reads the file if present, parses
/// what it can, ignores what it can't (old schema lines stay readable —
/// decision #7).
fn count_log(path: &Path) -> (usize, usize) {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return (0, 0);
    };
    let mut total = 0usize;
    let mut hooks = 0usize;
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<crate::audit::AuditEntry>(line) {
            Ok(e) => {
                total += 1;
                if e.source == "hook" {
                    hooks += 1;
                }
            }
            Err(_) => total += 1, // unparseable line still happened
        }
    }
    (total, hooks)
}

/// Does this config file mention a termaxa hook? Deliberately a substring
/// check on the raw text rather than a schema parse: the shapes differ per
/// agent and per version, and we only claim "configured", never "will fire".
fn hook_configured(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|s| s.contains("termaxa hook") || s.contains("termaxa\\\" hook"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn count_log_reads_without_creating_and_tolerates_junk() {
        let dir = std::env::temp_dir().join(format!("tmx-doc-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Missing file: zero, and nothing created.
        let missing = dir.join("nope.jsonl");
        assert_eq!(count_log(&missing), (0, 0));
        assert!(!missing.exists(), "count_log must not create the log file");

        // Two valid entries (one hook, one check) plus a junk line.
        let f = dir.join("audit.jsonl");
        let hook_line = r#"{"ts_ms":1,"ts":"t","source":"hook","command":"rm -rf .","decision":"deny","matched_rule":null,"reason":"r","signals":[],"escalated":false,"approved":null,"exit_code":null,"cwd":"/x"}"#;
        let check_line = r#"{"ts_ms":2,"ts":"t","source":"check","command":"ls","decision":"allow","matched_rule":null,"reason":"r","signals":[],"escalated":false,"approved":null,"exit_code":null,"cwd":"/x"}"#;
        std::fs::write(
            &f,
            format!("{hook_line}\n{check_line}\nnot json at all\n\n"),
        )
        .unwrap();
        let (total, hooks) = count_log(&f);
        assert_eq!(total, 3, "junk lines still count as entries that happened");
        assert_eq!(hooks, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_policy_edited_behind_the_gate_becomes_a_reported_problem() {
        let dir = std::env::temp_dir().join(format!("tmx-doc-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let policy = dir.join("policy.yaml");
        std::fs::write(&policy, "version: 1\ndefault: ask\nrules: []\n").unwrap();

        // 1. No baseline: say so, and do NOT quietly create one — a
        //    diagnostic that records the value it checks always reports
        //    "unchanged".
        let mut problems: Vec<String> = Vec::new();
        report_fingerprint(&policy, &state, &mut problems);
        assert_eq!(problems.len(), 1, "a missing baseline is a real gap");
        assert!(
            !crate::fingerprint::baseline_file(&state).exists(),
            "doctor must observe, never record"
        );

        // 2. Baseline matches: nothing to fix.
        let hash = crate::fingerprint::of_file(&policy).unwrap();
        crate::fingerprint::record(&state, &hash).unwrap();
        let mut problems: Vec<String> = Vec::new();
        report_fingerprint(&policy, &state, &mut problems);
        assert!(problems.is_empty(), "unchanged policy is not a problem");

        // 3. The edit from the review — the one no deny rule can stop,
        //    because an agent's file-writing tool never reaches the hook.
        std::fs::write(&policy, "version: 1\ndefault: allow\nrules: []\n").unwrap();
        let mut problems: Vec<String> = Vec::new();
        report_fingerprint(&policy, &state, &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].contains("changed"),
            "the problem must name what happened: {}",
            problems[0]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hook_configured_detects_plain_and_absolute_forms() {
        let dir = std::env::temp_dir().join(format!("tmx-doctor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let plain = dir.join("plain.json");
        let mut f = std::fs::File::create(&plain).unwrap();
        writeln!(
            f,
            r#"{{"hooks":{{"PreToolUse":[{{"command":"termaxa hook"}}]}}}}"#
        )
        .unwrap();
        assert!(hook_configured(&plain));

        // init writes an ABSOLUTE exe path on Windows; the substring must still hit.
        let abs = dir.join("abs.json");
        let mut f = std::fs::File::create(&abs).unwrap();
        writeln!(
            f,
            r#"{{"hooks":{{"beforeShellExecution":[{{"command":"C:\\Users\\x\\.cargo\\bin\\termaxa hook"}}]}}}}"#
        )
        .unwrap();
        assert!(hook_configured(&abs));

        let empty = dir.join("empty.json");
        std::fs::write(&empty, "{}").unwrap();
        assert!(!hook_configured(&empty));

        assert!(!hook_configured(&dir.join("does-not-exist.json")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
