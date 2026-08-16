use crate::audit::{now, AuditEntry, AuditLog};
use crate::context;
use crate::policy::{Action, Policy};
use anyhow::{bail, Result};
use std::io::{self, Write};
use std::process::Command;

/// `termaxa run -- <cmd...>`: gatekept execution from the CLI.
pub fn run(paths: &crate::paths::Paths, argv: &[String]) -> Result<i32> {
    if argv.is_empty() {
        bail!("nothing to run — usage: termaxa run -- <command...>");
    }
    let command = shell_join(argv);

    let policy = Policy::load(&paths.policy_file())?;
    let ctx =
        crate::resolve::EvalContext::from_paths(std::env::current_dir().unwrap_or_default(), paths);
    let base = policy.evaluate_command(&command, &ctx);
    let signals = context::gather(&command);
    let (decision, escalated) = context::apply(base, &signals);

    println!("┌ termaxa");
    println!("│ command : {}", command);
    println!("│ decision: {}", decision.action);
    println!("│ reason  : {}", decision.reason);
    for s in &signals {
        println!(
            "│ context : {}{}",
            s.label,
            if s.escalate { "  ⚠" } else { "" }
        );
    }
    println!("└");

    crate::notify::maybe_send(
        &policy,
        &decision.action.to_string(),
        &command,
        &decision.reason,
        "run",
    );

    // The runner executes the command itself, so ITS process cwd is the
    // correct resolution base — unlike the hook, whose process cwd is the
    // harness's, not the command's. Threaded explicitly so that distinction
    // is visible rather than relying on an ambient default inside resolve.
    let run_cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut backup_id: Option<String> = None;
    let insure = |backup_id: &mut Option<String>| {
        match crate::backup::take(&paths.state_dir, &command, &run_cwd) {
            Ok(Some(rec)) => {
                println!("🛟 backup {} — {}", rec.id, rec.note);
                *backup_id = Some(rec.id);
            }
            Ok(None) => {} // nothing to insure
            Err(e) => eprintln!(
                "termaxa: backup failed ({}); proceeding — command was approved",
                e
            ),
        }
    };

    let root = paths.project_dir.parent();
    let preview_summary =
        crate::preview::generate(&command, root, &run_cwd, true).map(|p| p.summary);

    let (approved, exit_code) = match decision.action {
        Action::Deny => {
            eprintln!("termaxa: blocked by policy.");
            (Some(false), None)
        }
        Action::Ask => {
            if let Some(pv) = crate::preview::generate(&command, root, &run_cwd, true) {
                println!("┌ {}", pv.title);
                for l in &pv.lines {
                    println!("│{}", l);
                }
                println!("└");
            }
            print!("Proceed? [y/N] ");
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            let yes = matches!(line.trim().to_lowercase().as_str(), "y" | "yes");
            if yes {
                insure(&mut backup_id);
                let code = execute(argv)?;
                (Some(true), Some(code))
            } else {
                eprintln!("termaxa: declined.");
                (Some(false), None)
            }
        }
        Action::Allow => {
            insure(&mut backup_id);
            let code = execute(argv)?;
            (None, Some(code))
        }
    };

    let intent_label = crate::intent::classify_command(&command).map(|i| i.label().to_string());

    let log = AuditLog::new(&paths.state_dir)?;
    let (ts_ms, ts) = now();
    log.append(&AuditEntry {
        ts_ms,
        ts,
        source: "run".into(),
        // `run` is the human's own surface: no agent harness produced it, so
        // naming one would be false provenance.
        actor: None,
        decided_by: Some(decision.source.as_str().to_string()),
        command,
        decision: decision.action.to_string(),
        matched_rule: decision.matched_rule,
        reason: decision.reason,
        signals: signals.iter().map(|s| s.label.clone()).collect(),
        escalated,
        session: None,
        backup: backup_id,
        preview: preview_summary,
        intent: intent_label,
        approved,
        exit_code,
        cwd: std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        // Filled by `append`, which links each entry to the one before it.
        prev: None,
        hash: None,
    })?;

    Ok(exit_code.unwrap_or(1))
}

/// Rebuild a display/analysis string from argv WITHOUT losing token
/// boundaries: any argument containing whitespace or quotes is re-quoted so
/// downstream tokenizers (previews, backups) see the original structure.
/// A naive `join(" ")` flattens `-c "TRUNCATE users"` into three words —
/// which is how v0.6 initially failed to insure a truncate.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty()
                || a.chars()
                    .any(|c| c.is_whitespace() || c == '"' || c == '\'')
            {
                format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn execute(argv: &[String]) -> Result<i32> {
    let status = Command::new(&argv[0]).args(&argv[1..]).status()?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::TempTree;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    /// A project whose policy gives every command the same verdict.
    fn project_with_default(tmp: &TempTree, default: &str) -> crate::paths::Paths {
        let project_dir = tmp.dir("proj/.termaxa");
        std::fs::write(
            project_dir.join("policy.yaml"),
            format!("version: 1\ndefault: {}\nrules: []\n", default),
        )
        .expect("policy must be writable");
        crate::paths::Paths {
            project_dir,
            state_dir: tmp.dir("state"),
        }
    }

    #[test]
    fn shell_join_leaves_ordinary_arguments_alone() {
        // Nothing here carries structure, so nothing should gain quotes —
        // the reconstruction is what rules are matched against.
        assert_eq!(shell_join(&argv(&["git", "status"])), "git status");
    }

    #[test]
    fn shell_join_keeps_a_quoted_argument_in_one_piece() {
        // The v0.6 failure this function exists for: `-c "TRUNCATE users"`
        // flattened into three words, so the backup layer never saw a
        // truncate worth insuring.
        assert_eq!(
            shell_join(&argv(&["psql", "-c", "TRUNCATE users"])),
            "psql -c \"TRUNCATE users\""
        );
    }

    #[test]
    fn shell_join_quotes_an_empty_argument() {
        // An empty argument is a token too; unquoted it vanishes from the
        // string entirely and `sh -c ""` reads as a bare `sh -c`.
        assert_eq!(shell_join(&argv(&["sh", "-c", ""])), "sh -c \"\"");
    }

    #[test]
    fn shell_join_quotes_on_a_quote_character_without_whitespace() {
        assert_eq!(shell_join(&argv(&["say", "it's"])), "say \"it's\"");
        assert_eq!(shell_join(&argv(&["say", "a\"b"])), "say \"a\\\"b\"");
    }

    #[test]
    fn shell_join_escapes_backslashes_before_quoting() {
        // Backslashes go first, or the escape added for `"` gets escaped in
        // turn and the quoting closes early.
        assert_eq!(
            shell_join(&argv(&["cat", "C:\\tmp dir\\x"])),
            "cat \"C:\\\\tmp dir\\\\x\""
        );
    }

    #[cfg(unix)]
    #[test]
    fn execute_returns_the_child_exit_code() {
        // 7 on purpose: none of 0, 1 or -1, so a body that reports a fixed
        // code instead of the child's cannot pass.
        assert_eq!(execute(&argv(&["sh", "-c", "exit 7"])).unwrap(), 7);
    }

    #[cfg(windows)]
    #[test]
    fn execute_returns_the_child_exit_code() {
        assert_eq!(execute(&argv(&["cmd", "/C", "exit 7"])).unwrap(), 7);
    }

    #[test]
    fn execute_reports_an_unlaunchable_command_as_an_error() {
        // Spawn failure must surface, not read as a successful exit 0.
        assert!(execute(&argv(&["termaxa-no-such-binary-xyzzy"])).is_err());
    }

    #[test]
    fn run_refuses_an_empty_command_line() {
        let tmp = TempTree::new("runner-empty");
        let paths = project_with_default(&tmp, "allow");

        let err = run(&paths, &[]).expect_err("there is nothing to gate or execute");
        assert!(
            err.to_string().contains("nothing to run"),
            "the error should say what was missing, got: {}",
            err
        );
    }

    #[test]
    fn run_blocks_a_denied_command_and_records_the_decision() {
        let tmp = TempTree::new("runner-deny");
        let paths = project_with_default(&tmp, "deny");

        let code = run(&paths, &argv(&["echo", "hello"])).expect("a block is not an error");
        assert_eq!(code, 1, "a blocked command must not report success");

        let log = std::fs::read_to_string(paths.log_file())
            .expect("every decision is logged, including the ones that ran nothing");
        assert!(log.contains("\"decision\":\"deny\""), "{}", log);
        assert!(log.contains("\"command\":\"echo hello\""), "{}", log);
        // Nothing was launched, so there is no child exit code to report.
        assert!(log.contains("\"exit_code\":null"), "{}", log);
        assert!(log.contains("\"approved\":false"), "{}", log);
    }
}
