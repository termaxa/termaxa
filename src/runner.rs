use crate::audit::{now, AuditEntry, AuditLog};
use crate::context;
use crate::policy::{Action, Policy};
use anyhow::{bail, Result};
use std::io::{self, Write};
use std::path::Path;
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
    // #73: what the delete targets look like now, so that what runs is what
    // was judged. Between the verdict, the prompt a person answers, and the
    // copy, the tree can change; the re-check just before `execute` refuses
    // if it did, naming the counts, and the person re-runs to see the new
    // preview.
    let judged = crate::delete::target_signature(&command, &run_cwd);
    let mut recheck_refusal: Option<String> = None;
    let mut backup_id: Option<String> = None;
    // Returns whether the command may go on to run. A failed backup proceeds
    // with a warning by default; a policy that sets `backup_failure: deny`
    // refuses instead, because nobody is reading warnings on an unattended run.
    let insure = |backup_id: &mut Option<String>| -> bool {
        match crate::backup::take(&paths.state_dir, &command, &run_cwd) {
            Ok(Some(rec)) => {
                println!("🛟 backup {} — {}", rec.id, rec.note);
                *backup_id = Some(rec.id);
                // Retention (#72): one eligible backup at most per take.
                if let Ok(done) = crate::backup::prune(&paths.state_dir, policy.retention, Some(1))
                {
                    for id in done.removed {
                        println!("{}", crate::ui::dim(&format!("   pruned {id} (retention)")));
                    }
                }
                true
            }
            Ok(None) => true, // nothing to insure
            Err(e) if policy.backup_failure == crate::policy::BackupFailure::Deny => {
                eprintln!(
                    "termaxa: backup failed ({}); refused — the policy sets \
                     `backup_failure: deny`, so an uninsured command does not run",
                    e
                );
                false
            }
            Err(e) => {
                eprintln!(
                    "termaxa: backup failed ({}); proceeding — command was approved",
                    e
                );
                true
            }
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
            // An answer has to come from a person at a terminal. Under
            // `wrap`, the agent's Bash tool hands us a pipe that never
            // closes: the prompt blocked for 120 s until the harness gave
            // up (Claude Code, Sep 10, 2026) - and the agent itself noted
            // it could have piped `y` into the same stdin. Both end here:
            // no terminal, no ask, refused with the reason. A pipe with a
            // `y` in it is not a human.
            if !stdin_is_terminal() {
                eprintln!(
                    "termaxa: this needs a human at a terminal and stdin is not one \
                     (a pipe, a harness, a script) — refused rather than run unasked. \
                     Add an allow rule, or run it yourself."
                );
                (Some(false), None)
            } else {
                print!("Proceed? [y/N] ");
                io::stdout().flush()?;
                let mut line = String::new();
                let read = io::stdin().read_line(&mut line)?;

                // NO ONE TO ASK is not the same as a refusal, and saying
                // "declined" when nobody declined is a lie the user cannot debug.
                // `read_line` returns Ok(0) on a closed or non-interactive stdin -
                // which is exactly what a `wrap` shim hands us, since the agent
                // is not a person at a terminal.
                //
                // The verdict is unchanged: an `ask` nobody can answer must not
                // run. Falling through to the y/N match would already have
                // declined, by accident of an empty string failing to equal "y";
                // this makes it a decision with a message that fits (#48 - a gate
                // whose refusals are unexplainable gets uninstalled).
                if read == 0 {
                    eprintln!(
                        "termaxa: this needs a human and stdin is not interactive — \
                     refused rather than run unasked."
                    );
                    (Some(false), None)
                } else if matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
                    if insure(&mut backup_id) {
                        if let Some(why) = changed_since(&command, &run_cwd, judged.as_ref()) {
                            eprintln!("termaxa: {why}");
                            recheck_refusal = Some(why);
                            (Some(false), None)
                        } else {
                            let code = execute(argv)?;
                            (Some(true), Some(code))
                        }
                    } else {
                        (Some(false), None)
                    }
                } else {
                    eprintln!("termaxa: declined.");
                    (Some(false), None)
                }
            }
        }
        Action::Allow => {
            if insure(&mut backup_id) {
                if let Some(why) = changed_since(&command, &run_cwd, judged.as_ref()) {
                    eprintln!("termaxa: {why}");
                    recheck_refusal = Some(why);
                    (Some(false), None)
                } else {
                    let code = execute(argv)?;
                    (None, Some(code))
                }
            } else {
                (Some(false), None)
            }
        }
    };
    // A refused re-check is recorded as the refusal it was, not as the
    // verdict that preceded it.
    let decision = match recheck_refusal {
        Some(why) => crate::policy::Decision {
            action: Action::Deny,
            source: crate::policy::DecisionSource::Context,
            matched_rule: decision.matched_rule.clone(),
            reason: why,
        },
        None => decision,
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

/// Whether stdin is a terminal - the only place an answer to an ask can come
/// from. A pipe from a harness never closes, and a pipe from an agent can
/// carry a `y`; neither is a person.
#[cfg(unix)]
fn stdin_is_terminal() -> bool {
    // SAFETY: isatty on a constant fd is a pure query with no side effects.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}
#[cfg(not(unix))]
fn stdin_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Rebuild a display/analysis string from argv WITHOUT losing token
/// boundaries: any argument containing whitespace or quotes is re-quoted so
/// downstream tokenizers (previews, backups) see the original structure.
/// A naive `join(" ")` flattens `-c "TRUNCATE users"` into three words —
/// which is how v0.6 initially failed to insure a truncate.
pub(crate) fn shell_join(argv: &[String]) -> String {
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

/// #73: the target set re-scanned under the same budget and compared with
/// what was judged. `Some(reason)` when it differs; `None` when it is the
/// same, when there was nothing to compare (no delete targets, or a tree
/// over the budget both times), and when the budget was hit now but not
/// then - that last case is a change too, and is said so.
fn changed_since(
    command: &str,
    cwd: &Path,
    judged: Option<&crate::delete::TargetSignature>,
) -> Option<String> {
    let judged = judged?;
    match crate::delete::target_signature(command, cwd) {
        Some(now) if now == *judged => None,
        Some(now) => Some(format!(
            "the target set changed since it was judged ({} files across {} directories then, {} across {} now) — refused; run it again to see the new preview",
            judged.files, judged.dirs, now.files, now.dirs
        )),
        None => Some(format!(
            "the target set changed since it was judged ({} files across {} directories then, past the scan budget now) — refused; run it again to see the new preview",
            judged.files, judged.dirs
        )),
    }
}

fn execute(argv: &[String]) -> Result<i32> {
    // Outside the wrapper's shims (#65): under `termaxa wrap`, `sh` by name
    // is the shim, and the shim is what brought us here.
    let inherited = std::env::var_os("PATH");
    let (program, path) = match crate::paths::home_base() {
        Ok(home) => crate::wrap::outside_shims(&argv[0], inherited.as_deref(), &home),
        Err(_) => (argv[0].clone().into(), inherited.unwrap_or_default()),
    };
    let status = Command::new(&program)
        .args(&argv[1..])
        .env("PATH", &path)
        .status()?;
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

    /// #73: the target set is signed when the command is judged and
    /// re-signed just before it runs. Unchanged: runs. A file added,
    /// removed or rewritten in between: refused, with both counts in the
    /// reason. No delete targets, or a tree past the scan budget both
    /// times: nothing to compare, runs as today.
    #[test]
    fn a_target_set_that_changed_since_it_was_judged_is_refused_and_says_so() {
        let tmp = TempTree::new("recheck");
        let cwd = tmp.dir("proj");
        let scratch = tmp.dir("proj/scratch");
        for i in 1..=3 {
            std::fs::write(scratch.join(format!("f{i}")), "x").unwrap();
        }
        let judged = crate::delete::target_signature("rm -rf scratch", &cwd)
            .expect("three files: a signature");
        assert_eq!((judged.files, judged.dirs), (3, 1));
        assert_eq!(
            changed_since("rm -rf scratch", &cwd, Some(&judged)),
            None,
            "unchanged: runs"
        );

        std::fs::write(scratch.join("f4"), "x").unwrap();
        let why = changed_since("rm -rf scratch", &cwd, Some(&judged)).expect("a file arrived");
        assert!(
            why.contains("3 files across 1 directories then, 4 across 1 now"),
            "{why}"
        );
        assert!(why.contains("refused"), "{why}");

        // A rewrite with the same count is still a change: size and mtime
        // are in the signature.
        let judged = crate::delete::target_signature("rm -rf scratch", &cwd).unwrap();
        std::fs::write(scratch.join("f1"), "longer content").unwrap();
        assert!(changed_since("rm -rf scratch", &cwd, Some(&judged)).is_some());

        // Nothing to compare: no delete target, or none that exists.
        assert_eq!(crate::delete::target_signature("git status", &cwd), None);
        assert_eq!(
            crate::delete::target_signature("rm -rf nothing-here", &cwd),
            None
        );
        assert_eq!(changed_since("git status", &cwd, None), None);
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
