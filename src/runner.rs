use crate::audit::{now, AuditEntry, AuditLog};
use crate::context;
use crate::policy::{Action, Policy};
use anyhow::{bail, Result};
use std::io::{self, Write};
use std::process::Command;

/// `aegis run -- <cmd...>`: gatekept execution from the CLI.
pub fn run(paths: &crate::paths::Paths, argv: &[String]) -> Result<i32> {
    if argv.is_empty() {
        bail!("nothing to run — usage: aegis run -- <command...>");
    }
    let command = shell_join(argv);

    let policy = Policy::load(&paths.policy_file())?;
    let base = policy.evaluate_command(&command);
    let signals = context::gather(&command);
    let (decision, escalated) = context::apply(base, &signals);

    println!("┌ aegis");
    println!("│ command : {}", command);
    println!("│ decision: {}", decision.action);
    println!("│ reason  : {}", decision.reason);
    for s in &signals {
        println!("│ context : {}{}", s.label, if s.escalate { "  ⚠" } else { "" });
    }
    println!("└");

    crate::notify::maybe_send(
        &policy,
        &decision.action.to_string(),
        &command,
        &decision.reason,
        "run",
    );

    let mut backup_id: Option<String> = None;
    let insure = |backup_id: &mut Option<String>| {
        match crate::backup::take(&paths.state_dir, &command) {
            Ok(Some(rec)) => {
                println!("🛟 backup {} — {}", rec.id, rec.note);
                *backup_id = Some(rec.id);
            }
            Ok(None) => {} // nothing to insure
            Err(e) => eprintln!("aegis: backup failed ({}); proceeding — command was approved", e),
        }
    };

    let (approved, exit_code) = match decision.action {
        Action::Deny => {
            eprintln!("aegis: blocked by policy.");
            (Some(false), None)
        }
        Action::Ask => {
            if let Some(pv) = crate::preview::generate(&command) {
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
                eprintln!("aegis: declined.");
                (Some(false), None)
            }
        }
        Action::Allow => {
            insure(&mut backup_id);
            let code = execute(argv)?;
            (None, Some(code))
        }
    };

    let log = AuditLog::new(&paths.state_dir)?;
    let (ts_ms, ts) = now();
    log.append(&AuditEntry {
        ts_ms,
        ts,
        source: "run".into(),
        command,
        decision: decision.action.to_string(),
        matched_rule: decision.matched_rule,
        reason: decision.reason,
        signals: signals.iter().map(|s| s.label.clone()).collect(),
        escalated,
        session: None,
        backup: backup_id,
        approved,
        exit_code,
        cwd: std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
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
            if a.is_empty() || a.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'') {
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
