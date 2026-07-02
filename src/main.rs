mod audit;
mod backup;
mod context;
mod hook;
mod init;
mod notify;
mod pg;
mod policy;
mod preview;
mod runner;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use policy::Policy;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aegis",
    version,
    about = "Policy, approval, and audit layer between AI agents and your tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scaffold .aegis/ in the current directory and detect agents & tools
    Init {
        /// Also install the PreToolUse hook into .claude/settings.json
        #[arg(long = "claude-code")]
        claude_code: bool,
    },
    /// Evaluate a command against policy without running it
    Check {
        /// The command string, e.g. "git push --force origin main"
        command: Vec<String>,
    },
    /// Claude Code PreToolUse hook mode (reads hook JSON on stdin)
    Hook,
    /// Execute a command through the policy gate: aegis run -- git push
    Run {
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Show recent audit log entries
    Log {
        /// Number of entries to show
        #[arg(short, long, default_value_t = 20)]
        n: usize,
        /// Filter by decision: allow | ask | deny
        #[arg(long)]
        decision: Option<String>,
        /// Filter by source: hook | run | check
        #[arg(long)]
        source: Option<String>,
        /// Emit raw JSON lines instead of the pretty format
        #[arg(long)]
        json: bool,
    },
    /// Notification tools
    Notify {
        /// Send a probe message to the configured webhook and report loudly
        #[arg(long)]
        test: bool,
    },
    /// Aggregate statistics from the audit log
    Stats,
    /// List backups taken by the insurance engine
    Backups,
    /// Restore a backup by id (see `aegis backups`)
    Rollback { id: String },
}

fn main() {
    let cli = Cli::parse();
    let code = match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aegis: {:#}", e);
            2
        }
    };
    std::process::exit(code);
}

fn dispatch(cli: Cli) -> Result<i32> {
    match cli.command {
        Cmd::Init { claude_code } => {
            init::run(&std::env::current_dir()?, claude_code)?;
            Ok(0)
        }
        Cmd::Check { command } => {
            let cmd = command.join(" ");
            if cmd.trim().is_empty() {
                bail!("usage: aegis check \"<command>\"");
            }
            let aegis_dir = require_aegis_dir()?;
            let policy = Policy::load(&aegis_dir.join("policy.yaml"))?;
            let base = policy.evaluate(&cmd);
            let signals = context::gather(&cmd);
            let (decision, escalated) = context::apply(base, &signals);

            println!("command : {}", cmd);
            println!("decision: {}", decision.action);
            if let Some(rule) = &decision.matched_rule {
                println!("rule    : {}", rule);
            }
            println!("reason  : {}", decision.reason);
            for s in &signals {
                println!("context : {}{}", s.label, if s.escalate { "  ⚠" } else { "" });
            }
            if escalated {
                println!("note    : context escalated allow → ask");
            }
            if let Some(pv) = preview::generate(&cmd) {
                println!("\npreview : {}", pv.title);
                for l in &pv.lines {
                    println!("{}", l);
                }
            }
            // Record the dry-run in the audit trail with source "check".
            let log = audit::AuditLog::new(&aegis_dir)?;
            let (ts_ms, ts) = audit::now();
            log.append(&audit::AuditEntry {
                ts_ms,
                ts,
                source: "check".into(),
                command: cmd.clone(),
                decision: decision.action.to_string(),
                matched_rule: decision.matched_rule.clone(),
                reason: decision.reason.clone(),
                signals: signals.iter().map(|s| s.label.clone()).collect(),
                escalated,
                session: None,
                backup: None,
                approved: None,
                exit_code: None,
                cwd: std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
            })?;

            // Exit codes make `aegis check` scriptable: 0 allow, 3 ask, 4 deny.
            Ok(match decision.action {
                policy::Action::Allow => 0,
                policy::Action::Ask => 3,
                policy::Action::Deny => 4,
            })
        }
        Cmd::Hook => {
            let aegis_dir = require_aegis_dir()?;
            hook::run(&aegis_dir)?;
            Ok(0)
        }
        Cmd::Run { argv } => {
            let aegis_dir = require_aegis_dir()?;
            runner::run(&aegis_dir, &argv)
        }
        Cmd::Log { n, decision, source, json } => {
            let aegis_dir = require_aegis_dir()?;
            let log = audit::AuditLog::new(&aegis_dir)?;
            // Read generously, filter, then trim to n — so filters don't starve.
            let entries: Vec<_> = log
                .read_last(100_000)?
                .into_iter()
                .filter(|e| decision.as_deref().map_or(true, |d| e.decision == d))
                .filter(|e| source.as_deref().map_or(true, |s| e.source == s))
                .collect();
            let skip = entries.len().saturating_sub(n);
            let entries: Vec<_> = entries.into_iter().skip(skip).collect();
            if json {
                for e in &entries {
                    println!("{}", serde_json::to_string(e)?);
                }
                return Ok(0);
            }
            if entries.is_empty() {
                println!("(audit log is empty)");
                return Ok(0);
            }
            for e in entries {
                let mark = match e.decision.as_str() {
                    "allow" => "✓",
                    "ask" => "?",
                    _ => "✗",
                };
                let outcome = match (e.approved, e.exit_code) {
                    (Some(true), Some(code)) => format!("  → approved, exit {}", code),
                    (Some(false), _) => "  → not run".to_string(),
                    (None, Some(code)) => format!("  → exit {}", code),
                    _ => String::new(),
                };
                let sess = e
                    .session
                    .as_deref()
                    .map(|s| format!(" ({})", &s[..s.len().min(8)]))
                    .unwrap_or_default();
                println!(
                    "{} {} [{}{}] {} — {}{}{}",
                    e.ts,
                    mark,
                    e.source,
                    sess,
                    e.command,
                    e.reason,
                    if e.escalated { "  ⚠ escalated" } else { "" },
                    outcome
                );
            }
            Ok(0)
        }
        Cmd::Notify { test } => {
            let aegis_dir = require_aegis_dir()?;
            let policy = Policy::load(&aegis_dir.join("policy.yaml"))?;
            if test {
                notify::test(&policy)
            } else {
                println!("usage: aegis notify --test");
                Ok(1)
            }
        }
        Cmd::Stats => {
            let aegis_dir = require_aegis_dir()?;
            let log = audit::AuditLog::new(&aegis_dir)?;
            let entries = log.read_last(1_000_000)?;
            if entries.is_empty() {
                println!("(audit log is empty)");
                return Ok(0);
            }
            let total = entries.len();
            let count = |f: &dyn Fn(&audit::AuditEntry) -> bool| entries.iter().filter(|e| f(e)).count();
            println!("entries    : {}", total);
            println!("  allow    : {}", count(&|e| e.decision == "allow"));
            println!("  ask      : {}", count(&|e| e.decision == "ask"));
            println!("  deny     : {}", count(&|e| e.decision == "deny"));
            println!("by source  : hook {} / run {} / check {}",
                count(&|e| e.source == "hook"),
                count(&|e| e.source == "run"),
                count(&|e| e.source == "check"));
            println!("escalated  : {}", count(&|e| e.escalated));
            let sessions: std::collections::HashSet<_> =
                entries.iter().filter_map(|e| e.session.as_deref()).collect();
            println!("sessions   : {}", sessions.len());

            let mut denied: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for e in entries.iter().filter(|e| e.decision == "deny") {
                *denied.entry(e.command.as_str()).or_default() += 1;
            }
            let mut top: Vec<_> = denied.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1));
            if !top.is_empty() {
                println!("top denied :");
                for (cmd, n) in top.into_iter().take(5) {
                    println!("  {}× {}", n, cmd);
                }
            }
            Ok(0)
        }
        Cmd::Backups => {
            let aegis_dir = require_aegis_dir()?;
            let records = backup::list(&aegis_dir)?;
            if records.is_empty() {
                println!("(no backups yet)");
                return Ok(0);
            }
            for r in records {
                println!("{}  {}  [{}]  {}\n    insures: {}", r.id, r.ts, r.kind, r.note, r.command);
            }
            Ok(0)
        }
        Cmd::Rollback { id } => {
            let aegis_dir = require_aegis_dir()?;
            let records = backup::list(&aegis_dir)?;
            let Some(rec) = records.iter().find(|r| r.id == id) else {
                bail!("no backup with id `{}` — see `aegis backups`", id);
            };
            println!("restore  : {} [{}]", rec.id, rec.kind);
            println!("saved    : {}", rec.note);
            println!("insured  : {}", rec.command);
            print!("Restoring writes data. Proceed? [y/N] ");
            use std::io::Write as _;
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
                eprintln!("aegis: rollback declined.");
                return Ok(1);
            }
            let msg = backup::restore(&aegis_dir, &id)?;
            println!("✓ {}", msg);
            Ok(0)
        }
    }
}

/// Find .aegis/ by walking up from cwd; error with a helpful hint if absent.
fn require_aegis_dir() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    match Policy::find_policy_file(&cwd) {
        Some(policy_file) => Ok(policy_file.parent().unwrap().to_path_buf()),
        None => bail!("no .aegis/policy.yaml found in this directory or any parent — run `aegis init` first"),
    }
}
