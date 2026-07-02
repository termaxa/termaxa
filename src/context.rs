use crate::policy::{Action, Decision};
use std::process::Command;

/// A signal the context engine noticed about the environment or the command.
#[derive(Debug, Clone)]
pub struct Signal {
    pub label: String,
    pub escalate: bool,
}

/// Gather cheap, local context signals. Never fails; absence of signal is fine.
pub fn gather(command: &str) -> Vec<Signal> {
    let mut signals = Vec::new();
    let cmd_lc = command.to_lowercase();

    // Git branch awareness: pushing/committing while on a protected branch.
    if cmd_lc.starts_with("git push") || cmd_lc.starts_with("git commit") {
        if let Some(branch) = current_git_branch() {
            let protected = matches!(branch.as_str(), "main" | "master" | "production" | "release");
            signals.push(Signal {
                label: format!("current branch: {}", branch),
                escalate: protected && cmd_lc.starts_with("git push"),
            });
        }
    }

    // Force / destructive flags.
    for flag in ["--force", "-f ", "--hard", "--no-verify", "-rf"] {
        if cmd_lc.contains(flag) {
            signals.push(Signal {
                label: format!("destructive flag detected: {}", flag.trim()),
                escalate: true,
            });
        }
    }

    // Production markers in the command itself (connection strings, env names).
    for marker in ["prod", "production"] {
        if cmd_lc.contains(marker) && !cmd_lc.starts_with("git") {
            signals.push(Signal {
                label: format!("possible production target: contains `{}`", marker),
                escalate: true,
            });
            break;
        }
    }

    // SQL red flags.
    for stmt in ["drop table", "drop database", "truncate ", "delete from"] {
        if cmd_lc.contains(stmt) {
            signals.push(Signal {
                label: format!("destructive SQL: `{}`", stmt.trim()),
                escalate: true,
            });
        }
    }

    signals
}

/// Escalation ladder: allow -> ask. `ask` and `deny` are never escalated further
/// (a human is already in the loop, or it's already blocked), and context never
/// downgrades a decision.
pub fn apply(decision: Decision, signals: &[Signal]) -> (Decision, bool) {
    let should_escalate = signals.iter().any(|s| s.escalate);
    if should_escalate && decision.action == Action::Allow {
        let labels: Vec<&str> = signals
            .iter()
            .filter(|s| s.escalate)
            .map(|s| s.label.as_str())
            .collect();
        return (
            Decision {
                action: Action::Ask,
                matched_rule: decision.matched_rule,
                reason: format!(
                    "{} — escalated to ask by context: {}",
                    decision.reason,
                    labels.join("; ")
                ),
            },
            true,
        );
    }
    (decision, false)
}

fn current_git_branch() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if branch.is_empty() {
        None
    } else {
        Some(branch)
    }
}
