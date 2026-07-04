use crate::audit::{now, AuditEntry, AuditLog};
use crate::context;
use crate::policy::{Action, Policy};
use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use std::io::Read;

/// Subset of the Claude Code PreToolUse hook input we care about.
/// See: https://docs.claude.com/en/docs/claude-code/hooks
#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
}

/// Run as a Claude Code PreToolUse hook.
///
/// Reads the hook event JSON from stdin and prints a JSON decision:
///   allow -> permissionDecision "allow"  (command runs without prompting)
///   ask   -> permissionDecision "ask"    (Claude Code shows its own approval prompt)
///   deny  -> permissionDecision "deny"   (blocked; reason is fed back to the model)
///
/// Non-Bash tools and unparsable input fall through with no decision
/// (exit 0, no output), leaving Claude Code's normal permission flow intact.
pub fn run(paths: &crate::paths::Paths) -> Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;

    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => return Ok(()), // not for us; stay out of the way
    };

    if input.tool_name != "Bash" {
        return Ok(());
    }

    let command = input
        .tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if command.is_empty() {
        return Ok(());
    }

    let policy = Policy::load(&paths.policy_file())?;

    let base = policy.evaluate_command(&command);
    let signals = context::gather(&command);
    let (decision, escalated) = context::apply(base, &signals);

    let preview_summary = crate::preview::generate(&command).map(|p| p.summary);

    // Insure before allowing: PreToolUse runs before execution, so a backup
    // taken here is guaranteed to predate the command. Never for deny.
    let mut backup_id: Option<String> = None;
    if decision.action != Action::Deny {
        if let Ok(Some(rec)) = crate::backup::take(&paths.state_dir, &command) {
            backup_id = Some(rec.id);
        }
    }

    // Audit first, decide second: even denied attempts are part of the record.
    if let Ok(log) = AuditLog::new(&paths.state_dir) {
        let (ts_ms, ts) = now();
        let _ = log.append(&AuditEntry {
            ts_ms,
            ts,
            source: "hook".into(),
            command: command.clone(),
            decision: decision.action.to_string(),
            matched_rule: decision.matched_rule.clone(),
            reason: decision.reason.clone(),
            signals: signals.iter().map(|s| s.label.clone()).collect(),
            escalated,
            session: input.session_id.clone(),
            backup: backup_id.clone(),
            preview: preview_summary.clone(),
            approved: None,
            exit_code: None,
            cwd: input.cwd.unwrap_or_default(),
        });
    }

    let permission = match decision.action {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    };

    let mut reason = format!("[termaxa] {}", decision.reason);
    if escalated {
        reason.push_str(" (context-escalated)");
    }
    if matches!(decision.action, Action::Ask | Action::Deny) {
        if let Some(s) = &preview_summary {
            reason.push_str(&format!(" | {}", s));
        }
    }
    if let Some(id) = &backup_id {
        reason.push_str(&format!(" | backup {}", id));
    }

    crate::notify::maybe_send(
        &policy,
        &decision.action.to_string(),
        &command,
        &decision.reason,
        "hook",
    );

    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    });
    println!("{}", out);
    Ok(())
}
