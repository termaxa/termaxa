use crate::audit::{now, AuditEntry, AuditLog};
use crate::context;
use crate::policy::{Action, Policy};
use anyhow::Result;
use serde_json::json;
use std::io::Read;

/// Which agent is calling us. Detected from the input's shape, so
/// `termaxa hook` is ONE command that speaks every agent's dialect.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Dialect {
    /// Claude Code PreToolUse: {"tool_name":"Bash","tool_input":{"command":...}}
    /// -> {"hookSpecificOutput":{"permissionDecision":...}}
    ClaudeCode,
    /// Cursor beforeShellExecution (v1.7+): {"hook_event_name":"beforeShellExecution","command":...}
    /// -> {"permission":..., "agent_message":...}
    Cursor,
    /// OpenAI Codex CLI: same PreToolUse/hookSpecificOutput shape as Claude Code,
    /// but the event self-identifies as codex via `agent` / hook_event_name.
    Codex,
    /// GitHub Copilot CLI: {"toolName":"shell","toolArgs":"{\"command\":...}"}
    /// -> bare {"permissionDecision":..., "permissionDecisionReason":...} (no wrapper)
    Copilot,
}

pub struct ParsedHook {
    pub dialect: Dialect,
    pub command: String,
    pub cwd: String,
    pub session: Option<String>,
}

/// Raw JSON in -> normalized hook event out. None = not for us; step aside.
pub fn parse_input(raw: &str) -> Option<ParsedHook> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);

    // Cursor: hook_event_name + top-level command
    if s("hook_event_name").as_deref() == Some("beforeShellExecution") {
        let command = s("command")?;
        if command.is_empty() {
            return None;
        }
        return Some(ParsedHook {
            dialect: Dialect::Cursor,
            command,
            cwd: s("cwd").unwrap_or_default(),
            session: s("conversation_id"),
        });
    }

    // Copilot CLI: toolName + toolArgs (a JSON *string* holding the args)
    if let Some(tool) = s("toolName") {
        if tool == "shell" || tool == "bash" || tool == "run_in_terminal" {
            // toolArgs may arrive as a JSON string OR an inline object.
            let args_val = match v.get("toolArgs") {
                Some(serde_json::Value::String(st)) => {
                    serde_json::from_str::<serde_json::Value>(st).unwrap_or(serde_json::Value::Null)
                }
                Some(other) => other.clone(),
                None => serde_json::Value::Null,
            };
            let command = args_val
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            if command.is_empty() {
                return None;
            }
            return Some(ParsedHook {
                dialect: Dialect::Copilot,
                command,
                cwd: s("cwd").or_else(|| s("workingDirectory")).unwrap_or_default(),
                session: s("sessionId").or_else(|| s("session_id")),
            });
        }
    }

    // Claude Code & Codex share the PreToolUse/tool_input.command shape.
    // Distinguish by any explicit agent tag; default the shared shape to Claude Code.
    if s("tool_name").as_deref() == Some("Bash")
        || s("hook_event_name").as_deref() == Some("PreToolUse")
    {
        let command = v
            .get("tool_input")
            .and_then(|t| t.get("command"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        if command.is_empty() {
            return None;
        }
        // Codex self-identifies via an `agent`/`source` field or codex-prefixed session.
        let looks_codex = s("agent").map(|a| a.to_lowercase().contains("codex")).unwrap_or(false)
            || s("source").map(|a| a.to_lowercase().contains("codex")).unwrap_or(false);
        return Some(ParsedHook {
            dialect: if looks_codex { Dialect::Codex } else { Dialect::ClaudeCode },
            command,
            cwd: s("cwd").unwrap_or_default(),
            session: s("session_id").or_else(|| s("conversation_id")),
        });
    }
    None
}

/// Decision -> the JSON each agent expects on stdout.
pub fn render_response(dialect: Dialect, permission: &str, reason: &str) -> String {
    match dialect {
        Dialect::ClaudeCode => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission,
                "permissionDecisionReason": reason,
            }
        })
        .to_string(),
        // Official docs use snake_case; early builds used camelCase. Emit both —
        // unknown keys are ignored, and this survives either Cursor version.
        Dialect::Cursor => json!({
            "permission": permission,
            "agent_message": reason,
            "user_message": reason,
            "agentMessage": reason,
            "userMessage": reason,
        })
        .to_string(),
        // Codex uses the same PreToolUse/hookSpecificOutput contract as Claude Code.
        Dialect::Codex => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission,
                "permissionDecisionReason": reason,
            }
        })
        .to_string(),
        // Copilot CLI expects the decision at the top level (no hookSpecificOutput wrapper).
        Dialect::Copilot => json!({
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        })
        .to_string(),
    }
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

    let input = match parse_input(&buf) {
        Some(p) => p,
        None => return Ok(()), // not for us; stay out of the way
    };
    let command = input.command.clone();

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
            session: input.session.clone(),
            backup: backup_id.clone(),
            preview: preview_summary.clone(),
            approved: None,
            exit_code: None,
            cwd: input.cwd.clone(),
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

    println!("{}", render_response(input.dialect, permission, &reason));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cursor_dialect() {
        let raw = r#"{"hook_event_name":"beforeShellExecution","command":"git push --force","cwd":"/w","conversation_id":"c-1"}"#;
        let p = parse_input(raw).unwrap();
        assert_eq!(p.dialect, Dialect::Cursor);
        assert_eq!(p.command, "git push --force");
        assert_eq!(p.session.as_deref(), Some("c-1"));
    }

    #[test]
    fn detects_claude_dialect() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s-1","cwd":"/w"}"#;
        let p = parse_input(raw).unwrap();
        assert_eq!(p.dialect, Dialect::ClaudeCode);
        assert_eq!(p.command, "git status");
    }

    #[test]
    fn ignores_unrelated_input() {
        assert!(parse_input(r#"{"hook_event_name":"afterFileEdit"}"#).is_none());
        assert!(parse_input("not json").is_none());
    }

    #[test]
    fn renders_each_dialect() {
        let c = render_response(Dialect::Cursor, "deny", "[termaxa] blocked");
        assert!(c.contains("\"permission\":\"deny\"") && c.contains("agent_message"));
        let cc = render_response(Dialect::ClaudeCode, "ask", "[termaxa] careful");
        assert!(cc.contains("hookSpecificOutput") && cc.contains("permissionDecision"));
    }

    #[test]
    fn detects_copilot_dialect() {
        let raw = r#"{"toolName":"shell","toolArgs":"{\"command\":\"rm -rf /\"}","sessionId":"cop-1"}"#;
        let p = parse_input(raw).unwrap();
        assert_eq!(p.dialect, Dialect::Copilot);
        assert_eq!(p.command, "rm -rf /");
        assert_eq!(p.session.as_deref(), Some("cop-1"));
    }

    #[test]
    fn copilot_accepts_inline_toolargs_object() {
        let raw = r#"{"toolName":"shell","toolArgs":{"command":"git status"}}"#;
        let p = parse_input(raw).unwrap();
        assert_eq!(p.dialect, Dialect::Copilot);
        assert_eq!(p.command, "git status");
    }

    #[test]
    fn detects_codex_dialect() {
        let raw = r#"{"hook_event_name":"PreToolUse","agent":"codex-cli","tool_input":{"command":"git push --force"}}"#;
        let p = parse_input(raw).unwrap();
        assert_eq!(p.dialect, Dialect::Codex);
        assert_eq!(p.command, "git push --force");
    }

    #[test]
    fn shared_shape_without_tag_defaults_to_claude() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        assert_eq!(parse_input(raw).unwrap().dialect, Dialect::ClaudeCode);
    }

    #[test]
    fn copilot_render_is_unwrapped() {
        let r = render_response(Dialect::Copilot, "deny", "[termaxa] no");
        assert!(r.contains("permissionDecision") && !r.contains("hookSpecificOutput"));
    }
}
