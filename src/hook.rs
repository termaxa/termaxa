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

/// Normalize a URI-style path to a native one.
/// Cursor emits workspace roots like "/c:/Users/User/code/proj" on Windows;
/// convert to "c:/Users/User/code/proj" (which Rust's Path handles fine).
/// On Unix, a leading-slash path is already native, so leave it alone.
fn normalize_uri_path(p: &str) -> String {
    // "/c:/..." -> "c:/..."  (strip the leading slash before a drive letter)
    let bytes = p.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[2] == b':' && bytes[1].is_ascii_alphabetic() {
        return p[1..].to_string();
    }
    p.to_string()
}

pub fn parse_input(raw: &str) -> Option<ParsedHook> {
    // Cursor (and some Windows shells) prepend a UTF-8 BOM; strip it or the
    // JSON parse fails on the leading bytes.
    let raw = raw.trim_start_matches('\u{feff}').trim();
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);

    // Cursor: hook_event_name + top-level command
    if s("hook_event_name").as_deref() == Some("beforeShellExecution") {
        let command = s("command")?;
        if command.is_empty() {
            return None;
        }
        // Cursor sends an empty "cwd" and puts the project path in
        // "workspace_roots" (URI-style, e.g. "/c:/Users/..."). Use cwd if
        // present, else the first workspace root, normalized to a native path.
        let cwd = {
            let raw_cwd = s("cwd").unwrap_or_default();
            if !raw_cwd.is_empty() {
                raw_cwd
            } else {
                v.get("workspace_roots")
                    .and_then(|w| w.as_array())
                    .and_then(|a| a.first())
                    .and_then(|x| x.as_str())
                    .map(normalize_uri_path)
                    .unwrap_or_default()
            }
        };
        return Some(ParsedHook {
            dialect: Dialect::Cursor,
            command,
            cwd,
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
                cwd: s("cwd")
                    .or_else(|| s("workingDirectory"))
                    .unwrap_or_default(),
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
        let looks_codex = s("agent")
            .map(|a| a.to_lowercase().contains("codex"))
            .unwrap_or(false)
            || s("source")
                .map(|a| a.to_lowercase().contains("codex"))
                .unwrap_or(false);
        return Some(ParsedHook {
            dialect: if looks_codex {
                Dialect::Codex
            } else {
                Dialect::ClaudeCode
            },
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
pub fn run() -> Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;

    // Diagnostic: set TERMAXA_HOOK_DEBUG=<path> to capture exactly what the
    // agent delivered (raw stdin + argv). Invaluable for debugging Windows
    // hook invocation where stdin delivery varies by agent.
    if let Ok(dbg) = std::env::var("TERMAXA_HOOK_DEBUG") {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&dbg)
        {
            let argv: Vec<String> = std::env::args().collect();
            let _ = writeln!(
                f,
                "--- {} ---\nARGV: {:?}\nSTDIN_LEN: {}\nSTDIN: {}\n",
                now().1,
                argv,
                buf.len(),
                buf
            );
        }
    }

    let input = match parse_input(&buf) {
        Some(p) => p,
        None => return Ok(()), // not for us; stay out of the way
    };
    let command = input.command.clone();

    // Agents spawn the hook with an arbitrary working directory, but they tell us
    // the real project dir in the payload's `cwd`. Resolve the policy explicitly
    // from THAT path rather than mutating the global process cwd (which would make
    // any later relative-path logic ambiguous). This bug affected every agent; it
    // only surfaced with Cursor because Claude Code happened to spawn hooks inside
    // the project dir, masking the incorrect assumption.
    let start_dir = if !input.cwd.is_empty() && std::path::Path::new(&input.cwd).is_dir() {
        std::path::PathBuf::from(&input.cwd)
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    let paths = crate::paths::resolve_from(&start_dir)?;

    // One-line resolution trace (reviewer request): set TERMAXA_HOOK_DEBUG to a
    // file path and this records exactly what got resolved, so future debugging
    // is minutes not hours.
    if let Ok(dbg) = std::env::var("TERMAXA_HOOK_DEBUG") {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&dbg)
        {
            let _ = writeln!(
                f,
                "[{}] dialect={:?} process_cwd={:?} payload_cwd={:?} resolved_policy={}",
                now().1,
                input.dialect,
                std::env::current_dir().ok(),
                input.cwd,
                paths.policy_file().display()
            );
        }
    }

    let policy = Policy::load(&paths.policy_file())?;

    let base = policy.evaluate_command(&command);
    let signals = context::gather(&command);
    let (mut decision, escalated) = context::apply(base, &signals);

    // Destructive-intent classification (v0.11) — recorded on every entry so
    // the breaker can count attempts without re-parsing history.
    let intent_label = crate::intent::classify_command(&command).map(|i| i.label().to_string());

    // Session circuit breaker: repeated destructive intent in one session
    // escalates ask -> deny. Only ASK is ever touched — explicit allow/deny
    // rules are deliberate user policy. Runs BEFORE the backup step so a
    // breaker-denied command never triggers insurance (nothing will run).
    if decision.action == Action::Ask {
        let log_path = paths.state_dir.join("logs").join("audit.jsonl");
        if let Some((_intent, _prior, reason)) = crate::intent::maybe_trip(
            &paths.policy_file(),
            &log_path,
            input.session.as_deref(),
            &command,
        ) {
            decision = crate::policy::Decision {
                action: Action::Deny,
                matched_rule: Some(crate::intent::BREAKER_RULE.to_string()),
                reason,
            };
        }
    }

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
            intent: intent_label.clone(),
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

    // Belt and suspenders: Cursor and Copilot also honor the process exit code
    // (2 = block). On Windows especially, stdout JSON delivery can be finicky,
    // so a denied command exits non-zero to guarantee the block lands.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    if decision.action == Action::Deny {
        std::process::exit(2);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_real_payload_uses_workspace_roots_when_cwd_empty() {
        // The EXACT shape Cursor 3.10 sends on Windows: empty cwd, path in
        // workspace_roots as a URI, plus a UTF-8 BOM prefix.
        let raw = "\u{feff}{\"command\":\"rm -rf .cursor .git\",\"cwd\":\"\",\"hook_event_name\":\"beforeShellExecution\",\"workspace_roots\":[\"/c:/Users/User/code/proj\"],\"conversation_id\":\"c9\"}";
        let p = parse_input(raw).expect("must parse Cursor payload with BOM + empty cwd");
        assert_eq!(p.dialect, Dialect::Cursor);
        assert_eq!(p.command, "rm -rf .cursor .git");
        // cwd must be recovered from workspace_roots, normalized off the URI slash
        assert_eq!(p.cwd, "c:/Users/User/code/proj");
    }

    #[test]
    fn normalize_uri_path_handles_windows_and_unix() {
        assert_eq!(normalize_uri_path("/c:/Users/x"), "c:/Users/x");
        assert_eq!(normalize_uri_path("/home/user/proj"), "/home/user/proj"); // unix untouched
        assert_eq!(normalize_uri_path("c:/already/native"), "c:/already/native");
    }

    #[test]
    fn bom_prefixed_json_still_parses() {
        let raw = "\u{feff}{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}";
        assert_eq!(parse_input(raw).unwrap().command, "ls");
    }

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
        let raw =
            r#"{"toolName":"shell","toolArgs":"{\"command\":\"rm -rf /\"}","sessionId":"cop-1"}"#;
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
