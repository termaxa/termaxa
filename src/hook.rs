use crate::audit::{now, AuditEntry, AuditLog};
use crate::context;
use crate::policy::{Action, Policy};
use anyhow::Result;
use serde_json::json;
use std::io::Read;

/// The session id `doctor`'s liveness probe sends, and the value the hook
/// checks to recognise a probe and stay inert. One meaning, one spelling
/// (decision #21): it was written out independently in `doctor.rs` and here,
/// and a sentinel that only works when two string literals agree is a silent
/// failure waiting to happen - a typo in either would make the probe write a
/// real audit line, or make a real session go inert.
///
/// HONEST RESIDUE: four integration-test literals remain - three in
/// `tests/hook_dialects.rs` and one in `tests/probe_inertness.rs`. `termaxa`
/// is a binary crate with no lib target, so integration tests cannot import
/// this const at all. Those literals are the reason a rename here would need
/// `grep termaxa-doctor-probe` rather than the compiler. Unifying them needs
/// a lib target, which is a larger change than this sweep and is the honest
/// remaining half of decision #21 here.
pub const PROBE_SESSION: &str = "termaxa-doctor-probe";

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
    /// True for post-execution events (afterShellExecution / postToolUse /
    /// PostToolUse): the command already ran, so this is a receipt, not a gate.
    pub is_post: bool,
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

impl Dialect {
    /// Stable name for the audit record. Written to disk, so it is a wire
    /// format: changing one of these strings rewrites what past entries mean,
    /// and a reader comparing across versions would silently miscount.
    pub fn actor(self) -> &'static str {
        match self {
            Dialect::ClaudeCode => "claude-code",
            Dialect::Cursor => "cursor",
            Dialect::Codex => "codex",
            Dialect::Copilot => "copilot",
        }
    }
}

pub fn parse_input(raw: &str) -> Option<ParsedHook> {
    // Cursor (and some Windows shells) prepend a UTF-8 BOM; strip it or the
    // JSON parse fails on the leading bytes.
    let raw = raw.trim_start_matches('\u{feff}').trim();
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);

    // Event name, lowercased for version-tolerant matching. Cursor renamed its
    // hooks between versions: older builds sent `beforeShellExecution` /
    // `afterShellExecution`; Cursor 3.11+ sends `preToolUse` / `postToolUse`
    // (camelCase) with `tool_name:"Shell"`. Claude Code sends `PreToolUse` /
    // `PostToolUse`. Match all of them case-insensitively.
    let event = s("hook_event_name").map(|e| e.to_lowercase());
    let is_pre = matches!(
        event.as_deref(),
        Some("pretooluse") | Some("beforeshellexecution")
    );
    let is_post = matches!(
        event.as_deref(),
        Some("posttooluse") | Some("aftershellexecution")
    );

    // Cursor identifies itself several ways across versions: `cursor_version`
    // (3.11+), `tool_name:"Shell"` + `conversation_id` (3.11+), OR the legacy
    // `beforeShellExecution`/`afterShellExecution` event names (older builds,
    // which no other agent uses). Detect all so every Cursor version routes here.
    let is_cursor = v.get("cursor_version").is_some()
        || matches!(
            event.as_deref(),
            Some("beforeshellexecution") | Some("aftershellexecution")
        )
        || (s("tool_name").as_deref() == Some("Shell") && v.get("conversation_id").is_some());

    // Command from either top-level `command` (old Cursor) or
    // `tool_input.command` (Claude/Codex/Cursor 3.11).
    let command_from = || -> String {
        if let Some(c) = s("command") {
            return c;
        }
        v.get("tool_input")
            .and_then(|t| t.get("command"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string()
    };

    // cwd: prefer explicit non-empty top-level cwd, then tool_input.cwd, then
    // the first workspace root (URI-normalized for Windows drive paths).
    let resolve_cwd = || -> String {
        let top = s("cwd").unwrap_or_default();
        if !top.is_empty() {
            return top;
        }
        let ti = v
            .get("tool_input")
            .and_then(|t| t.get("cwd"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        if !ti.is_empty() {
            return ti;
        }
        v.get("workspace_roots")
            .and_then(|w| w.as_array())
            .and_then(|a| a.first())
            .and_then(|x| x.as_str())
            .map(normalize_uri_path)
            .unwrap_or_default()
    };

    // ---- Cursor (any version): pre gates, post is a receipt ----
    if is_cursor && (is_pre || is_post) {
        let command = command_from();
        if command.is_empty() {
            return None;
        }
        return Some(ParsedHook {
            dialect: Dialect::Cursor,
            command,
            cwd: resolve_cwd(),
            session: s("conversation_id").or_else(|| s("session_id")),
            is_post,
        });
    }

    // ---- Copilot CLI: toolName + toolArgs (a JSON *string* holding the args) ----
    if let Some(tool) = s("toolName") {
        if tool == "shell" || tool == "bash" || tool == "run_in_terminal" {
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
                is_post,
            });
        }
    }

    // ---- Claude Code & Codex: PreToolUse/PostToolUse + tool_input.command ----
    // (Cursor already handled above, so a bare tool_name:"Bash" here is Claude/Codex.)
    if s("tool_name").as_deref() == Some("Bash") || is_pre || is_post {
        let command = v
            .get("tool_input")
            .and_then(|t| t.get("command"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        if command.is_empty() {
            return None;
        }
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
            is_post,
        });
    }

    None
}

/// A file-write tool call: the agent is about to write to `path`.
///
/// Kept separate from [`ParsedHook`] rather than folded into it. The shell
/// path is command-shaped the whole way down — policy, classifier, preview and
/// insurance all take a command string — and a write event has no command.
/// Widening `ParsedHook` would thread an empty `command` through five engines
/// that have nothing to say about it.
#[derive(Debug, Clone, PartialEq)]
pub struct FileWrite {
    pub dialect: Dialect,
    pub tool: String,
    pub path: String,
    pub cwd: String,
    pub session: Option<String>,
}

/// Names that mean the tool writes. Matched as substrings, case-folded, so a
/// rename within the same vocabulary (`Write`, `write_file`, `MultiEdit`,
/// `edit_file`, `create_file`, `apply_patch`, `str_replace_editor`,
/// `NotebookEdit`) keeps its coverage.
///
/// Coarse on purpose. An exact list of tool names is the shape that broke when
/// Cursor renamed its hook events between 3.10 and 3.11, and a rename here
/// would remove the gate without removing the registration, which is the quiet
/// direction. Read-shaped tools carry none of these verbs, which is what keeps
/// `Read` on `.termaxa/policy.yaml` from being refused — reading the policy is
/// allowed on the shell path too.
const WRITE_VERBS: [&str; 7] = [
    "write", "edit", "create", "patch", "replace", "notebook", "save",
];

/// Field names that carry the target path, across dialects.
const PATH_FIELDS: [&str; 6] = [
    "file_path",
    "notebook_path",
    "filePath",
    "target_file",
    "path",
    "abs_path",
];

/// Raw JSON in -> a file-write event out. `None` = not one; step aside.
///
/// Only called after [`parse_input`] has declined, so anything command-shaped
/// has already been handled by the shell path.
pub fn parse_file_write(raw: &str) -> Option<FileWrite> {
    let raw = raw.trim_start_matches('\u{feff}').trim();
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);

    // Pre only. A write that already happened cannot be gated, and a receipt
    // for it would give the circuit breaker nothing it can count.
    let event = s("hook_event_name").map(|e| e.to_lowercase());
    if matches!(
        event.as_deref(),
        Some("posttooluse") | Some("aftershellexecution")
    ) {
        return None;
    }

    let tool = s("tool_name").or_else(|| s("toolName"))?;
    let folded = tool.to_lowercase();
    if !WRITE_VERBS.iter().any(|v| folded.contains(v)) {
        return None;
    }

    // Copilot delivers its arguments as a JSON *string*; everyone else as an
    // object under `tool_input`.
    let args = match v.get("toolArgs") {
        Some(serde_json::Value::String(st)) => serde_json::from_str(st).ok()?,
        Some(other) => other.clone(),
        None => v.get("tool_input")?.clone(),
    };

    let path = PATH_FIELDS
        .iter()
        .find_map(|k| args.get(k).and_then(|p| p.as_str()))
        .filter(|p| !p.is_empty())?;

    let is_cursor = v.get("cursor_version").is_some() || v.get("conversation_id").is_some();
    let looks_codex = s("agent")
        .or_else(|| s("source"))
        .map(|a| a.to_lowercase().contains("codex"))
        .unwrap_or(false);
    let dialect = if v.get("toolName").is_some() {
        Dialect::Copilot
    } else if is_cursor {
        Dialect::Cursor
    } else if looks_codex {
        Dialect::Codex
    } else {
        Dialect::ClaudeCode
    };

    Some(FileWrite {
        dialect,
        tool,
        path: path.to_string(),
        cwd: s("cwd")
            .or_else(|| s("workingDirectory"))
            .or_else(|| {
                v.get("workspace_roots")
                    .and_then(|w| w.as_array())
                    .and_then(|a| a.first())
                    .and_then(|x| x.as_str())
                    .map(normalize_uri_path)
            })
            .unwrap_or_default(),
        session: s("session_id")
            .or_else(|| s("conversation_id"))
            .or_else(|| s("sessionId")),
    })
}

/// Gate a file-write tool call.
///
/// Deny if the target is one of the gate's own files, and say nothing at all
/// otherwise. Saying nothing is the point: an `allow` here would be Termaxa
/// asserting a verdict on every file the agent writes, which it has no opinion
/// about and no way to form one. Where the policy merely does not object, the
/// harness's own permission flow is left exactly as it was.
///
/// The decision does not depend on the policy, so it survives a project with
/// no `.termaxa/` at all and a policy that will not parse. Both are states in
/// which the shell path has nothing to say, and both are states in which
/// "do not overwrite the hook config" is still the right answer.
/// Refuse a write to the gate's own configuration.
///
/// Returns an `Outcome` rather than exiting: this used to call
/// `process::exit(2)` inline, which is correct for a one-shot hook process and
/// FATAL for the supervisor daemon - the first protected-file write an agent
/// attempted would have taken the supervisor down with it, and a dead
/// supervisor denies everything afterwards (v0.16's deny-on-unreachable). A
/// gate that kills itself by refusing something is a denial of service with
/// extra steps.
fn gate_file_write(w: &FileWrite) -> Outcome {
    let silent = Outcome {
        rendered: None,
        exit_code: 0,
        audit_seq: None,
    };
    let Some(protected) = crate::protect::classify(&w.cwd, &w.path) else {
        return silent;
    };

    let subject = format!("{} {}", w.tool, w.path);
    let reason = format!("[termaxa] {}", protected.reason);

    // Audit best-effort, and never at the cost of the block: if the state dir
    // cannot be resolved there is nowhere to write the record, and a deny that
    // went unrecorded is still a deny.
    let start_dir = if !w.cwd.is_empty() && std::path::Path::new(&w.cwd).is_dir() {
        std::path::PathBuf::from(&w.cwd)
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    if let Ok(paths) = crate::paths::resolve_from(&start_dir) {
        if let Ok(log) = AuditLog::new(&paths.state_dir) {
            let (ts_ms, ts) = now();
            let _ = log.append(&AuditEntry {
                ts_ms,
                ts,
                source: "hook".into(),
                actor: Some(w.dialect.actor().to_string()),
                // A protected-path refusal is the write matcher's own rule,
                // not the policy's - an explicit decision either way.
                decided_by: Some(
                    crate::policy::DecisionSource::ExplicitRule
                        .as_str()
                        .to_string(),
                ),
                command: subject.clone(),
                decision: "deny".into(),
                matched_rule: Some(protected.what.to_string()),
                reason: protected.reason.to_string(),
                signals: vec![],
                escalated: false,
                session: w.session.clone(),
                backup: None,
                preview: None,
                intent: None,
                approved: None,
                exit_code: None,
                cwd: w.cwd.clone(),
                // Filled by `append`, which links each entry to the one
                // before it.
                prev: None,
                hash: None,
            });
        }
        if let Ok(policy) = Policy::load(&paths.policy_file()) {
            crate::notify::maybe_send(&policy, "deny", &subject, protected.reason, "hook");
        }
    }

    Outcome {
        rendered: Some(render_response(w.dialect, "deny", &reason)),
        exit_code: 2,
        audit_seq: None,
    }
}

/// Should this decision be withheld rather than emitted?
///
/// Only a default-allow — allow with no rule behind it — and only for the
/// dialect whose contract documents that no output means no opinion. Claude
/// Code documents exactly that; Codex claims the same contract. Cursor and
/// Copilot do not, and the last time this project assumed Cursor's hook
/// contract it shipped four releases of silent ungating (3.11). They keep
/// emitting until a TERMAXA_HOOK_DEBUG capture on a live session says
/// silence is safe. See the comment at the call site in `run` for why the
/// default-allow goes silent at all.
fn is_silent(dialect: Dialect, decision: &crate::policy::Decision) -> bool {
    matches!(dialect, Dialect::ClaudeCode | Dialect::Codex)
        && decision.action == crate::policy::Action::Allow
        && decision.matched_rule.is_none()
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
/// What a hook invocation concluded, before anyone prints or exits.
///
/// v0.17. The decision path used to print and `process::exit` inline, which
/// is fine for a process that answers one payload and dies - and impossible
/// for a daemon that must answer thousands and stay alive. Both callers now
/// share the same logic and differ only in what they do with this:
/// `hook::run` prints and exits, `supervise` serialises it onto a socket.
///
/// Duplicating the decision path instead would have put two engines on one
/// question, which is the mistake this codebase keeps paying for (#37) - and
/// here the two copies would have been the trusted one and the untrusted one.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The rendered response in the harness's dialect, or `None` when the
    /// answer is silence (an allow the agent should not be interrupted by).
    pub rendered: Option<String>,
    pub exit_code: i32,
    /// The audit sequence this was recorded under.
    ///
    /// Always `None` today: the audit log is append-only JSONL with no
    /// sequence numbers, so there is nothing to report. The field is in the
    /// PROTOCOL because a hook that cannot write the record still wants a way
    /// to reference the entry the supervisor wrote — but the protocol
    /// carrying it does not mean this end can fill it.
    ///
    /// Kept rather than removed because the wire type is already published in
    /// v0.16's `Response`; removing it here would leave the two halves
    /// disagreeing about the message shape. It is filled when the log grows
    /// sequence numbers, which is its own decision (#65: record what the
    /// system can establish).
    ///
    /// The allow is for WINDOWS specifically: both readers of this field live
    /// in `#[cfg(unix)]` blocks (the daemon's response, the hook's forward),
    /// so a Windows build sees it written and never read. Scoped to the field
    /// rather than the struct, and narrated, because "dead on one platform"
    /// is a different fact from "dead".
    #[cfg_attr(not(unix), allow(dead_code))]
    pub audit_seq: Option<u64>,
}

pub fn run() -> Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let outcome = decide(&buf)?;
    if let Some(r) = &outcome.rendered {
        println!("{r}");
    }
    // Belt and suspenders: Cursor and Copilot also honor the process exit code
    // (2 = block). On Windows especially, stdout JSON delivery can be finicky,
    // so a denied command exits non-zero to guarantee the block lands.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    if outcome.exit_code != 0 {
        std::process::exit(outcome.exit_code);
    }
    Ok(())
}

/// Decide one payload. Prints nothing, exits nothing.
///
/// The whole hook path, minus I/O: this is what the daemon calls with bytes
/// off a socket and what `run` calls with bytes off stdin.
pub fn decide(raw_payload: &str) -> Result<Outcome> {
    let buf = raw_payload.to_string();

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
        None => {
            // Not command-shaped. It may still be a file-write tool call, and
            // the one thing a write tool must not do is rewrite the gate's own
            // configuration. Anything else here stays out of the way, exactly
            // as before.
            if let Some(w) = parse_file_write(&buf) {
                return Ok(gate_file_write(&w));
            }
            return Ok(Outcome {
                rendered: None,
                exit_code: 0,
                audit_seq: None,
            });
        }
    };
    let command = input.command.clone();

    // Post-execution event: the command already ran. Record a receipt
    // (source "post") so the circuit breaker can exclude human-approved
    // commands from the retry threshold (decision #13). No policy eval, no
    // gating, no output — append and exit.
    if input.is_post {
        let start_dir = if !input.cwd.is_empty() && std::path::Path::new(&input.cwd).is_dir() {
            std::path::PathBuf::from(&input.cwd)
        } else {
            std::env::current_dir().unwrap_or_default()
        };
        if let Ok(paths) = crate::paths::resolve_from(&start_dir) {
            if let Ok(log) = AuditLog::new(&paths.state_dir) {
                let (ts_ms, ts) = now();
                let _ = log.append(&AuditEntry {
                    ts_ms,
                    ts,
                    source: "post".into(),
                    actor: Some(input.dialect.actor().to_string()),
                    // A receipt records that a command RAN. Nothing decided
                    // anything here, and naming a decider would invent one.
                    decided_by: None,
                    command: command.clone(),
                    decision: "executed".into(),
                    matched_rule: None,
                    reason: "post-execution receipt".into(),
                    signals: vec![],
                    escalated: false,
                    session: input.session.clone(),
                    backup: None,
                    preview: None,
                    intent: crate::intent::classify_command(&command)
                        .map(|i| i.label().to_string()),
                    approved: Some(true),
                    exit_code: None,
                    cwd: input.cwd.clone(),
                    // Filled by `append`, which links each entry to the one
                    // before it.
                    prev: None,
                    hash: None,
                });
            }
        }
        return Ok(Outcome {
            rendered: None,
            exit_code: 0,
            audit_seq: None,
        });
    }

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

    // ---- supervised mode (v0.16 groundwork, v0.17 daemon) ----
    //
    // Detected from the filesystem: the socket is either there or it is not.
    // When it IS there, this hook is inside the agent's trust domain and has
    // no authority of its own - it forwards the payload and prints what comes
    // back. Until the daemon ships there is nothing to forward TO, so the
    // reachability check is the whole of it, and it fails CLOSED.
    //
    // That direction is the permanent answer to Cursor 3.11: four releases of
    // silent fail-open, because a gate that loses its brain and carries on is
    // worse than one that stops. An operator who configured supervision gets
    // a refusal with a reason, not a decision made by the wrong process.
    if crate::supervise::detect() == crate::supervise::Mode::Supervised {
        // Forward and print. Nothing below this line runs: this hook has no
        // authority in supervised mode, and exercising any would produce a
        // decision made inside the agent's own trust domain.
        //
        // The endpoint comes from `TERMAXA_SOCKET` (exported by `wrap`), an
        // XDG runtime dir, or the operator's own state directory - NOT from
        // this process's $HOME. The first proving run found why: a hook
        // running as the agent resolved $HOME to the agent's home, found no
        // socket, and quietly decided on its own authority.
        //
        // A second supervised hook must not recurse into the supervisor: the
        // daemon calls `decide` itself, and if that call re-entered here it
        // would connect to its own socket and deadlock a single-threaded
        // server. TERMAXA_SUPERVISOR=1 in the daemon's own process breaks the
        // loop.
        if std::env::var("TERMAXA_SUPERVISOR").as_deref() != Ok("1") {
            let sock = crate::supervise::endpoint().unwrap_or_default();
            return Ok(
                match crate::supervise::ask(&sock, &buf, Some(input.dialect.actor()), &input.cwd) {
                    Ok(resp) => Outcome {
                        rendered: Some(resp.rendered),
                        exit_code: resp.exit_code,
                        audit_seq: resp.audit_seq,
                    },
                    Err(e) => Outcome {
                        rendered: Some(render_response(
                            input.dialect,
                            "deny",
                            &format!("[termaxa] {}", e.reason()),
                        )),
                        exit_code: 2,
                        audit_seq: None,
                    },
                },
            );
        }
    }

    let policy = Policy::load(&paths.policy_file())?;

    // The payload's cwd is where the command runs; the project root comes
    // from the located policy. Never the process cwd - a hook runs wherever
    // the harness spawned it.
    let ctx = crate::resolve::EvalContext::from_paths(&start_dir, &paths);
    let base = policy.evaluate_command(&command, &ctx);
    let signals = context::gather(&command);
    let (mut decision, escalated) = context::apply(base, &signals);

    // Destructive-intent classification (v0.11) — recorded on every entry so
    // the breaker can count attempts without re-parsing history.
    let intent_label = crate::intent::classify_command(&command).map(|i| i.label().to_string());

    // Session circuit breaker: repeated destructive intent in one session
    // escalates ask -> deny. Only ASK is ever touched — explicit allow/deny
    // rules are deliberate user policy. Runs BEFORE the backup step so a
    // breaker-denied command never triggers insurance (nothing will run).
    // A DEFAULT-ask file-overwrite must neither accumulate pressure (see
    // recent_intent_count) nor BE the tripping command: three denied `.env`
    // attempts must not turn the next `cargo build > build.log` into a deny.
    // The policy had no opinion on that build log — decline-not-allow,
    // applied to the breaker.
    let ungated_overwrite = decision.matched_rule.is_none()
        && matches!(
            crate::intent::classify_command(&command),
            Some(crate::intent::Intent::FileOverwrite)
        );
    if decision.action == Action::Ask && !ungated_overwrite {
        let log_path = paths.state_dir.join("logs").join("audit.jsonl");
        if let Some((_intent, _prior, reason)) = crate::intent::maybe_trip(
            &paths.policy_file(),
            &log_path,
            input.session.as_deref(),
            &command,
        ) {
            decision = crate::policy::Decision {
                action: Action::Deny,
                // The breaker chose this deliberately, from history rather
                // than from a rule - a Context decision in the sense that
                // matters here: something formed an opinion.
                source: crate::policy::DecisionSource::Context,
                matched_rule: Some(crate::intent::BREAKER_RULE.to_string()),
                reason,
            };
        }
    }

    // Pass the project root so the delete preview can answer "is this target
    // outside the project?" — the process cwd can't supply it, because the
    // agent may spawn us from anywhere (the Cursor cwd bug).
    let (preview_summary, uninsurable) = {
        // A denied command must not cause a subprocess. The preview is still
        // generated — statically — so the denial reason keeps its detail.
        let live = decision.action != crate::policy::Action::Deny;
        match crate::preview::generate(
            &command,
            paths.project_dir.parent(),
            std::path::Path::new(&input.cwd),
            live,
        ) {
            Some(p) => (Some(p.summary), p.uninsurable),
            None => (None, false),
        }
    };

    // Probe mode requires BOTH the env var and the sentinel session id — see
    // the note at the audit-suppression site below for why. Computed here
    // because the insurance amplifier needs it.
    let is_probe = std::env::var("TERMAXA_HOOK_PROBE").as_deref() == Ok("1")
        && input.session.as_deref() == Some(PROBE_SESSION);

    // Roadmap 2.5: an ask on a command with no net becomes a deny. Applied
    // after context escalation, so a signal that raised allow->ask can then
    // be amplified to deny by uninsurability - the two compose in the order
    // they are meant to: is this concerning, and if so, is asking safe?
    //
    // NOT for a probe. `doctor` asks "does the configured POLICY deny
    // anything", which is a different question from "can the enforcement
    // stack stop this command". Amplifying the probe would answer the second
    // and print the first: a policy with no rules at all would look
    // protective, because `rm -rf /` is uninsurable and the default is ask.
    // That misreading gets worse with every safeguard added later, so the
    // probe sees the policy verdict and enforcement sees the amplified one.
    // One reader, two questions, answered separately (#37).
    let (decision, uninsured_escalation) = if is_probe {
        (decision, false)
    } else {
        crate::context::apply_insurance(decision, uninsurable)
    };

    // Insure before allowing: PreToolUse runs before execution, so a backup
    // taken here is guaranteed to predate the command. Never for deny.
    //
    // LIVENESS PROBE (v0.15). `doctor` invokes the hook exactly as the agent
    // does, to prove it can actually run — see `doctor::hook_live`. A probe must
    // be inert: no backup, no audit entry, no state. It still evaluates policy
    // and answers, because answering is the thing being tested.
    //
    // Why this exists: `hook_configured` used to be a substring search for
    // "termaxa hook" in settings.json. A hook whose path did not resolve at exec
    // time failed non-blocking, the session ran ungated, and doctor reported
    // "configured" in green. Observed on Windows 2026-08-13.
    //
    // The env var ALONE must not switch off backups and the audit record —
    // for a tool whose pitch is the backup and the record, a single ambient
    // variable that silently disables both (direnv, a doctored launch
    // script) is a kill switch. So probe mode requires BOTH the variable and
    // the sentinel session id, and `doctor` is the only thing that sends the
    // sentinel. An agent command cannot set its harness's env; a leaked env
    // var without the sentinel changes nothing.
    let mut backup_id: Option<String> = None;
    if !is_probe && decision.action != Action::Deny {
        if let Ok(Some(rec)) =
            crate::backup::take(&paths.state_dir, &command, std::path::Path::new(&input.cwd))
        {
            backup_id = Some(rec.id);
        }
    }

    // Audit first, decide second: even denied attempts are part of the record.
    // Except a probe, which must leave the record exactly as it found it.
    if !is_probe {
        if let Ok(log) = AuditLog::new(&paths.state_dir) {
            let (ts_ms, ts) = now();
            let _ = log.append(&AuditEntry {
                ts_ms,
                ts,
                source: "hook".into(),
                actor: Some(input.dialect.actor().to_string()),
                decided_by: Some(decision.source.as_str().to_string()),
                command: command.clone(),
                decision: decision.action.to_string(),
                matched_rule: decision.matched_rule.clone(),
                reason: decision.reason.clone(),
                signals: signals.iter().map(|s| s.label.clone()).collect(),
                escalated: escalated || uninsured_escalation,
                session: input.session.clone(),
                backup: backup_id.clone(),
                preview: preview_summary.clone(),
                intent: intent_label.clone(),
                approved: None,
                exit_code: None,
                cwd: input.cwd.clone(),
                // Filled by `append`, which links each entry to the one
                // before it.
                prev: None,
                hash: None,
            });
        }
    }

    // DECLINE RATHER THAN ALLOW (v0.15).
    //
    // A policy that merely fails to object is not the same as a policy that
    // deliberately blesses a command, and until now Termaxa said "allow" for
    // both. That is a false statement about our own confidence: for every
    // command no rule matched, we were asserting a verdict we had not formed.
    //
    // So: an explicit `action: allow` rule still emits allow, because someone
    // wrote it down on purpose. The default-allow path emits nothing and lets
    // the harness decide for itself.
    //
    // Suggested by Tim Schipper.
    let silent = is_silent(input.dialect, &decision);

    let permission = match decision.action {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    };

    let mut reason = format!("[termaxa] {}", decision.reason);
    if uninsured_escalation {
        // Named distinctly from context escalation: the record should say
        // WHICH amplifier fired, or a later reader cannot tell a signal-driven
        // ask from an uninsurable-driven deny.
        reason.push_str(" (uninsurable — escalated to deny)");
    } else if escalated {
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

    // A probe must not page anyone: with `notify.on: [deny]` configured,
    // every `termaxa doctor` run would otherwise post a "denied rm -rf /"
    // webhook per detected agent.
    if !is_probe {
        crate::notify::maybe_send(
            &policy,
            &decision.action.to_string(),
            &command,
            &decision.reason,
            "hook",
        );
    }

    // A probe must always answer — `doctor` reads the decision to prove the hook
    // can run at all, and silence is indistinguishable from a dead hook.
    let rendered = if !silent || is_probe {
        Some(render_response(input.dialect, permission, &reason))
    } else {
        None
    };

    Ok(Outcome {
        rendered,
        exit_code: if decision.action == Action::Deny {
            2
        } else {
            0
        },
        audit_seq: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v0.15: a policy that merely fails to object must not claim to approve.
    /// The default-allow path emits nothing; an explicit allow rule still says
    /// allow, because someone wrote that rule on purpose.
    #[test]
    fn a_default_allow_is_silence_and_an_explicit_allow_is_not() {
        use crate::policy::{Action, Decision};

        let no_opinion = Decision {
            action: Action::Allow,
            // The typed form of the distinction this test already drew by
            // hand: `Default` IS "no opinion" (v0.16, roadmap 2.5).
            source: crate::policy::DecisionSource::Default,
            matched_rule: None,
            reason: "no rule matched; policy default is `allow`".into(),
        };
        let deliberate = Decision {
            action: Action::Allow,
            source: crate::policy::DecisionSource::ExplicitRule,
            matched_rule: Some("git status*".into()),
            reason: "matched rule `git status*`".into(),
        };

        assert!(
            is_silent(Dialect::ClaudeCode, &no_opinion),
            "an unmatched command must not be reported as approved"
        );
        assert!(
            !is_silent(Dialect::ClaudeCode, &deliberate),
            "an explicit allow rule is a deliberate blessing and must be emitted"
        );
        // Cursor and Copilot keep emitting: their empty-stdout semantics are
        // uncaptured, and Cursor has burned this project once already (3.11).
        assert!(!is_silent(Dialect::Cursor, &no_opinion));
        assert!(!is_silent(Dialect::Copilot, &no_opinion));
    }

    /// ask and deny always speak, whether or not a rule matched them.
    #[test]
    fn only_allow_can_ever_be_silent() {
        use crate::policy::{Action, Decision};
        for action in [Action::Ask, Action::Deny] {
            let d = Decision {
                action,
                source: crate::policy::DecisionSource::Default,
                matched_rule: None,
                reason: "default".into(),
            };
            assert!(
                !is_silent(Dialect::ClaudeCode, &d),
                "{action} must always be emitted"
            );
        }
    }

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
    fn cursor_311_pretooluse_is_gated() {
        // The EXACT shape Cursor 3.11.25 sends on Windows (captured live).
        // Old parse_input matched none of this -> Termaxa silently no-op'd.
        let raw = r#"{"conversation_id":"758","tool_name":"Shell","tool_input":{"command":"git status","cwd":"C:\\Users\\User\\code\\p","timeout":30000},"cwd":"C:\\Users\\User\\code\\p","session_id":"758","hook_event_name":"preToolUse","cursor_version":"3.11.25","workspace_roots":["/C:/Users/User/code/p"]}"#;
        let p = parse_input(raw).expect("Cursor 3.11 preToolUse must be recognized");
        assert_eq!(p.dialect, Dialect::Cursor);
        assert_eq!(p.command, "git status");
        assert!(!p.is_post, "preToolUse must gate, not receipt");
        assert_eq!(p.session.as_deref(), Some("758"));
    }

    #[test]
    fn cursor_311_posttooluse_is_receipt() {
        let raw = r#"{"conversation_id":"758","tool_name":"Shell","tool_input":{"command":"git status","cwd":"C:\\Users\\User\\code\\p"},"tool_output":"{\"output\":\"\",\"exitCode\":0}","duration":174.96,"cwd":"C:\\Users\\User\\code\\p","session_id":"758","hook_event_name":"postToolUse","cursor_version":"3.11.25","workspace_roots":["/C:/Users/User/code/p"]}"#;
        let p = parse_input(raw).expect("Cursor 3.11 postToolUse must be recognized");
        assert_eq!(p.dialect, Dialect::Cursor);
        assert_eq!(p.command, "git status");
        assert!(p.is_post, "postToolUse must be a receipt");
    }

    #[test]
    fn cursor_311_empty_cwd_recovers_from_tool_input_or_roots() {
        // 3.11 sometimes sends empty top-level cwd; recover from tool_input.cwd
        // or workspace_roots.
        let raw = r#"{"conversation_id":"758","tool_name":"Shell","tool_input":{"command":"where.exe git","cwd":""},"cwd":"","session_id":"758","hook_event_name":"preToolUse","cursor_version":"3.11.25","workspace_roots":["/C:/Users/User/code/p"]}"#;
        let p = parse_input(raw).unwrap();
        assert_eq!(
            p.cwd, "C:/Users/User/code/p",
            "must recover cwd from workspace_roots"
        );
    }

    #[test]
    fn old_cursor_beforeshellexecution_still_works() {
        // Backward-compat: pre-3.11 Cursor must still be gated.
        let raw = "\u{feff}{\"command\":\"rm -rf .cursor .git\",\"cwd\":\"\",\"hook_event_name\":\"beforeShellExecution\",\"workspace_roots\":[\"/c:/Users/User/code/proj\"],\"conversation_id\":\"c9\"}";
        let p = parse_input(raw).unwrap();
        assert_eq!(p.dialect, Dialect::Cursor);
        assert_eq!(p.command, "rm -rf .cursor .git");
        assert!(!p.is_post);
    }

    #[test]
    fn detects_claude_dialect() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s-1","cwd":"/w"}"#;
        let p = parse_input(raw).unwrap();
        assert_eq!(p.dialect, Dialect::ClaudeCode);
        assert_eq!(p.command, "git status");
    }

    #[test]
    fn detects_post_execution_events() {
        // Cursor afterShellExecution → receipt
        let cur = r#"{"hook_event_name":"afterShellExecution","command":"rm -rf ./cache","cwd":"/w","conversation_id":"c1"}"#;
        let p = parse_input(cur).unwrap();
        assert!(p.is_post);
        assert_eq!(p.dialect, Dialect::Cursor);
        assert_eq!(p.command, "rm -rf ./cache");

        // Claude PostToolUse → receipt
        let cc = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"git commit -m x"},"session_id":"s1"}"#;
        let p = parse_input(cc).unwrap();
        assert!(p.is_post);
        assert_eq!(p.dialect, Dialect::ClaudeCode);

        // Pre-events are NOT post
        let pre = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        assert!(!parse_input(pre).unwrap().is_post);
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

    // ---- file-write tools ----------------------------------------------
    //
    // The half of self-defence the shell rules cannot reach. Every case here
    // is named for the situation it came from rather than for the function it
    // calls.

    /// What Termaxa would decide, given a raw payload: the deny reason, or
    /// `None` for "no decision, leave the harness alone".
    fn verdict(raw: &str) -> Option<&'static str> {
        let w = parse_file_write(raw)?;
        crate::protect::classify(&w.cwd, &w.path).map(|p| p.what)
    }

    fn write_payload(tool: &str, path: &str) -> String {
        json!({
            "session_id": "s-1",
            "cwd": "/repo",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": { "file_path": path, "content": "default: allow\n" }
        })
        .to_string()
    }

    /// Field report, 2026-08-12: an agent hit the `rm -rf` deny, reasoned five
    /// seconds later that dropping `-rf` made the command equivalent, and
    /// retried. Same instinct one tool over is a `Write` at the policy that
    /// denied it, and until this matcher existed the shell rules could not see
    /// it.
    #[test]
    fn the_write_tool_no_longer_routes_around_a_shell_deny() {
        assert_eq!(
            verdict(&write_payload("Write", "/repo/.termaxa/policy.yaml")),
            Some("termaxa-state")
        );
        assert_eq!(
            verdict(&write_payload("Edit", "/repo/.claude/settings.json")),
            Some("agent-hook-config")
        );
    }

    /// The tools Claude Code ships, including the one whose path field is
    /// spelled differently.
    #[test]
    fn every_write_tool_is_recognised_including_notebooks() {
        for tool in ["Write", "Edit", "MultiEdit"] {
            assert_eq!(
                verdict(&write_payload(tool, "/repo/.termaxa/policy.yaml")),
                Some("termaxa-state"),
                "{tool}"
            );
        }
        let nb = json!({
            "cwd": "/repo",
            "hook_event_name": "PreToolUse",
            "tool_name": "NotebookEdit",
            "tool_input": { "notebook_path": "/repo/.termaxa/policy.yaml" }
        })
        .to_string();
        assert_eq!(verdict(&nb), Some("termaxa-state"));
    }

    /// An ordinary edit must produce no decision at all, not an `allow`.
    /// Asserting `allow` on every file an agent writes would be Termaxa
    /// answering a question it has no way to form an opinion about, and at the
    /// harness boundary an `allow` is an answer, not a shrug.
    #[test]
    fn an_ordinary_edit_gets_no_decision_rather_than_an_allow() {
        let raw = write_payload("Edit", "/repo/src/main.rs");
        let w = parse_file_write(&raw).expect("still parses as a write event");
        assert_eq!(crate::protect::classify(&w.cwd, &w.path), None);
    }

    /// Reading the policy is allowed on the shell path (`cat .termaxa*` is an
    /// explicit allow in the starter policy), so a read tool must not be
    /// caught here either. `Read` carries the same `file_path` field as
    /// `Write`, so only the verb separates them.
    #[test]
    fn read_tools_are_left_alone_even_on_a_protected_path() {
        let raw = json!({
            "cwd": "/repo",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": "/repo/.termaxa/policy.yaml" }
        })
        .to_string();
        assert!(parse_file_write(&raw).is_none());
    }

    /// A rename within the same vocabulary keeps its coverage. This is the
    /// failure Cursor 3.11 caused on the shell side, where an exact-name check
    /// stopped matching and the gate went quiet.
    #[test]
    fn a_renamed_write_tool_still_matches_by_verb() {
        for tool in [
            "write_file",
            "edit_file",
            "create_file",
            "apply_patch",
            "str_replace_editor",
        ] {
            assert_eq!(
                verdict(&write_payload(tool, "/repo/.termaxa/policy.yaml")),
                Some("termaxa-state"),
                "{tool}"
            );
        }
    }

    #[test]
    fn a_shell_payload_stays_on_the_shell_path() {
        // `parse_input` handles it, and `parse_file_write` must not also claim
        // it — the write path has no policy engine behind it.
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf .termaxa"}}"#;
        assert!(parse_input(raw).is_some());
        assert!(parse_file_write(raw).is_none());
    }

    #[test]
    fn a_write_that_already_happened_is_not_gated() {
        let raw = json!({
            "cwd": "/repo",
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/repo/.termaxa/policy.yaml" }
        })
        .to_string();
        assert!(parse_file_write(&raw).is_none());
    }

    #[test]
    fn a_write_event_with_no_target_path_is_not_one() {
        let raw =
            r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"content":"x"}}"#;
        assert!(parse_file_write(raw).is_none());
        let empty =
            r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":""}}"#;
        assert!(parse_file_write(empty).is_none());
    }

    /// Copilot delivers tool arguments as a JSON string rather than an object,
    /// the same shape the shell path already has to unwrap.
    #[test]
    fn copilot_string_encoded_arguments_are_unwrapped() {
        let raw = json!({
            "toolName": "create_file",
            "toolArgs": r#"{"path":"/repo/.github/hooks/hooks.json"}"#,
            "workingDirectory": "/repo"
        })
        .to_string();
        let w = parse_file_write(&raw).expect("copilot write must parse");
        assert_eq!(w.dialect, Dialect::Copilot);
        assert_eq!(
            crate::protect::classify(&w.cwd, &w.path).map(|p| p.what),
            Some("agent-hook-config")
        );
    }

    /// A payload with a BOM and a relative path, which is the combination the
    /// Cursor field reports arrive in.
    #[test]
    fn a_bom_prefixed_write_with_a_relative_path_still_resolves() {
        let raw = format!(
            "\u{feff}{}",
            json!({
                "hook_event_name": "preToolUse",
                "cursor_version": "3.11.25",
                "conversation_id": "c-9",
                "tool_name": "Edit",
                "tool_input": { "file_path": ".termaxa/policy.yaml" },
                "workspace_roots": ["/c:/Users/User/code/proj"]
            })
        );
        let w = parse_file_write(&raw).expect("cursor write must parse");
        assert_eq!(w.dialect, Dialect::Cursor);
        assert_eq!(w.cwd, "c:/Users/User/code/proj");
        assert_eq!(
            crate::protect::classify(&w.cwd, &w.path).map(|p| p.what),
            Some("termaxa-state")
        );
    }
}
