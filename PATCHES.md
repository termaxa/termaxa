# Circuit Breaker v0.11 — EXACT patches (verified against the synced repo)

One new file + five small edits. Every FIND block below is verbatim from your
current code, so you can copy-paste (or hand this file to Cursor agent mode
and tell it to apply the patches literally).

New file first:

    src/intent.rs   →  copy from this package into C:\Users\User\code\termaxa\src\

Then the edits, in order.

═══════════════════════════════════════════════════════════════════
PATCH 1 — src/main.rs : declare the module
═══════════════════════════════════════════════════════════════════

FIND:
```rust
mod audit;
mod backup;
mod context;
mod hook;
mod init;
```

REPLACE WITH:
```rust
mod audit;
mod backup;
mod context;
mod hook;
mod init;
mod intent;
```

═══════════════════════════════════════════════════════════════════
PATCH 2 — src/audit.rs : add the intent field to AuditEntry
═══════════════════════════════════════════════════════════════════

FIND:
```rust
    /// Preview summary at decision time (e.g. "DELETE ALL from sessions
    /// ~120,000 rows") — persisted so reports can aggregate impact as fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
```

REPLACE WITH:
```rust
    /// Preview summary at decision time (e.g. "DELETE ALL from sessions
    /// ~120,000 rows") — persisted so reports can aggregate impact as fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// Destructive-intent classification (v0.11+): file-delete | db-destroy
    /// | git-destructive | infra-destroy. Serde-defaulted so pre-v0.11 log
    /// lines parse as None (decision #7: backward-compatible audit schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
```

═══════════════════════════════════════════════════════════════════
PATCH 3 — src/hook.rs : classify + breaker escalation (the core)
═══════════════════════════════════════════════════════════════════

3a. FIND (inside run(), right after Policy::load):
```rust
    let base = policy.evaluate_command(&command);
    let signals = context::gather(&command);
    let (decision, escalated) = context::apply(base, &signals);

    let preview_summary = crate::preview::generate(&command).map(|p| p.summary);
```

REPLACE WITH:
```rust
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
                matched_rule: Some("circuit-breaker".to_string()),
                reason,
            };
        }
    }

    let preview_summary = crate::preview::generate(&command).map(|p| p.summary);
```

3b. FIND (the audit entry a few lines below):
```rust
            session: input.session.clone(),
            backup: backup_id.clone(),
            preview: preview_summary.clone(),
            approved: None,
```

REPLACE WITH:
```rust
            session: input.session.clone(),
            backup: backup_id.clone(),
            preview: preview_summary.clone(),
            intent: intent_label.clone(),
            approved: None,
```

═══════════════════════════════════════════════════════════════════
PATCH 4 — src/main.rs : Check arm logs intent too
═══════════════════════════════════════════════════════════════════

FIND (inside Cmd::Check):
```rust
                session: None,
                backup: None,
                preview: preview_summary,
                approved: None,
```

REPLACE WITH:
```rust
                session: None,
                backup: None,
                preview: preview_summary,
                intent: intent::classify_command(&cmd).map(|i| i.label().to_string()),
                approved: None,
```

═══════════════════════════════════════════════════════════════════
PATCH 5 — src/runner.rs : run arm logs intent too
═══════════════════════════════════════════════════════════════════

FIND:
```rust
        session: None,
        backup: backup_id,
        preview: preview_summary,
        approved,
```

REPLACE WITH:
```rust
        session: None,
        backup: backup_id,
        preview: preview_summary,
        intent: crate::intent::classify_command(&command).map(|i| i.label().to_string()),
        approved,
```

NOTE: `command` is moved into the struct literal one line above the fields
shown — the classify call borrows it inside the same literal, which is fine
because the `command` field is populated by move while `intent` evaluates
first only if listed earlier. To be safe against field-evaluation order,
if the compiler complains about use-after-move, hoist the classify call
above the literal:
```rust
    let intent_label = crate::intent::classify_command(&command).map(|i| i.label().to_string());
```
and use `intent: intent_label,` in the literal instead.

═══════════════════════════════════════════════════════════════════
PATCH 6 — src/init.rs : hardened starter policy + breaker config
═══════════════════════════════════════════════════════════════════

The live Cursor test's lesson: in a full-auto/auto-approve world, `ask`
silently degrades to `allow`. Bulk deletes now default to deny; relax
deliberately per project.

6a. FIND (the five ask-rules in the destructive section):
```rust
  # Broad recursive-force deletes (any target), Unix + PowerShell forms.
  - match: "*rm -rf*"
    action: ask
    reason: "Recursive force delete — confirm the target before running."
  - match: "*rm -fr*"
    action: ask
    reason: "Recursive force delete — confirm the target before running."
  - match: "*Remove-Item*-Recurse*-Force*"
    action: ask
    reason: "Recursive force delete (PowerShell) — confirm the target."
  - match: "*Remove-Item*-Force*-Recurse*"
    action: ask
    reason: "Recursive force delete (PowerShell) — confirm the target."
  - match: "*Get-ChildItem*Remove-Item*"
    action: ask
    reason: "Bulk delete pipeline (PowerShell) — confirm before running."
```

REPLACE WITH:
```rust
  # Broad recursive-force deletes (any target), Unix + PowerShell + cmd
  # forms. DENY by default: with auto-approving agent UIs, `ask` silently
  # degrades to `allow`. Relax deliberately, per project, if you need to.
  - match: "*rm -rf*"
    action: deny
    reason: "Recursive force delete blocked by default policy."
  - match: "*rm -fr*"
    action: deny
    reason: "Recursive force delete blocked by default policy."
  - match: "*Remove-Item*-Recurse*"
    action: deny
    reason: "Recursive delete (PowerShell) blocked by default policy."
  - match: "*Remove-Item*-Force*"
    action: deny
    reason: "Forced delete (PowerShell) blocked by default policy."
  - match: "*Get-ChildItem*Remove-Item*"
    action: deny
    reason: "Bulk delete pipeline (PowerShell) blocked by default policy."
  - match: "*del /s*"
    action: deny
    reason: "Recursive delete (cmd) blocked by default policy."
  - match: "*rmdir /s*"
    action: deny
    reason: "Recursive delete (cmd) blocked by default policy."
  - match: "*rd /s*"
    action: deny
    reason: "Recursive delete (cmd) blocked by default policy."
```

6b. FIND (the very end of STARTER_POLICY):
```rust
  - match: "ssh *"
    action: ask
"#;
```

REPLACE WITH:
```rust
  - match: "ssh *"
    action: ask

# Session circuit breaker (v0.11): if the same destructive intent
# (file delete / db destroy / git force / infra destroy) is asked or
# denied `threshold` times in one agent session, further variants are
# DENIED automatically. Human-approved commands don't count.
circuit_breaker:
  enabled: true
  threshold: 2   # trip on the 3rd attempt
"#;
```

(The `circuit_breaker` key is read by intent.rs directly; Policy's serde
ignores unknown top-level keys, so existing policy parsing is untouched.)

═══════════════════════════════════════════════════════════════════
OPTIONAL (v0.11.1) — approved-ask exclusion goes live
═══════════════════════════════════════════════════════════════════

The breaker already excludes asks that have a matching `source: "post"`
execution record (same command + session). To produce those records, handle
post-execution events in hook.rs's parse path: when `hook_event_name` is
"afterShellExecution" (Cursor) or "PostToolUse" (Claude Code), append an
audit entry with source "post", decision "executed", the command, session,
and classified intent — then exit 0 WITHOUT evaluating policy (it already
ran; this is a receipt, not a gate). Register the post hooks in init.rs
alongside the existing ones. Until then the breaker counts all asks
(strict mode) — the safe direction. Verify Cursor's afterShellExecution
actually fires on Windows with TERMAXA_HOOK_DEBUG before trusting it.

═══════════════════════════════════════════════════════════════════
OPTIONAL — Execution Report line
═══════════════════════════════════════════════════════════════════

In report.rs's aggregation, count entries where
`matched_rule.as_deref() == Some("circuit-breaker")` and print e.g.:
`│ breaker   : tripped 2× — repeated destructive variants denied`
This is the demo line. Ship it with v0.11.0 or fast-follow.

═══════════════════════════════════════════════════════════════════
Verify
═══════════════════════════════════════════════════════════════════

```
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test
```

Expect your existing tests + 13 new in intent.rs, all green. The money
test is `breaker_trips_on_third_variant` — it replays the live Cursor
whack-a-mole (`rm -rf .` → `Remove-Item -Recurse -Force .` → `del /s /q .`)
and asserts the third variant is denied.
