# Circuit Breaker — Integration Guide (v0.11.0)

`src/intent.rs` is complete and drop-in. The edits below wire it into the
existing code. They are small and anchored to code that exists in your repo.
Apply them in order; `cargo build` will guide you at step 3 (the compiler
lists every construction site that needs the new field).

Total: 1 new file, ~4 small edits, ~30 lines of glue.

---

## Step 1 — Declare the module

**File: `src/main.rs`** — next to the other `mod` declarations at the top:

```rust
mod intent;
```

---

## Step 2 — Add the `intent` field to the audit entry

**File: `src/audit.rs`** — inside `pub struct AuditEntry { ... }`, add:

```rust
    /// Destructive-intent classification (v0.11+). `#[serde(default)]`
    /// keeps pre-v0.11 JSONL lines parsing cleanly as None (decision #7:
    /// backward-compatible audit schema, no migration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
```

---

## Step 3 — Fix construction sites

Run `cargo build`. The compiler will error on every place an `AuditEntry`
is constructed with a struct literal ("missing field `intent`"). For each:

- In the **hook path** (where the real decision is logged): set
  `intent: intent.map(|i| i.label().to_string())` — see Step 4.
- Everywhere else (`check`, `run`, tests): set `intent: None` for now.
  (Optional improvement later: classify in `check`/`run` too — same one-liner.)

---

## Step 4 — Escalation logic in the hook

**File: `src/hook.rs`** — in the function that evaluates the parsed hook
event, AFTER the policy decision (and after any context escalation) but
BEFORE the audit entry is written. You already have in scope: the resolved
`paths` (with `.policy_file()` and `.state_dir`), the `parsed` hook
(with `.command` and `.session`), and a mutable `decision`.

```rust
    // ---- session circuit breaker (v0.11) -------------------------------
    // Classify destructive intent for this command (logged either way).
    let intent = crate::intent::classify_command(&parsed.command);

    // Only ASK decisions are ever escalated. Explicit allow/deny rules are
    // deliberate user policy and are never overridden.
    if decision.action == crate::policy::Action::Ask {
        let log_path = paths.state_dir.join("logs").join("audit.jsonl");
        if let Some((_i, _prior, reason)) = crate::intent::maybe_trip(
            &paths.policy_file(),
            &log_path,
            parsed.session.as_deref(),
            &parsed.command,
        ) {
            decision = crate::policy::Decision {
                action: crate::policy::Action::Deny,
                matched_rule: Some("circuit-breaker".into()),
                reason,
            };
        }
    }
    // --------------------------------------------------------------------
```

Notes:
- If your `Decision.matched_rule` is `String` rather than `Option<String>`,
  drop the `Some(...)` wrapper.
- If `decision` is not currently `mut`, make it `let mut decision = ...`.
- The audit entry written right after this must carry BOTH the (possibly
  escalated) decision and the intent from Step 3. That is what makes the
  breaker stateless: every denied variant is itself logged with its intent,
  so the breaker stays tripped for the rest of the session with zero extra
  state files.

---

## Step 5 — Starter policy: config block + hardened defaults

**File: `src/init.rs`** — append to the starter `policy.yaml` template
(the `POLICY` const):

```yaml

# Session circuit breaker: if the same destructive intent (file delete,
# db destroy, git force, infra destroy) is asked/denied `threshold` times
# in one agent session, further variants are DENIED automatically.
# Approved commands don't count toward the threshold.
circuit_breaker:
  enabled: true
  threshold: 2   # trip on the 3rd attempt
```

And — the lesson from the live Cursor test — flip the bulk-delete starter
rules from `ask` to `deny` (in a full-auto/auto-approve world, `ask`
silently degrades to `allow`):

```yaml
  # Hard deny by default. Relax deliberately, per project, if you need to.
  - match: "*rm -rf*"
    action: deny
    reason: "Recursive force delete blocked by default policy."
  - match: "*rm -fr*"
    action: deny
  - match: "*Remove-Item*-Recurse*"
    action: deny
  - match: "*Get-ChildItem*Remove-Item*"
    action: deny
  - match: "*del /s*"
    action: deny
  - match: "*rmdir /s*"
    action: deny
```

---

## Step 6 (optional, enables approved-ask exclusion) — post-execution events

The breaker excludes asks that a human approved, evidenced by a
`source: "post"` record for the same command + session. To produce those
records, handle post-execution hook events:

**File: `src/hook.rs`** — where `hook_event_name` is inspected, add: if the
event is `"afterShellExecution"` (Cursor) or `"PostToolUse"` (Claude Code),
append an audit entry with `source: "post"`, `decision: "executed"`, the
command, the session, `intent` classified as usual — then exit 0 WITHOUT
policy evaluation (it already ran; this is a receipt, not a gate).

**File: `src/init.rs`** — register the post hooks:
- Cursor `hooks.json`: add `"afterShellExecution": [ { "command": "<abs path> hook" } ]`
  alongside the existing `beforeShellExecution`.
- Claude Code settings: add a `PostToolUse` hook mirroring the `PreToolUse` one.

Until Step 6 is done, the breaker simply counts ALL asks (strict mode) —
safe, just slightly more aggressive. You can ship v0.11.0 without Step 6
and add it in v0.11.1.

---

## Step 7 (recommended) — surface trips in the Execution Report

**File: `src/report.rs`** — count entries where `matched_rule ==
"circuit-breaker"` and print a dedicated line, e.g.:

```
│ breaker   : tripped 1× — repeated file-delete variants denied
```

This is the demo moment: "Termaxa noticed your agent retrying destructive
variants and shut it down."

---

## Verify

```
cargo fmt --all
cargo fmt --all -- --check
cargo test            # includes 13 new tests in intent.rs
```

The money test is `breaker_trips_on_third_variant` — it replays the live
Cursor scenario: `rm -rf .` → `Remove-Item -Recurse -Force .` →
`del /s /q .`, and asserts the third variant is denied.
