# Termaxa — Product Document

**The execution layer between AI agents and your tools.**
Version: 0.7.0 · Rust · single ~1.5 MB binary · Windows/Linux/macOS

## The problem

AI coding agents run shell commands. Most are fine. Some are `git push --force`, `terraform apply`, `DROP TABLE users`, `rm -rf`. Today the choice is binary: supervise every command (kills the point of agents) or trust blindly (kills your Friday). Existing answers build *walls* (sandboxes, blanket blocks); nobody builds *windshields* — showing what's about to happen, insuring it, and recording it.

## What Termaxa does

Every command an agent attempts flows through six engines before it touches anything:

```
Claude Code ──► TERMAXA ──► git / psql / docker / terraform / ...
                 │
                 ├─ POLICY     .termaxa/policy.yaml — allow / ask / deny,
                 │             first match wins, shell-aware: compound
                 │             commands are split and the most dangerous
                 │             segment governs
                 ├─ CONTEXT    branch, --force/-rf flags, prod markers,
                 │             destructive SQL, $() substitution — can only
                 │             ESCALATE (allow→ask), never weaken a rule
                 ├─ PREVIEW    git push: commits gained AND commits the
                 │             remote would LOSE; postgres: row estimates +
                 │             FK blast radius ("referenced by 3 tables")
                 ├─ INSURANCE  automatic pre-execution backups: remote-ref
                 │             pinning, mode-aware pg_dump (CASCADE-aware),
                 │             file copies — restore by id, y/N gated
                 ├─ NOTIFY     Slack-compatible webhook on deny/ask;
                 │             fire-and-forget, can never delay a decision
                 └─ AUDIT      append-only JSONL: every attempt (incl.
                               blocked), session ids, approvals, exit codes,
                               backup ids — filterable, JSON-exportable
```

## Sixty-second start

```powershell
cargo install --path .          # or drop the prebuilt binary on PATH
cd your-project
termaxa init --claude-code        # scaffolds .termaxa/, detects tools,
                                # wires the PreToolUse hook
```
From that moment every Bash command Claude Code attempts is governed. No daemon, no account, no config server — one binary, one YAML file.

## Command surface

| Command | Purpose |
|---|---|
| `termaxa init [--claude-code]` | scaffold + hook install + tool detection |
| `termaxa check "<cmd>"` | dry-run: verdict + context + preview (exit 0/3/4 — scriptable) |
| `termaxa hook` | Claude Code PreToolUse mode (JSON stdin → decision stdout) |
| `termaxa run -- <cmd>` | gated execution: preview → y/N → backup → run → audit |
| `termaxa log [--decision] [--source] [--json] [-n]` | the record |
| `termaxa stats` | fleet view: totals, sessions, top denied |
| `termaxa backups` / `termaxa rollback <id>` | list insurance / restore |
| `termaxa notify --test` | loud webhook probe |

## What a governed moment looks like

Agent asks to force-push. Claude Code's own permission prompt shows:

> **[termaxa]** Force push — remote history will be overwritten. | **remote LOSES 1 commit(s)**; 1 commit(s); 5 files changed | backup b-1783006590625

One line: the rule, the loss, the gain, the insurance receipt. Deny instead, and the reason feeds back to the model — which then proposes a PR instead of retrying (field-observed behavior).

## Design principles (each one load-bearing)

1. **Fail closed on policy, fail open on plumbing.** Unmatched command → ask a human. Malformed hook input → step aside; a gate that breaks sessions gets uninstalled.
2. **One-way escalation.** Context heuristics may raise alarm, never lower a verdict — so cheap, false-positive-prone signals are *safe* to add.
3. **Reasons travel with verdicts** — into prompts, logs, and back to the model.
4. **Best-effort layers never block enforcement.** Preview/notify/backup failures degrade to absence, not to hangs (measured: 51 ms deny with a dead webhook).
5. **Insurance covers the measured blast radius.** A CASCADE truncate's backup includes the FK dependents the preview named.
6. **Shells see many commands; match segments, not strings.** `git status && rm -rf /` is judged by its worst part.
7. **Estimates, never scans.** Previews read planner statistics; they never `COUNT(*)` a production table.

## Field-tested, literally

Both post-v0.5 security fixes came from live contact, not planning:
- A real Windows run exposed that force-push previews measured gain but not **loss** → v0.6.1.
- The first live Claude Code session exposed the **compound-command prefix bypass** → v0.7.0, with the incident preserved as a named regression test.

## Honest scope

Cooperative interception: Termaxa governs the agent-harness hook path and `termaxa run`. An agent with raw, unhooked shell access is not contained — that's OS-sandboxing, a complementary layer. The threat model is *agents making expensive mistakes*, which is the one that actually fires daily.

## Where it goes (see roadmap.md)

Near: home-directory state, terraform previews, plugin registry (`termaxa add <tool>`), Cursor/OpenHands. Far: risk-tier approval routing, session replay, and the Cloud control plane (team policies, central audit, interactive approvals) — the OSS-runtime → enterprise-governance path from the original vision, reachable because developers install the runtime for the previews, not the compliance.

## The bet

In five years the feature synonymous with Termaxa shouldn't be "security" — it should be **execution previews**: *"before my agent touches anything, Termaxa shows me exactly what's going to happen — and has already taken the backup."* Security as a consequence of transparency, not the headline.
