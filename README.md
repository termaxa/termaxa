<div align="center">

# 🛡 Termaxa

**Run AI coding agents with confidence.**

Preview what a command will do. Measure the blast radius. Take an automatic backup *before* it runs. Roll back when something goes wrong.

[![CI](https://github.com/termaxa/termaxa/actions/workflows/ci.yml/badge.svg)](https://github.com/termaxa/termaxa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/termaxa/termaxa?display_name=tag)](https://github.com/termaxa/termaxa/releases)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

</div>

---

Your AI agent wants to run `git push --force`, `DROP TABLE users`, `terraform apply`, `rm -rf`. Most of the time it's right. Sometimes it isn't. Today your only options are *supervise every command* (which defeats the point of an agent) or *trust it blindly* (which defeats your Friday).

Termaxa is a third option: a gate the agent's commands pass through. It reads a policy you wrote, shows you what's actually about to happen, backs up what's about to change, and records everything. Built for **Claude Code** today; works as a standalone CLI anywhere.

```
  Claude Code --> TERMAXA --> git . postgres . docker . terraform . your shell
                    |
                    +- decide    allow / ask / deny  (your policy)
                    +- preview   commits lost, rows affected, resources destroyed
                    +- insure    automatic backup before destructive ops
                    +- record    every attempt, with an execution report
```

## Quick start (5 minutes)

**1. Install.** Download a prebuilt binary from [Releases](https://github.com/termaxa/termaxa/releases) and put it on your PATH — or, with a Rust toolchain:

```bash
cargo install --path .
```

**2. Wire up a project.**

```bash
cd your-project
termaxa init --claude-code      # writes .termaxa/policy.yaml, installs the Claude Code hook
```

**3. See it work.**

```bash
termaxa check "git push --force origin main"
```

From now on, every Bash command Claude Code runs in this project passes through Termaxa first. Runtime state (logs, backups) lives in `~/.termaxa/`, safely **outside** your repo.

## What it looks like

### 1 - A destructive command can't hide behind a safe prefix

```console
$ termaxa check "git status && rm -rf /"
decision: deny
reason  : segment 2/2 `rm -rf /` — Recursive delete from root is blocked.
```

Termaxa splits compound commands and judges each part. `git status &&` buys nothing.

### 2 - Blast radius, before you commit to it

```console
$ termaxa check "psql -d shop -c 'DROP TABLE users'"
decision: deny
reason  : DROP TABLE is blocked. Archive or rename instead.
preview : postgres impact
  DROP TABLE users
    rows (estimate) : 50,000
    referenced by   : audit_log, orders, sessions (3 tables)
    without CASCADE : this DROP will FAIL (dependents exist)
  insurance : pg_dump users before execution (automatic on run/hook)
```

Row estimates come from the planner (`pg_class.reltuples`) — Termaxa never scans your tables.

### 3 - Destroy, then un-destroy

```console
$ termaxa run -- git push --force origin main
┌ push preview (main -> origin)
│  ⚠ remote will LOSE 1 commit(s):
│    ✗ 44510f1 important work
└
Proceed? [y/N] y
🛟 backup b-1783006590625 — origin/main @ 44510f1 pinned to termaxa/backup/b-1783006590625

$ termaxa rollback b-1783006590625
✓ origin/main restored to 44510f1
```

Force push measures what the remote will *lose*, not just gain — and pins it to a backup branch first.

### After a session: the report

```console
$ termaxa report
┌─ Termaxa Execution Report ─────────────────────────
│ commands  : 4   ✓ 1 allow · ? 2 ask · ✗ 1 deny
│ blocked   : ✗ psql -d shop -c "DROP TABLE users"
│ impact    : • DROP users ~50,000 rows, 3 dependent(s)
│            • plan: +3 ~0 -1
│ backups   : 1 — rollback available
│ risk      : Medium  (deny×3 + escalation×2 + ask×1 = 5)
└──────────────────────────────────────────────────
```

Every line is a fact with a source in the audit log. Nothing invented.

## Why Termaxa?

**"Claude Code already asks permission — why do I need this?"**
The built-in prompt tells you the *command*. Termaxa tells you the *consequence*: 50,000 rows, 3 dependent tables, 1 commit lost. It takes the backup **before** you approve, and when it blocks something it tells the model *why*, so the agent proposes an alternative instead of retrying.

**Why not a sandbox / Docker?**
A sandbox contains damage *to the sandbox*. But your repo, your database, and your Terraform state are exactly the real things an agent must touch to be useful. Sandboxes are walls; Termaxa is a windshield. They're complementary — run both.

**Why not OPA / policy engines?**
OPA decides allow/deny well. It has no execution previews, no automatic backups, no rollback, and no agent-native hook. Termaxa is policy *plus* the things you actually want when an agent is holding the keyboard.

## Architecture

```
                     a command the agent wants to run
                                  |
        +-------------------------v-------------------------+
        |                       TERMAXA                       |
        |                                                   |
        |  shell split -> policy -> context -> decision     |
        |  (&&, ;, |)     (yaml)   (branch,    (allow/      |
        |                          flags,       ask/deny)   |
        |                          prod, SQL)      |        |
        |                                          v        |
        |              preview <-------------- consequential|
        |         (git loss, pg blast radius,      |        |
        |          terraform plan)                 v        |
        |              insurance <------------- destructive |
        |         (git ref / pg_dump / files)      |        |
        |                                          v        |
        |                                       execute     |
        |                                          |        |
        |  audit (JSONL, ~/.termaxa) <---------------+        |
        |  notify (webhook)   report (session summary)      |
        +---------------------------------------------------+
```

Six engines, one binary. Policy is in-repo (`.termaxa/policy.yaml`, reviewable in PRs); logs and backups live in `~/.termaxa/` where no `git` operation can touch them.

## Policy

`.termaxa/policy.yaml` — first match wins, `*` is a wildcard, matching is case- and whitespace-insensitive:

```yaml
version: 1
default: ask                     # unmatched commands require approval

rules:
  - match: "git status*"
    action: allow
  - match: "git push*--force*"
    action: ask
    reason: "Force push — remote history will be overwritten."
  - match: "*drop table*"
    action: deny
    reason: "DROP TABLE is blocked. Archive or rename instead."

notify:                          # optional
  webhook: https://hooks.slack.com/services/...
  on: [deny, ask]
```

## Command reference

| Command | Purpose |
|---|---|
| `termaxa init [--claude-code]` | scaffold `.termaxa/`, detect tools, install the hook |
| `termaxa check "<cmd>"` | dry-run: verdict + preview (exit 0/3/4) |
| `termaxa run -- <cmd>` | gated execution: preview → approve → backup → run |
| `termaxa hook` | Claude Code PreToolUse mode (stdin JSON → decision) |
| `termaxa log [--decision D] [--source S] [--json]` | the audit trail |
| `termaxa stats` | totals, sessions, top blocked |
| `termaxa backups` · `termaxa rollback <id>` | list / restore backups |
| `termaxa report [--session ID] [--all] [--md]` | session summary |
| `termaxa notify --test` | verify your webhook |
| `termaxa paths` | where policy and state live |

## Honest limitations

Termaxa is v0.9. It's real and tested, and it is not magic. Specifically:

- **Cooperative, not a sandbox.** Termaxa governs commands that flow through the Claude Code hook or `termaxa run`. An agent with raw, unhooked shell access is *not* contained — that needs OS-level sandboxing, a complementary layer. The threat model is *agents making expensive mistakes*, not a malicious agent actively evading you.
- **Shell parsing is good, not perfect.** It splits on `&&`, `||`, `;`, `|` and flags `$(...)`. Subshells `( )`, deeply nested quoting, and variable-expanded commands are judged conservatively, not deeply understood.
- **Previews are best-effort.** No database connection → static analysis only. Terraform previews shell out to `terraform plan`. Remote Terraform state is versioned by its backend, not by Termaxa.
- **Backups have edges.** `rm` insurance keys on the literal `rm` command. Postgres backups use `pg_dump`/`psql` and must be on your PATH. No retention/pruning yet — backups accumulate.
- **The format may still change.** Pre-1.0 means the policy schema and CLI can shift between minor versions. Pin a release.

See [SECURITY.md](SECURITY.md) for the full threat model.

## Contributing

Issues and PRs welcome. `cargo test` must pass; CI runs on Linux, macOS, and Windows. The codebase is ~3,500 lines of dependency-light Rust — `src/policy.rs` and `src/preview.rs` are the best places to start reading.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
