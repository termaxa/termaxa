# Aegis

**Policy, approval, preview, insurance, and audit — the layer between AI agents and your tools.**

Your coding agent wants to run `git push --force`, `terraform apply`, or `DROP TABLE users`. Aegis decides — based on a policy you wrote, escalated by context it observes — whether that runs silently, requires approval, or gets blocked. Before consequential commands it shows what will actually happen (commits the remote would LOSE, rows a TRUNCATE would erase, FK blast radius). Before destructive ones it takes automatic backups you can restore by id. Every attempt is logged; denials can notify a Slack channel.

```
Claude Code ──► Aegis ──► git / docker / terraform / psql / ...
                 │
                 ├─ policy.yaml    allow / ask / deny, first match wins
                 ├─ context        branch, force flags, prod markers, SQL
                 ├─ previews       git push gain/LOSS, postgres blast radius
                 ├─ insurance      auto-backup before destruction; `aegis rollback <id>`
                 ├─ notify         Slack-compatible webhook on deny/ask
                 └─ audit.jsonl    every attempt, sessions, outcomes; `aegis stats`
```

## Commands

| Command | What it does |
|---|---|
| `aegis init [--claude-code]` | Scaffold `.aegis/`, detect tools, wire the Claude Code hook |
| `aegis check "<cmd>"` | Dry-run against policy + preview. Exit: 0 allow, 3 ask, 4 deny |
| `aegis hook` | Claude Code PreToolUse mode (JSON stdin → decision stdout) |
| `aegis run -- <cmd>` | Gatekept execution: preview → approval → backup → run |
| `aegis log [-n] [--decision] [--source] [--json]` | Audit trail, filterable |
| `aegis stats` | Totals by decision/source, escalations, sessions, top denied |
| `aegis backups` / `aegis rollback <id>` | List insurance; restore by id |
| `aegis notify --test` | Probe the webhook and report loudly |

## Install

```bash
cargo build --release
cp target/release/aegis ~/.local/bin/   # or anywhere on PATH
```

Requires Rust 1.75+.

## Quick start

```bash
cd your-project
aegis init --claude-code
```

This scaffolds `.aegis/policy.yaml` with a sane starter policy, detects your agent harnesses and CLI tools, and installs a `PreToolUse` hook into `.claude/settings.json`. From that moment, **every Bash command Claude Code attempts flows through Aegis** before it executes.

## Commands

| Command | What it does |
|---|---|
| `aegis init [--claude-code]` | Scaffold `.aegis/`, detect tools, optionally wire the Claude Code hook |
| `aegis check "<cmd>"` | Dry-run a command against policy. Exit codes: 0 allow, 3 ask, 4 deny |
| `aegis hook` | Claude Code PreToolUse hook mode (JSON on stdin → decision on stdout) |
| `aegis run -- <cmd>` | Gatekept execution from your own shell, with interactive approval |
| `aegis log [-n 20]` | Show the audit trail |

## Policy format

`.aegis/policy.yaml` — first matching rule wins, `*` is a wildcard, matching is case-insensitive and whitespace-normalized (so `DROP   TABLE` can't dodge a `drop table` rule):

```yaml
version: 1
default: ask          # what happens when nothing matches

rules:
  - match: "git status*"
    action: allow

  - match: "git push*--force*"
    action: deny
    reason: "Force pushes are blocked by policy. Open a PR instead."

  - match: "git push*"
    action: ask

  - match: "terraform apply*"
    action: ask

  - match: "*drop table*"
    action: deny
    reason: "DROP TABLE is blocked. Archive or rename instead."
```

The `reason` on a deny is fed back to the model in hook mode — so the agent learns *why* and can propose an alternative, instead of retrying blindly.

## Context engine

Policy says *what*; context says *right now*. Before deciding, Aegis gathers cheap local signals:

- current git branch (pushes while on `main`/`master`/`production` escalate)
- destructive flags: `--force`, `--hard`, `-rf`, `--no-verify`
- production markers in the command (`prod`, connection strings)
- destructive SQL: `DROP TABLE`, `TRUNCATE`, `DELETE FROM`

Escalation only goes one way: context can raise `allow → ask`, never lower a decision. A `deny` stays a deny no matter what.

## Claude Code integration

`aegis init --claude-code` writes this into `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "aegis hook" }]
      }
    ]
  }
}
```

Aegis reads the hook event, evaluates, audits, and returns `allow` / `ask` / `deny` through the hook protocol. Non-Bash tools and malformed input fall through untouched — Aegis never breaks your session by guessing.

## Audit trail

Every decision — including blocked attempts — lands in `.aegis/logs/audit.jsonl` as structured JSON: timestamp, source (hook/run/check), command, decision, matched rule, context signals, escalation, approval, exit code, cwd. `aegis log` pretty-prints it; the JSONL is there for anything downstream (dashboards, replay, compliance).

## Honest scope (v0.1)

This is a **cooperative** gate: it governs commands flowing through the agent harness's hook system and through `aegis run`. An agent with unrestricted raw shell access outside the hook path is not contained — that requires OS-level sandboxing, which is a different (complementary) layer. The threat model here is *agents making expensive mistakes*, not agents adversarially escaping.

## Roadmap

- **v0.2** — plugins with real simulation: git diff previews, `terraform plan` auto-wrapping, postgres schema-aware impact analysis ("this DROP cascades to 3 tables, ~2.4M rows — archive instead?")
- **v0.3** — richer context (CI status via `gh`, env detection from connection strings), Slack approval webhook, per-directory policy overlays
- **later** — plugin registry, team policies, central audit (the Cloud story)
