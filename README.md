<div align="center">

# 🛡 Termaxa

**Run AI coding agents with confidence.**

Termaxa gates the shell commands an agent runs — previews the blast radius, backs up first, blocks the dangerous ones, and escalates repeat offenders. It's a cooperative windshield, not a sandbox.

[![CI](https://github.com/termaxa/termaxa/actions/workflows/ci.yml/badge.svg)](https://github.com/termaxa/termaxa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/termaxa/termaxa?display_name=tag)](https://github.com/termaxa/termaxa/releases)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

</div>

---

Your AI agent wants to run `git push --force`, `DROP TABLE users`, `terraform apply`, `rm -rf`. Most of the time it's right. Sometimes it isn't. Today your only options are *supervise every command* (which defeats the point of an agent) or *trust it blindly* (which defeats your Friday).

Termaxa is a third option: a gate the agent's commands pass through. It reads a policy you wrote, shows you what's actually about to happen, backs up what's about to change, and records everything. Built for **Claude Code** and **Cursor** today; works as a standalone CLI anywhere.

```
  Claude Code --> TERMAXA --> git . postgres . docker . terraform . your shell
                    |
                    +- decide    allow / ask / deny  (your policy)
                    +- preview   commits lost, rows affected, resources destroyed
                    +- insure    automatic backup before destructive ops
                    +- escalate  repeated destructive intent -> auto-deny
                    +- record    every attempt, with an execution report
```

## Quick start (5 minutes)

**1. Install.** Download a prebuilt binary from [Releases](https://github.com/termaxa/termaxa/releases) and put it on your PATH — or, with a Rust toolchain:

```bash
cargo install termaxa
termaxa                       # what this is, and what to try next
termaxa check "rm -rf /"      # works immediately — no setup, no project config
```

**2. Wire up a project.**

```bash
cd your-project
termaxa init --claude-code      # writes .termaxa/policy.yaml, installs the Claude Code hook
termaxa doctor                  # confirm it's actually wired up
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
decision  deny
reason    segment 2/2 `rm -rf /` — Recursive delete from root is blocked.
```

Termaxa splits compound commands and judges each part. `git status &&` buys nothing.

### 2 - Blast radius, before you commit to it

```console
$ termaxa check "psql -d shop -c 'DROP TABLE users'"
decision  deny
reason    DROP TABLE is blocked. Archive or rename instead.

postgres impact
  DROP TABLE users
    rows (estimate) : 50,000
    referenced by   : audit_log, orders, sessions (3 tables)
    without CASCADE : this DROP will FAIL (dependents exist)
  insurance : pg_dump users before execution (automatic on run/hook)
```

Row estimates come from the planner (`pg_class.reltuples`, stale between `ANALYZE`s) — Termaxa never scans your tables.

### 3 - An agent that retries can't syntax its way through

An agent blocked on `rm -rf .` will often just try again with different words. Termaxa classifies the *intent*, not the spelling, and trips a per-session circuit breaker on repeat attempts:

```console
$ rm -rf .                        -> ask   (file-delete #1)
$ Remove-Item -Recurse -Force .   -> ask   (file-delete #2, different shell)
$ del /s /q .                     -> DENY  circuit breaker: 2 prior
                                     file-delete attempts this session
```

Three shells, one intent, third variant auto-denied — no rule enumerated per spelling. `find -exec rm`, `xargs rm`, and `unlink` count too. Configure via `circuit_breaker:` in `policy.yaml` (on by default, threshold 2).

### 4 - Destroy, then un-destroy

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

### 5 - What a delete actually costs

Deletes are the most common destructive command and the easiest to get wrong,
because a path can look correctly scoped right up until it isn't:

```console
$ termaxa check "rm -rf /c/Users/harih"
decision  ask
reason    no rule matched; policy default is `ask`

delete impact
  target      : C:\Users\harih
  as written  : /c/Users/harih
  ⚠ OUTSIDE the project root (C:\Users\harih\project)
  ⚠ resolves to a USER PROFILE directory
  ⚠ contains  : .ssh (SSH private keys), .aws (AWS credentials)
  contains    : 5,000+ files (stopped counting) across 422 directories
  ✗ insurance : too large to copy (5,000+ files) — NOT recoverable
```

`/c/Users/harih` is Git Bash syntax for `C:\Users\harih` — a real user
profile, not a stray directory. Termaxa resolves the path, counts what's
actually inside it (budgeted: 5,000 files or 300ms, and it says when it
stopped counting), flags credentials in the blast radius, and tells you
whether a backup is even possible.

An ordinary in-project delete says none of that, which is the point — a
warning that fires on `rm -rf ./target` is a warning nobody reads:

```console
$ termaxa check "rm -rf ./target"
delete impact
  target      : /home/you/project/target
  contains    : 1,204 files across 38 directories
  insurance   : copy 1 path(s) to .termaxa/backups before deletion
```

**What it can't do:** know what you meant. If the path has a typo in it,
Termaxa will faithfully report the blast radius of the path you actually
typed. Making that gap visible before execution is the whole contribution.

### Is it actually wired up?

The failure mode nobody warns you about: the hook is installed, the agent doesn't call it, and everything looks fine. `termaxa doctor` answers the question directly.

```console
$ termaxa doctor

Termaxa doctor
──────────────────────────────────────────
✓ termaxa 0.15.0
  /home/you/.cargo/bin/termaxa

Policy
✓ /home/you/project/.termaxa/policy.yaml
  67 rule(s), default ask
  fingerprint 1aa53b6e0d64
  ✓ unchanged since 2026-08-13T18:10:22Z

Agents
✓ Claude Code  hook configured and live

Preview support
✓ git        force-push previews and git backups
· psql       Postgres blast radius unavailable
· pg_dump    Postgres backups unavailable
· terraform  plan previews unavailable

State
✓ /home/you/.termaxa/projects/project-4005e00d
  3 audit entries (3 from hooks)

──────────────────────────────────────────
✓ Everything checks out.
  proof is in the log: run your agent, then `termaxa report`
```

**Configured and live** is earned, not assumed: doctor invokes the registered hook command exactly as the agent would — synthetic must-deny payload on stdin, two-second timeout — and requires a decision back. Three states: **configured and live** (it answered), **registered but NOT firing** (a registration exists, the command doesn't run — worse than absent, because it's the state that *looks* safe), and **not configured**. Until v0.15 doctor only checked that a registration existed; a hook whose path was mangled at exec failed non-blocking, two full sessions ran ungated, and doctor said "configured" in green throughout.

Two honest boundaries. The probe only runs binaries named `termaxa` — a settings file arrives with a cloned repo and is untrusted input. And **live means "answered when doctor invoked it"**: if the agent's own invocation is broken on the agent's side, the probe can't see that — which is why doctor pairs it with the log. Live here plus no recent hook entries there means the agent has never reached the gate; doctor says so and points you at `TERMAXA_HOOK_DEBUG`, because agents rename their hook APIs, and when they do, the gate fails open and silent (see [Honest limitations](#honest-limitations)). Doctor is read-only, probe included: no backup, no audit entry, no notification — proven by test against the real binary.

### After a session: the report

```console
$ termaxa report

Session   session a3f8c21
──────────────────────────────────────────
Duration            18 min
Commands            41   ✓ 34 · ? 6 · ✗ 1
Escalated           2
Auto-flow           34
Previews            4
Backups             3
Rollbacks           0

Destructive intents
──────────────────────────────────────────
file-delete         5
db-destroy          1
breaker trips       1

Insight
──────────────────────────────────────────
The breaker blocked file-delete 1 time in this scope.

This often indicates:
• generated files being cleaned
• build/output directories
• an agent retry loop

If this work is intentional, add an explicit allow rule
scoped to the paths involved — relaxation is deliberate.

Recent events
──────────────────────────────────────────
? git push --force origin main
✗ psql -d shop -c "DROP TABLE users"
✓ cargo test

Backups   : 3 — rollback available (`termaxa backups`)
Risk      : High    (deny×3 + escalation×2 + ask×1 = 13)

Last 30 days
──────────────────────────────────────────
Sessions        12
Commands        341
Decisions       ✓ 302 · ? 31 · ✗ 8
Backups         19
Breaker trips   3

Top directories
  api
  crates/core
  web
```

One command, no flags: what the agent tried, what got blocked, what's recoverable — plus a 30-day view. Note that *destructive intents* and *breaker trips* are separate numbers: a legitimate `rm -rf ./build` is a classified intent, not a trip.

Every line is a fact with a source in the audit log. Nothing invented, nothing collected: the report reads the local append-only log, makes no network calls, and sends no telemetry.

## Why Termaxa?

**"Claude Code already asks permission — why do I need this?"**

The built-in prompt tells you the *command*. Termaxa tells you the *consequence*: 50,000 rows, 3 dependent tables, 1 commit lost. It takes the backup **before** you approve, and when it blocks something it tells the model *why*, so the agent proposes an alternative instead of retrying.

**Why not a sandbox / Docker / Claude Code's `/sandbox`?**

A sandbox contains damage *to the sandbox*. But your repo, your database, and your Terraform state are exactly the real things an agent must touch to be useful — and a sandbox's default write scope *is* your working directory. Containment, consequence, and recovery are three different questions: sandboxes answer the first, Termaxa answers the second and third. They're complementary — run both. ([Longer version.](https://termaxa.com/blog/claude-code-sandbox))

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

  # match_path matches the RESOLVED target, not the spelling. `> .env` and
  # `> ./.env` are one file, and a rule needs only one of the two matchers.
  - match_path: "*/.env"
    action: deny
    reason: "Overwriting .env destroys credentials that are not in the repo."

circuit_breaker:                 # optional (on by default)
  enabled: true
  threshold: 2                   # trip on the 3rd repeated destructive attempt

notify:                          # optional
  webhook: https://hooks.slack.com/services/...
  on: [deny, ask]
```

## Command reference

| Command | Purpose |
|---|---|
| `termaxa` | what this is, and what to try next |
| `termaxa init [--claude-code]` | scaffold `.termaxa/`, detect tools, install the hook |
| `termaxa wrap -- <agent>` | launch an agent with shelled commands routed through the gate (Unix) |
| `termaxa doctor` | is the gate wired up? binary, policy, agents, tools, state |
| `termaxa check "<cmd>"` | dry-run: verdict + preview (exit 0/3/4) |
| `termaxa run -- <cmd>` | gated execution: preview → approve → backup → run |
| `termaxa hook` | agent hook mode (stdin JSON → decision) |
| `termaxa log [--decision D] [--source S] [--json]` | the audit trail |
| `termaxa stats` | totals, sessions, top blocked |
| `termaxa backups` · `termaxa rollback <id>` | list / restore backups |
| `termaxa report [--session ID] [--all] [--days N] [--md]` | session summary + rollup |
| `termaxa notify --test` | verify your webhook |
| `termaxa paths` | where policy and state live |

Colour is on when output is a terminal and off when it isn't. `NO_COLOR`, `TERMAXA_NO_COLOR`, and `CLICOLOR_FORCE` are all respected.

## Honest limitations

Termaxa is pre-1.0. It's real and tested, and it is not magic. Specifically:

- **Hooks advise; they don't enforce.** Termaxa gates commands an agent submits through the Claude Code or Cursor hook. Those agents are *cooperative* — they respect a `deny` and propose an alternative, which is what makes the gate work. An agent running in full-auto mode could, in principle, retry a blocked action through a different command or shell; the circuit breaker raises the cost of that, but a hook is an *integration* point for visibility and policy, not an *enforcement* boundary. `termaxa wrap -- <agent>` (Unix, v0.16) widens this: commands the agent runs *through a shell* pass through the gate even without a hook, though a caller naming `/bin/sh` by absolute path still does not. True enforcement means owning the execution path — that's the supervisor, next release. For hard guarantees today, pair Termaxa with OS-level sandboxing.
- **Native agent tools bypass the gate.** The hook sees *shell* commands. An agent's own built-in file/edit tools don't go through the shell — observed in live testing, a Cursor agent switched to its native file-delete tool and removed files Termaxa never saw. Non-shell tool calls need OS-level isolation underneath.
- **Cooperative, not a sandbox.** Termaxa governs commands that flow through the agent hook or `termaxa run`. An agent with raw, unhooked shell access is *not* contained — that needs OS-level sandboxing, a complementary layer. The threat model is *agents making expensive mistakes*, not a malicious agent actively evading you.
- **Shell parsing is good, not perfect.** It splits on `&&`, `||`, `;`, `|`
  and flags `$(...)`. Subshells `( )` and deeply nested quoting are judged
  conservatively, not deeply understood. A path built from a variable
  (`rm -rf ~/x/$SID`) is **not** resolved — Termaxa cannot see the caller's
  environment, and expanding it here would be guessing. Since v0.16 that
  target is carried as *unresolved* rather than resolved-wrongly, which lets
  the policy layer treat it as its own kind of risk instead of pretending to
  know where it points.
- **Previews are best-effort.** No database connection → static analysis only. Terraform previews shell out to `terraform plan`. Remote Terraform state is versioned by its backend, not by Termaxa.
- **Backups have edges.** Since v0.16 delete insurance resolves the command head, so `sudo rm`, `/bin/rm` and `env rm` are covered — but a delete expressed some other way (a script, a language runtime) is not, and a target too large to copy is reported as *not recoverable* rather than silently uninsured. Postgres backups use `pg_dump`/`psql` and must be on your PATH. No retention/pruning yet — backups accumulate.
- **The format may still change.** Pre-1.0 means the policy schema and CLI can shift between minor versions. Pin a release.
- **Claude Code and Cursor are live-tested.** Both are exercised end-to-end, including the circuit breaker tripping under a real Cursor session. Codex and Copilot dialects parse each agent's format but aren't verified end-to-end yet. Help validating them is welcome.
- **Windows PowerShell 5.1 mangles redirected Unicode.** `termaxa report > out.txt` writes UTF-16 and garbles the box-drawing glyphs. That's the shell, not Termaxa — use PowerShell 7, or `termaxa report --md | Out-File -Encoding utf8 report.md`.

See [SECURITY.md](SECURITY.md) for the full threat model.

## Contributing

Issues and PRs welcome. `cargo test` must pass; CI runs on Linux, macOS, and Windows. The codebase is dependency-light Rust: ~9,500 lines of production code in `src/`, plus ~10,500 lines of tests (unit tests live beside the code they test; `tests/` holds the integration ones). More test than product, on purpose — `src/policy.rs` and `src/preview.rs` are the best places to start reading, and the test module at the bottom of each file explains what the code is defending against.

If you can make an agent get past the gate in a way that isn't already documented above, that's the most useful contribution you can make: [open an issue](https://github.com/termaxa/termaxa/issues) or email security@termaxa.com.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
Contributions are accepted under the same terms — dual MIT/Apache-2.0, at the
user's option. No CLA.