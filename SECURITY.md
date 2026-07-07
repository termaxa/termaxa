# Security & Threat Model

Termaxa is a safety tool, so it owes you an honest account of what it does and does not protect against. Read this before relying on it.

## What Termaxa is for

**Threat model: an AI coding agent making expensive mistakes.** Agents are capable and mostly correct, but they occasionally run a command that destroys work — a force push over teammates' commits, a `DROP TABLE` on the wrong database, a `terraform destroy`, an `rm -rf` with a bad variable. Termaxa exists to put a fast, informed checkpoint in front of those commands: show the consequence, take a backup, record the attempt.

This is the common, real, daily failure mode. It is the one Termaxa addresses well.

## What Termaxa is NOT

**It is not a sandbox, and not a defense against a malicious or adversarial agent.**

Termaxa works by *cooperative interception*: it sees commands that flow through the Claude Code `PreToolUse` hook, or that you run via `termaxa run --`. That covers the normal path an agent takes. It does **not** cover:

- An agent (or process) that calls the real binary directly (`/usr/bin/git`), bypassing the hook.
- Commands run through a language runtime, a subshell Termaxa didn't parse, or an execution path outside the harness.
- Anything on a machine where the hook isn't installed.

If your threat model includes an agent *actively trying to evade you*, you need OS-level isolation — containers, seccomp, VMs, restricted credentials. Termaxa is complementary to those, not a replacement. **Run both.** Termaxa is the windshield; a sandbox is the seatbelt.

## Known limitations that affect safety

- **Shell parsing is heuristic.** Termaxa splits on `&&`, `||`, `;`, `|` and detects `$(...)`/backticks (escalating those to a human). It does not fully parse subshells `( )`, process substitution, or variable-expanded command names. Unparseable constructs are judged conservatively (the policy default, which ships as `ask`), but "conservative" is not "guaranteed."
- **Previews are best-effort and read-only.** Postgres estimates come from planner statistics and can be stale; a `DELETE ... WHERE` is reported as filtered without computing the exact count. Terraform previews trust `terraform plan`. A preview never executes the analyzed statement.
- **Backups have boundaries.** `pg_dump`/`psql` and `git` must be on PATH. `rm` insurance matches the literal `rm` command; shell aliases and absolute paths (`/bin/rm`) are not covered. Remote Terraform state is not backed up (its backend versions it). There is no backup retention/pruning yet.
- **Policy is only as good as you write it.** The starter policy is a sensible default, not a guarantee. Review it. `default: ask` fails closed, which is the safe direction, but an over-broad `allow` rule can still wave through something you'd rather catch.
- **Fail-open on plumbing.** If the hook receives malformed input, Termaxa steps aside rather than breaking your session. This is deliberate (a gate that bricks sessions gets uninstalled) but means a sufficiently broken invocation is ungoverned.

## Design choices that support safety

- **Fail closed on policy** (unmatched → `ask`), fail open on plumbing (broken hook input → step aside).
- **One-way escalation:** context signals can only raise a verdict (allow→ask), never lower one. Heuristics can't weaken an explicit rule.
- **Backups precede execution** on both `run` and `hook`, and never fire on `deny` (nothing runs).
- **State outside the repo:** logs and backups live in `~/.termaxa/`, so a `git reset --hard` can't destroy your audit trail. (This is fixed as of v0.8 — earlier versions kept state in-repo.)
- **Append-only audit:** every attempt, including blocked ones, is recorded and never overwritten.

## Reporting a vulnerability

If you find a way to bypass a policy that *should* hold (e.g. a compound-command or quoting trick that sneaks a destructive command past a matching `deny` rule), please report it.

- Open a GitHub issue for non-sensitive reports, or
- Email **SECURITY-CONTACT@EXAMPLE.COM** for anything you'd rather disclose privately.

Bypass reports are the most valuable contribution you can make. The compound-command splitting in v0.7 exists because the first live agent found exactly such a bypass within minutes — that finding is now a named regression test. We'd rather have yours the same way.
