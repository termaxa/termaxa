<div align="center">

# 🛡 Termaxa

**A gate between an AI coding agent and your shell.** Before a command runs, Termaxa shows what it would destroy, takes a backup it can restore, and asks or refuses by a policy you can read. For people running Claude Code, Codex, Cursor or Copilot CLI, alone or unattended.

**Try it in ten seconds:** [play.termaxa.com](https://play.termaxa.com) runs the real gate on a throwaway project. **Install:** `brew install termaxa/tap/termaxa` or `cargo install termaxa`.

<img src="https://termaxa.com/termaxa-claude-code-v2.gif" alt="A real Claude Code session with its own approvals switched off: the agent inspects scratch/, tries rm -rf ./scratch, and Termaxa's hook stops it with the reason and the 12 files it would have taken; the agent declines to route around it" width="800">

*A real Claude Code session, approvals off: the inspection runs, the `rm -rf` is stopped with its reason and its blast radius, and the agent declines to route around it. Recorded on Claude Code 2.1.283.*

[![CI](https://github.com/termaxa/termaxa/actions/workflows/ci.yml/badge.svg)](https://github.com/termaxa/termaxa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/termaxa/termaxa?display_name=tag)](https://github.com/termaxa/termaxa/releases)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

</div>

---

## The problem

A coding agent runs shell commands on its own, and the damage rarely comes from a clever attack. It comes from an ordinary chore done with the most forceful spelling available: `rm -rf` for a cleanup, `--force` for a push, `reset --hard` for an undo. Your choices have been to supervise every command, which defeats the point of an agent, or to trust it blindly, which works until it doesn't.

It isn't a rare failure. Measured in October 2026 across 36 models: asked to *"undo my last commit"*, 19 of them ran `git reset --hard` and destroyed uncommitted work in a file nobody had mentioned ([the benchmark](https://www.kaggle.com/benchmarks/devdoc83/destructive-reach), [the write-up](https://dev.to/zerodrop/asked-to-undo-a-commit-19-of-36-models-destroyed-work-nobody-mentioned-54je)).

## What Termaxa does

Termaxa is a single Rust binary that sits in the agent's hook path, with no model, no service and no account. For every command:

1. **Decides** by a policy in your repository: allow, ask or deny. First matching rule wins; unmatched commands ask.
2. **Previews the consequence,** not the text: the files a delete takes, the commit a force push loses, the rows a `DROP` removes, the uncommitted edits a `reset --hard` discards.
3. **Insures** before anything runs: copies the files, pins the ref, dumps the table, snapshots the edits, so `termaxa rollback` can undo it.
4. **Escalates** an agent that keeps trying: a circuit breaker counts destructive *intent* across spellings and shells, and trips.
5. **Records** every decision in an append-only, hash-chained log the agent cannot rewrite.

```console
$ termaxa check "rm -rf ./scratch"
command   rm -rf ./scratch
decision  deny
rule      *rm -rf*
reason    Recursive force delete blocked by default policy.
context   destructive flag detected: -rf  ⚠

delete impact
  target      : /home/dev/proj/scratch
  contains    : 12 files across 1 directory
  insurance   : copy 1 path(s) to .termaxa/backups before deletion (automatic on run/hook)
```

*Every console sample on this page was captured from the binary on a fixture. Paths are shortened, and the doctor and report outputs are abridged.*

## Why not the prompt you already have?

**The agent's own prompt** shows you the command. Termaxa shows you what the command would do, and stops the dangerous few even when nobody is watching the prompt. The recording above is a session with the agent's approvals switched off.

**A sandbox** contains what a command can reach. Termaxa judges what a command would destroy inside the reach you gave it: a sandbox that includes your repository lets `rm -rf ./src` through. They're complementary; use both when you need hard guarantees.

**A policy engine** (OPA and friends) evaluates a string against rules. Termaxa adds the three things a string doesn't carry: the consequence, the backup, and the record. The policy is still a file in your repo, reviewable in a pull request.

## Quick start

The order that works: judge your past, observe your present, then enforce.

**1. Install.**

```bash
brew install termaxa/tap/termaxa     # macOS / Linux (prebuilt, sha256-pinned)
cargo install termaxa                # any OS, with a Rust toolchain
winget install Termaxa.Termaxa       # Windows (the winget manifest can lag a release)
scoop bucket add termaxa https://github.com/termaxa/scoop-bucket && scoop install termaxa   # Windows, always current
```

Or download the asset for your platform from [Releases](https://github.com/termaxa/termaxa/releases): every one is attested and checksummed, and the Linux one is a static musl build that runs on any distro. There is deliberately no `curl | sh` installer, because Termaxa flags that pattern as a hazard and the gate's rules apply to the gate.

**2. Judge what your agents have already run.** Nothing is installed in a project, nothing is executed:

```bash
termaxa check "rm -rf /"      # works immediately, no setup
termaxa replay                # every command your agents have run on this machine, judged
```

`replay` reads the transcripts Claude Code and Codex keep under your home directory and answers the question to ask before adopting a gate: how often would it have asked about your ordinary work? Every ask it lists is a rule to add, or a reason it should stay an ask.

**3. Wire a project, in observe mode.**

```bash
cd your-project
termaxa init --claude-code --observe    # or --codex, --cursor, --copilot
termaxa doctor                          # proves the hook fires; "configured" alone is not enough
```

In observe mode every command still runs, the backups are still taken, and the record fills with what enforcement *would* have done. The hook says nothing, so your agent's prompts are exactly what they were.

**4. Read the report, then enforce.**

```bash
termaxa report       # "Observed, not enforced": what would have been asked, denied, and what ran with no copy
```

When *ran with no copy* is a number you can't live with, set `mode: enforce` in `.termaxa/policy.yaml`. From then on, every shell command the agent runs in this project passes through the gate first. Runtime state (logs, backups) lives under `~/.termaxa/`, outside your repository.

## What it looks like

### A compound command is judged by its worst part

```console
$ termaxa check "git status && rm -rf ./build"
command   git status && rm -rf ./build
decision  deny
rule      *rm -rf*
reason    segment 2/2 `rm -rf ./build` — Recursive force delete blocked by default policy.
context   destructive flag detected: -rf  ⚠

delete impact
  target      : /home/dev/proj/build
  contains    : 1 files across 1 directory
  insurance   : copy 1 path(s) to .termaxa/backups before deletion (automatic on run/hook)
```

`&&`, `||`, `;`, `|` and a lone `&` are split and judged per segment; the most dangerous segment governs. The first live Claude Code session found `git status && <anything>` riding a `git status*` allow rule; that bypass has been a named regression test since v0.7 ([GHSA-rv66-7qcx-c45j](https://github.com/termaxa/termaxa/security/advisories/GHSA-rv66-7qcx-c45j)).

### Blast radius, before you commit to it

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

Row estimates come from the planner (`pg_class.reltuples`, stale between `ANALYZE`s); Termaxa never scans your tables, and the preview never executes anything of yours. It did once: the Postgres preview could run the SQL file it was analysing ([GHSA-gxg4-5fmj-534m](https://github.com/termaxa/termaxa/security/advisories/GHSA-gxg4-5fmj-534m), fixed in v0.14.1), which is why "the preview runs nothing on a denied command" is now a rule with tests.

### An agent that retries can't syntax its way through

```console
$ rm -rf .                        -> ask   (file-delete #1)
$ Remove-Item -Recurse -Force .   -> ask   (file-delete #2, different shell)
$ del /s /q .                     -> DENY  circuit breaker: 2 prior
                                     file-delete attempts this session
```

Three shells, one intent, third variant denied, with no rule enumerated per spelling. `find -exec rm`, `xargs rm` and `unlink` count too. The breaker is on by default (threshold 2, `circuit_breaker:` in the policy). A trip holds that intent for the whole project, across sessions, until `termaxa breaker resume --reason "…"` releases it, recorded with who and why, or an optional `resume_after` expires it. `termaxa breaker status` shows what is holding.

### Destroy, then un-destroy

```console
$ termaxa run -- git reset --hard HEAD
┌ termaxa
│ command : git reset --hard HEAD
│ decision: ask
│ reason  : no rule matched; policy default is `ask`
│ context : destructive flag detected: --hard  ⚠
└
┌ discard impact
│  uncommitted : changes in 1 file would be discarded
│  files       : docs/notes.md
│  insurance   : snapshot them with git stash before they are discarded (automatic on run/hook)
└
Proceed? [y/N] y
🛟 backup b-1791356096439 — uncommitted changes in 1 file(s) snapshotted to refs/termaxa/backup/b-1791356096439 (a4136247); `git stash apply a4136247` brings them back
HEAD is now at 35105b7 c1

$ termaxa rollback b-1791356096439
restore  : b-1791356096439 [git-stash]
saved    : uncommitted changes in 1 file(s) snapshotted to refs/termaxa/backup/b-1791356096439 (a4136247); `git stash apply a4136247` brings them back
insured  : git reset --hard HEAD
Restoring writes data. Proceed? [y/N] y
✓ uncommitted changes in 1 file(s) restored from a4136247
```

`git reset --hard`, `git checkout -- <paths>` and `git restore <paths>` throw away uncommitted changes, and git's reflog never had them: it keeps commits, and uncommitted work was never one. This is the idiom from the benchmark above, and the snapshot is the answer to it. A force push is the same shape at the remote, and the starter policy simply denies it:

```console
$ termaxa check "git push --force origin main"
decision  deny
rule      git push*--force*
reason    Force pushes are blocked by policy. Open a PR instead.
context   current branch: main  ⚠
context   destructive flag detected: --force  ⚠
```

A project that relaxes that rule to an ask gets the push preview (the commits the remote would *lose*) and the insurance: the remote ref is pinned to a local backup branch before the push, and `rollback` pushes it back.

### What a delete actually costs

Deletes are the most common destructive command and the easiest to get wrong, because a path can look correctly scoped right up until it isn't:

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

`/c/Users/harih` is Git Bash syntax for `C:\Users\harih`, a real user profile. Termaxa resolves the path, counts what is inside it (budgeted: 5,000 files or 300 ms, and it says when it stopped counting), flags credentials in the blast radius, and says whether a backup is even possible. An ordinary in-project delete says none of that, which is the point: a warning that fires on `rm -rf ./target` is a warning nobody reads.

What it can't do is know what you meant. If the path has a typo in it, Termaxa faithfully reports the blast radius of the path you typed. Making that gap visible before execution is the whole contribution.

### After a session

The failure nobody warns you about: the hook is installed, the agent doesn't call it, and everything looks fine. `termaxa doctor` invokes the registered hook with a must-deny payload and reports whether it fired. It used to grep for the hook's name, and said "configured" in green through two sessions that ran ungated (Windows, August 13, 2026); that is why it probes now.

```console
$ termaxa doctor

Termaxa doctor
──────────────────────────────────────────
✓ termaxa 0.21.1
  /usr/local/bin/termaxa

Policy
✓ /home/dev/proj/.termaxa/policy.yaml
  203 rule(s), default ask
  enforce mode (default)
  fingerprint 69edb158b1af
  ✓ unchanged since 2026-10-07T06:54:22Z

Agents
✓ Claude Code  hook configured and live

Preview support
✓ git        force-push previews and git backups
· psql       Postgres blast radius unavailable
· pg_dump    Postgres backups unavailable
· terraform  plan previews unavailable
```

The fingerprint is how a policy edit gets noticed: `init` records a hash, and `doctor` says when the file no longer matches it. `termaxa report` reads the record and says what happened:

```console
$ termaxa report

Session   session s1
──────────────────────────────────────────
Commands            10   ✓ 3 · ? 4 · ✗ 3
Asks                4   approved 0 · declined 0 · unanswered 4
Previews            2
Backups             1

Destructive intents
──────────────────────────────────────────
file-delete         2
git-destructive     2
breaker trips       0

Observed, not enforced
──────────────────────────────────────────
enforcement would have asked 4 and denied 2
  insured             1   a copy was taken first
  known, uninsured    3   understood, nothing could be copied
  consequence unknown 2   the gate could not read what they change
  held by the floor   1   denied even in observe mode
ran with no copy: 5
```

Every line is a fact with a source in the audit log. The report reads the local append-only log, makes no network calls and sends no telemetry. `termaxa replay --against-record` goes one step further and holds your agents' transcripts against that log, sorting every shell call into judged, fired-but-unrecorded or never-fired. Its first run flagged nine calls as never fired; all nine were defects of its own transcript reader, each now a test. A tool that can disprove its own findings is the point of the check.

## Harnesses

| Harness | Wire it | How a verdict reaches the agent | Measured on | The caveat that matters |
|---|---|---|---|---|
| **Claude Code** | `termaxa init --claude-code` → `.claude/settings.json` (`PreToolUse` on `Bash` and the write tools) | an ask prompts inside the agent; a deny carries the reason and the preview | 2.1.283 (the recording above) | every Bash call arrives wrapped in a preamble, which the gate reads as scaffolding |
| **Codex CLI** | `termaxa init --codex` → `.codex/hooks.json` (`Bash` and `apply_patch`) | **deny only**: Codex rejects an explicit allow and has no ask, so an ask is a refusal with its reason; `apply_patch` is judged as the files it writes | 0.155.1 (Sep 19, 2026) | the agent reads the refusal and decides; nothing prompts you |
| **Cursor** | `termaxa init --cursor` → `.cursor/hooks.json` (shell and file tools; `Delete` is a delete) | an ask shows "Hook requested approval" in Allowlist and Run Everything; a deny is blocked everywhere | 3.21.16 (Oct 4, 2026) | **in Auto-review mode, Cursor's reviewer overrides a hook's ask and runs the command.** Confirmed by Cursor's support, Oct 6, 2026, and flagged to their team. Use Allowlist or Run Everything with Termaxa; `doctor` says so |
| **Copilot CLI** | `termaxa init --copilot` → `.github/hooks/hooks.json` | an ask prompts even under Allow All; a deny is blocked | 1.0.83 and 1.0.91 (Oct 4, 2026) | Copilot treats a hook's *allow* as an approval and skips its own prompt. In enforce mode that is the gate approving; in observe mode the gate stays silent, so Copilot's prompts are unchanged (v0.20.1 fixed the version that didn't) |
| **Herdr** | `herdr plugin install termaxa/termaxa` | a pane starts the agent under the gate; the sidebar shows a refusal; the record opens beside it | see [`herdr-plugin/`](herdr-plugin/) | the plugin wires the harness it starts |
| **Anything else** | `termaxa run -- <cmd>`, or `termaxa wrap -- <agent>` (Unix) | `run` gates one command; `wrap` shims the shells an agent resolves by name | Claude Code under `wrap`, Linux, with and without zsh | a harness that names `/bin/sh` by absolute path stays outside `wrap`; hooks are the way in |

Each harness speaks its own dialect, and dialects change: Cursor 3.11 renamed its hook events and four releases went ungated before v0.11.4. The dialects are captured, by version, in [docs/dialects.md](docs/dialects.md), and the hook **fails open** on a payload it can't read, by design, because a gate that fails closed on every harness update becomes the outage. `unrecognised: deny` in the policy flips that for unattended runs.

<img src="https://termaxa.com/termaxa-herdr.gif" alt="In a multiplexer, one action starts Claude Code under the gate; the refused rm -rf shows on the sidebar as termaxa deny, and the record opens beside the agent" width="800">

## Modes

**Enforce** is the default: asks ask, denies deny, insurance before execution.

**Observe** (`mode: observe`, `termaxa init --observe`, or `TERMAXA_MODE=observe` on one machine) runs everything and records what enforcement would have done, insurance included. The hook stays silent, so the agent's own prompts are unchanged. The exception is the floor: 33 starter rules marked `floor: true` are enforced in both modes, and so is any command whose insurance cannot be taken. They cover the gate's own configuration and state, the machine and its recovery points, and commands with no recovery path: `rm -rf /`, `mkfs`, `dd` to a device, shadow-copy deletion, `drop database`, database resets, `kubectl delete`, `terraform destroy`, `docker system prune`, `find -delete`. Policies written before v0.20 have no floor markers; add `floor: true` to the rules you would never relax, or take the 33 from [`examples/policy.yaml`](examples/policy.yaml). Design and measurements: [docs/observe-mode.md](docs/observe-mode.md).

**Supervised** (Unix) moves the authority. A daemon running as you makes every decision; the agent runs as a second account that cannot read the audit log, edit the backups, change the policy or stop the supervisor, because the operating system refuses, not the code.

```bash
termaxa init --supervised     # prints the setup; runs none of it
termaxa supervise &           # as you
sudo -u termaxa-agent termaxa wrap -- claude
```

`init --supervised` prints and never executes: creating a user and chowning a tree need root, and a tool that asks for root to set things up is asking for exactly the authority this mode exists to bound. A boundary rig proves it with 23 assertions, each with a control leg. The first real agent session under it found that no command reached the supervisor at all; the [field report](docs/field-reports/2026-08-17-supervised-routing.md) is published with what broke, and the fix is in v0.17. Full setup, the credential trade-off and what remains untested: [docs/supervisor.md](docs/supervisor.md).

**`wrap`** (Unix) is for agents without hooks: `termaxa wrap -- <agent>` shims the shells the agent resolves by name, and sets `CLAUDE_CODE_SHELL` for Claude Code, which honours it.

## What it insures, and what it can't

Destructive doesn't mean recoverable. Each row is what the code does; the last two are what it doesn't.

| Command | Preview | Insurance, taken before execution | `rollback` |
|---|---|---|---|
| a delete (`rm`, `rmdir`, `Remove-Item`, `del`, `rd`; `sudo rm`, `/bin/rm`, `git -C … rm`) | target, file count, what's inside, outside-the-project and credential warnings | the paths copied under `~/.termaxa/`, within the budget (5,000 files or 300 ms); over budget, the copy is refused with the preview's words rather than silently skipped | copies them back |
| an overwrite (a truncating redirect, `cp` onto an existing file, an option that writes a file) | what the existing file loses | the file copied | copies it back |
| a force push, or a push that removes refs | the commits the remote would lose; which refs go | the remote ref pinned to a local backup branch | force-pushes the pinned ref back |
| `git reset --hard`, `git checkout -- <paths>`, `git restore <paths>` | the uncommitted changes that would be discarded, by file | a stash snapshot pinned under `refs/termaxa/backup/` | applies it, staged state included |
| `DROP`, `TRUNCATE`, `DELETE` through `psql` | rows, dependents, whether the statement even succeeds | `pg_dump` of the tables (schema and data for `DROP`, data only otherwise) | replays the dump |
| `terraform apply` | the plan's add/change/destroy counts | the local state file copied; remote state is the backend's job | the state file, **not** the destroyed resources |
| `terraform destroy`, `find -delete`, `docker system prune`, database resets | the floor denies them; nothing is copied first, and nothing could be | none | none |
| a script the agent wrote (`python cleanup.py`), a deletion inside a language runtime, `git branch -D` | the gate cannot read what they change; `git branch -D` asks | none | none |

## Policy

`.termaxa/policy.yaml`: first match wins, `*` is a wildcard, matching is case- and whitespace-insensitive and sees through the spellings the resolver knows (`-C`, `env`, `sudo`, a variable assigned on the same line):

```yaml
version: 1
default: ask                     # unmatched commands require approval
mode: enforce                    # or observe

rules:
  - match: "git status*"
    action: allow
  - match: "git push*--force*"
    action: deny
    reason: "Force pushes are blocked by policy. Open a PR instead."
  - match: "*find* -delete*"
    action: deny
    reason: "find -delete removes everything it matches and nothing is copied first. Delete named paths with rm instead."
    floor: true                  # enforced even in observe mode

circuit_breaker:
  enabled: true
  threshold: 2
```

The starter `init` writes has 203 rules: 141 allow, 14 ask, 48 deny, 33 of them floor. Native file tools (Claude Code's `Write`, Cursor's `Delete`, Codex's `apply_patch`) are judged by their target through the same path rules, and the gate's own files are protected by rules you can read but the agent cannot rewrite unnoticed: `doctor` reports the fingerprint. `unrecognised: deny` and `backup_failure: deny` are the two switches for unattended runs.

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

Six engines, one binary. Policy is in-repo and reviewable in pull requests; logs and backups live under `~/.termaxa/`, where no `git` operation can touch them.

## Command reference

| Command | Purpose |
|---|---|
| `termaxa` | what this is, and what to try next |
| `termaxa init [--claude-code\|--codex\|--cursor\|--copilot] [--observe]` | scaffold `.termaxa/`, detect tools, install the hook; `--observe` starts in observe mode |
| `termaxa replay [paths…] [--all]` | judge every command in your agents' transcripts; nothing executed |
| `termaxa replay --against-record` | hold the transcripts against this machine's record: judged, fired-but-unrecorded, or never-fired. Exit 1 if either bypass is found |
| `termaxa demo` | the gate on a throwaway project: three checks and the record |
| `termaxa wrap -- <agent>` | launch an agent with shelled commands routed through the gate (Unix) |
| `termaxa supervise` | run the decision daemon as yourself; hooks decide through it (Unix) |
| `termaxa init --supervised` | print the supervised-mode setup; prints, never executes |
| `termaxa doctor` | is the gate wired up? binary, policy, agents, tools, state |
| `termaxa check "<cmd>"` | dry-run: verdict + preview (exit 0/3/4) |
| `termaxa run -- <cmd>` | gated execution: preview → approve → backup → run |
| `termaxa hook` | agent hook mode (stdin JSON → decision) |
| `termaxa log [-n N] [-f] [--decision D] [--source S] [--json]` | the audit trail; `-f` follows it |
| `termaxa stats` | totals, sessions, top blocked |
| `termaxa backups [--prune]` · `termaxa rollback <id>` | list / prune / restore backups |
| `termaxa report [--session ID] [--all] [--days N] [--md]` | session summary + rollup; in observe mode, what enforcement would have done |
| `termaxa breaker status` | the circuit breaker's standing trips for this project |
| `termaxa breaker resume --reason "…"` | release a trip, recorded with who, when and why (`reset` needs no reason) |
| `termaxa notify --test` | verify your webhook |
| `termaxa paths` | where policy and state live |

Colour is on when output is a terminal and off when it isn't. `NO_COLOR`, `TERMAXA_NO_COLOR` and `CLICOLOR_FORCE` are respected.

## Honest limitations

Termaxa is pre-1.0. It's real and tested, and it is not magic.

- **Hooks advise; they don't enforce.** The agents are cooperative: they respect a deny and propose an alternative, which is what makes the gate work. An agent in full-auto mode could retry a blocked action through another command or shell; the breaker raises the cost of that, but a hook is an integration point, not an enforcement boundary. Supervised mode moves who decides, not where the boundary is. For hard guarantees, pair Termaxa with OS-level sandboxing.
- **Cooperative, not a sandbox.** Termaxa governs commands that flow through a hook, `termaxa run` or a wrapped shell. Raw, unhooked shell access is not contained.
- **Native tools are judged by their target only.** A `Write` to `.env` is denied; a `Write` whose content is a script that deletes things is a write. What the agent then runs is judged when it runs it.
- **The gate fails open on a payload it doesn't recognise, by design.** `doctor` and the liveness probe are how you find out; `unrecognised: deny` is the switch for runs where a stopped agent is cheaper than an ungated one.
- **Shell parsing is good, not perfect.** Compound commands, `-c` strings, `eval`, same-line variables and the global options of git, kubectl, terraform, tofu and docker are read as what they run, and a program named by its path is read by its name for deny rules; `$(…)` is flagged unless the policy would allow what's inside. Subshells and deep quoting are judged conservatively. A path built from the caller's environment (`rm -rf ~/x/$SID`) is carried as *unresolved*, not guessed.
- **Previews are best-effort.** No database connection means static analysis only; Terraform previews shell out to `terraform plan`.
- **Backups have edges.** A delete expressed through a script or a language runtime is not insured; a target over the budget is refused rather than silently uninsured; a link is copied as a link, never followed into the tree behind it, which is the mechanism of the Sep 20, 2026 incident that deleted 48,218 live files through directory junctions.
- **The format may still change.** Pin a release.
- **Windows PowerShell 5.1 mangles redirected Unicode.** `termaxa report > out.txt` writes UTF-16 and garbles the box-drawing glyphs. Use PowerShell 7, or `termaxa report --md | Out-File -Encoding utf8 report.md`.

Every bug found in real use, with how it was found and where it was fixed, is in [docs/found-in-the-wild.md](docs/found-in-the-wild.md): 34 so far. The threat model and the published advisories are in [SECURITY.md](SECURITY.md).

## Contributing

Rust 2021, ~16,600 lines of production code and ~17,000 of tests, 552 tests on Linux, CI on Linux, macOS and Windows. `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` are the gate, and the gate's rules apply to the gate. Measurements beat opinions here: a change that alters a verdict comes with the fixture that shows it.

## Security

Found a bypass? [SECURITY.md](SECURITY.md) says how to report it and what happens next; five advisories are published there, one from an outside researcher, each with its exposure window in UTC.

## License

MIT or Apache-2.0, at your option.
