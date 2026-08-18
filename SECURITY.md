# Security & Threat Model

Termaxa is a safety tool, so it owes you an honest account of what it does and does not protect against. Read this before relying on it.

## What Termaxa is for

**Threat model: an AI coding agent making expensive mistakes.** Agents are capable and mostly correct, but they occasionally run a command that destroys work — a force push over teammates' commits, a `DROP TABLE` on the wrong database, a `terraform destroy`, an `rm -rf` with a bad variable. Termaxa exists to put a fast, informed checkpoint in front of those commands: show the consequence, take a backup, record the attempt.

This is the common, real, daily failure mode. It is the one Termaxa addresses well.

## What Termaxa is NOT

**It is not a sandbox, and not a defense against a malicious or adversarial agent.**

Termaxa works by *cooperative interception*: it sees commands that flow through the agent's shell hook (Claude Code `PreToolUse`/`PostToolUse`; Cursor `beforeShellExecution`/`afterShellExecution` and, on 3.11+, `preToolUse`/`postToolUse`), or that you run via `termaxa run --`. That covers the normal path an agent takes. It does **not** cover:

- An agent (or process) that calls the real binary directly (`/usr/bin/git`), bypassing the hook.
- Commands run through a language runtime, a subshell Termaxa didn't parse, or an execution path outside the harness.
- **An agent's own native file/edit tools.** Observed in live testing: a Cursor agent, blocked on shell deletes, switched to its built-in file-delete tool and removed ~20 files that never passed through the shell hook — so Termaxa never saw them, gated them, or backed them up. Any agent tool that acts on the filesystem without going through a shell command is outside the gate.
- Anything on a machine where the hook isn't installed.

If your threat model includes an agent *actively trying to evade you*, you need OS-level isolation — containers, seccomp, VMs, restricted credentials. Termaxa is complementary to those, not a replacement. **Run both.** Termaxa is the windshield; a sandbox is the seatbelt.

**Termaxa is an enforcement and recovery layer, not an isolation layer.** It can decide what an intercepted action should do, explain the consequence before it happens, preserve recoverability, and record what happened. It does not make an untrusted agent unable to act outside the interception boundary. Everything below follows from that sentence.

Supervised mode (v0.17) does not change it. It moves *who decides and who holds the record* outside the agent's reach, which is a real and measurable improvement to what the audit is worth — and it leaves the interception boundary exactly where it was. An agent's native file tools bypass a supervised gate precisely as they bypass a basic one.

### Where the line is, and what it costs

The distinction is **intent to evade**, not degree of misbehaviour.

Termaxa is built for an agent that is erring or misbehaving but still doing what it appears to be doing — running the command it says it is running, through the shell, in the open. An agent that is *trying* to get past the gate has execution paths the hook cannot see, and no amount of rule-writing closes them.

That boundary is not a hedge, and it has a measurable price. In August 2026, Tim Schipper ([@AraneaDev](https://github.com/AraneaDev)) ran an adversarial corpus against v0.14.1 with the starter policy: 22 commands, each destructive or gate-disabling, single command, fresh session. The result was **7 `allow`, 15 `ask`, 0 `deny`** — and since an auto-approving agent UI answers `ask` for you, all 22 reach execution.

Read that as a statement about the design rather than about the implementation. Policy matching is substring-based, so every one of those 22 is closable with a rule, and the next 22 spellings will need 22 more. A rule-per-spelling gate cannot provide a meaningful adversarial security boundary. It is not trying to. The problem is not that rules cannot close individual examples — they can, and those 22 are closable — it is that the mechanism is not a boundary against an agent deliberately looking for another execution path.

What that boundary looks like in practice, from a Claude Code auto-mode session
on 2026-08-11 (audit log, timestamps unedited):

```
19:12:26 ✗  rm -rf ./notes.txt && ls -la — segment 1/2 — Recursive force delete blocked
19:12:31 ?  rm ./notes.txt && ls -la     — segment 1/2 — no rule matched; default `ask`
19:14:42 ✓  post-execution receipt
```

The agent was told no, reasoned five seconds later that dropping `-rf` made the
command equivalent, and retried. It was not evading anything — it was being
helpful. The `deny` held, the workaround met an `ask` that forced a prompt even
under auto mode, the compound was split so `&& ls -la` did not mask the delete,
and a backup was taken before the prompt was answered. `termaxa rollback`
restored the file.

That is the erring-agent case the tool is built for, and it is also why `deny`
and insurance carry the weight rather than `ask`.

**The decision rule this gives us**, and the one we apply to every bypass report:

> Would a cooperative agent, making an ordinary mistake, hit this?

If yes, it is a bug and it gets fixed regardless of threat model — a careless agent hits `rm -r -f /` and `git push -f` exactly as readily as a hostile one. If it only fires under deliberate evasion — quoting a command name to dodge a rule, `bash -c` to hide a payload, a SQL comment inside a keyword — it is a documented limit, and this section is that documentation.

We state this because it would be very convenient to call every bypass "out of scope," and that is exactly when a framing deserves suspicion.

## Known limitations that affect safety

Some of these are **architectural boundaries** — they follow from Termaxa being an enforcement layer rather than an isolation layer, and no amount of implementation work removes them. Others are **implementation gaps** tracked for correction. They are listed together deliberately, because both affect what you should rely on today, and separating them would invite reading a known bug as "out of scope." Each entry says which it is.

*Implementation claims below are current as of v0.17. The threat model above is stable; this list is not.*

- **Shell parsing is heuristic.** Termaxa splits on `&&`, `||`, `;`, `|`, a lone `&` and newlines, and detects `$(...)`/backticks (escalating those to a human). It does not fully parse subshells `( )`, process substitution, or variable-expanded command names. Unparseable constructs are judged conservatively (the policy default, which ships as `ask`), but "conservative" is not "guaranteed."
- *(implementation, largely closed in v0.15/v0.16)* **The policy engine and the intent classifier once read a command differently.** The classifier strips quotes before tokenizing; policy matching normalized whitespace and case but matched a string that still contained them, so `"rm" -rf /` classified as a file-delete while missing the `rm -rf /*` deny rule. Since v0.15 policy matches against several readings including the tokenized form, so the quoted spelling is caught. The readings can only ADD matches, never remove one. What remains is that the two layers still have separate tokenizers, and a construct only one of them understands is judged by only one of them.
- **Allow rules are prefixes, not commands.** A rule like `ls*` matches any command *starting* with those characters — including `lsof` and `lsblk`. Rules that end in a wildcard immediately after the command name are broader than they look; prefer a trailing space (`ls *`).
- *(implementation, closed in v0.15/v0.16)* **Output redirection and copy destinations are modelled now.** Redirect targets are extracted by the same walk that splits segments, classified as destructive intent, previewed for what the file loses, and insured before execution ([#14](https://github.com/termaxa/termaxa/issues/14)). `cp`, `mv`, `tee` and `dd` are parsed by their own argument grammars, and each target carries the role the command gives it — a copy's SOURCE is read and its DESTINATION written, a move REMOVES its source ([#12](https://github.com/termaxa/termaxa/issues/12)). Rules can match resolved paths (`match_path:`), so `> .env` and `> ./.env` are one file rather than two strings.

  **What is not covered:** the machinery is only as wide as the extractors feeding it. `truncate`, `xcopy`, `robocopy`, and any other command that destroys a file by a route without a grammar produce no targets at all and reach their ordinary verdict. A path is only judged if something knows how to find it.
- **Termaxa does not defend its own configuration.** `.termaxa/` is an ordinary directory. A command matching a read-only allow rule can overwrite `policy.yaml` with a permissive one, or truncate the audit log (which is also the circuit breaker's memory). A *malformed* policy fails closed — `Policy::load` errors and the command is blocked — so the gap is the valid-but-permissive case. As of v0.15 the file-tool path is closed for these files: `termaxa init` registers a second `PreToolUse` matcher on the write tools (`Write|Edit|MultiEdit|NotebookEdit`) which reads the target path and denies a write landing in `.termaxa/` or an agent hook config. It reads nothing else and returns no decision for any other file, so it is not a general file-write gate. Three things it does not reach: a hook wired by hand from a pre-v0.15 snippet, which has the shell half only; a write tool whose name falls outside the vocabulary the matcher lists, since the matcher is the harness's filter and Termaxa cannot widen it after the fact; and Cursor, whose registration names the shell events specifically. `context_escalates` still runs regardless of policy, so a destructive *command* cannot reach silent `allow` even under a fully permissive policy — but it can reach `ask`.
- **The self-defence rules are a string filter, not a guard on a path.** The starter policy denies commands that *mention* `.termaxa/` or an agent hook config, so `echo 'default: allow' > .termaxa/policy.yaml` is blocked — but `git commit -am "tweak"` commits a modified policy without naming the file, and `git add .` is an `ask`. The read exceptions that keep the documented review workflow (`git diff`, `cat`, `cp` out of the directory) can also be redirected elsewhere, which is the unmodelled-redirection gap above rather than a property of these rules. What they stop is the explicit spelling; the careless one walks past. Note also that these rules cover the shell path only. File-writing tools are handled by the separate write-tool matcher described above, which compares a path rather than matching a string, so a rule added to this block does not extend to them and neither does a gap in it. `termaxa doctor` fingerprints the policy so a change that got past both is at least visible.
- **Previews are best-effort and read-only.** Postgres estimates come from planner statistics and can be stale; a `DELETE ... WHERE` is reported as filtered without computing the exact count. Terraform previews trust `terraform plan`. A preview never executes the analyzed statement.

  *This claim was false from v0.6.1 to v0.14.0.* The Postgres preview re-invoked `psql` with the user's own flags, and psql honours `-f` and `-c` in one invocation — so `psql -d db -f wipe.sql -c "DROP TABLE t"` made the preview execute `wipe.sql`, including on commands the policy then denied. Fixed in v0.14.1 by rebuilding the invocation from an allowlist of connection parameters. Reported by Tim Schipper.
- **The preview is generated before the decision is returned.** This is still true, but as of v0.14.2 a preview for a denied command runs *statically*: it parses the command and scans the filesystem, and spawns no subprocess. Before that, a denied `terraform destroy` still caused `terraform plan -destroy` to run in the working directory, initializing providers and evaluating `external` data sources; the psql case above was the first instance of the same structure. Denied commands therefore keep an informative reason (`DROP TABLE is blocked | DROP users`) without contacting the system they were blocked from. Previews for `git push`, which are entirely subprocess-derived, are simply absent on a deny.
- **Backups have boundaries.** `pg_dump`/`psql` and `git` must be on PATH. `rm` insurance resolves the command head, so `/bin/rm` and `/usr/bin/rm` are covered; shell aliases and variable-expanded command names are not. (This asymmetry is closed as of v0.16: the classifier, the delete extractor and the backup engine share one head resolution, so `sudo rm`, `/bin/rm`, `env rm` and the Windows path form are classified and insured alike. `xargs`-style indirection is still classified by its own rule rather than by head resolution.) Compound commands are insured for the first insurable segment only. Remote Terraform state is not backed up (its backend versions it). There is no backup retention/pruning yet.
- **Policy matching is case-insensitive by default.** This is usually what you want — `*rm -rf*` catches `rm -RF`, and `*drop table*` catches `DROP TABLE`. Where case carries meaning (`git branch -d/-D`, `git checkout -b/-B`), a rule can set `case_sensitive: true` and match the spelling it names; the starter policy opts in exactly once, for `git branch*-D*`. The cost of the default remains: a rule that does not opt in cannot distinguish the pair, and the action is chosen for the safer of the two.
- **Policy is only as good as you write it.** The starter policy is a sensible default, not a guarantee. Review it. `default: ask` fails closed, which is the safe direction, but an over-broad `allow` rule can still wave through something you'd rather catch. Note that ordering is load-bearing: matching is first-wins, so a broad allow prefix placed above a deny rule makes that deny unreachable. The starter policy puts hard stops first for this reason.
- **`ask` may or may not reach a human, depending on the harness.** This entry
  used to say flatly that `ask` degrades to `allow` under auto-approving UIs.
  Tested against Claude Code auto mode (the default since August 2026) that is
  **not** true: a hook's `ask` forces the prompt, because PreToolUse hooks are
  evaluated before the permission classifier, and `deny` blocks outright.
  Observed, not inferred — session log below.

  It remains true wherever the harness answers prompts without consulting a
  hook, and for any harness with no hook mechanism at all. Treat it as a
  property of your harness rather than a property of Termaxa, and check yours:
  a `deny` that holds and an `ask` that prompts are both easy to verify in five
  minutes. The starter policy still denies broad recursive deletes outright
  rather than asking, because that is the assumption that survives being wrong
  about the harness.
- **Fail-open on plumbing.** If the hook receives malformed input, Termaxa steps aside rather than breaking your session. This is deliberate (a gate that bricks sessions gets uninstalled) but means a sufficiently broken invocation is ungoverned.
- **The circuit breaker is per-session, and the session id can rotate.** The breaker counts repeated destructive intent within one agent session and escalates further variants to `deny`. If the harness rotates its session id mid-run (observed with both Claude Code and Cursor), the counter resets. It classifies command *intent* (file-delete, db-destroy, git-force, infra-destroy), including deletes hidden behind `find -exec`, `xargs`, and `unlink` — but it is a speed bump against retry-flailing, not a guaranteed cap, and it only sees commands that reach the shell hook. It also only escalates `ask` to `deny`: a command the policy already allows cannot be rescued by correct classification.
- **Hook dialects can drift.** Agents change their hook APIs between versions —
  observed live: Cursor 3.11 renamed its events (`preToolUse`/`postToolUse`) and
  Termaxa silently stopped gating it until v0.11.4, while every unit test stayed
  green (the fixtures used the old shape). When a dialect drifts, the gate fails
  *open and silent*, not loud. Mitigations: regression tests now use real
  captured payloads per agent version, and `TERMAXA_HOOK_DEBUG` records exactly
  what an agent sends so drift is diagnosable in minutes. If you upgrade your
  agent and Termaxa goes quiet (`termaxa log` shows no new hook entries), suspect
  dialect drift and file an issue with a debug capture.

## Design choices that support safety

- **Fail closed on policy** (unmatched → `ask`), fail open on plumbing (broken hook input → step aside).
- **One-way escalation:** context signals and the circuit breaker can only raise a verdict (allow→ask, ask→deny), never lower one. Heuristics can't weaken an explicit rule. This holds even against a permissive policy file: a destructive command cannot reach silent `allow`.
- **Backups precede execution** on both `run` and `hook`, and never fire on `deny` (nothing runs).
- **One parser per grammar.** The policy engine and the intent classifier share `shell::split_segments`; the classifier, the delete extractor and the backup engine share `delete::resolve_head`; segments carry the redirect targets found in the same walk that split them. Two engines reading the same command differently has produced several separate bugs, and the fix each time was to delete the duplicate rather than align it — most recently in v0.16, where comparing two scanners before removing one surfaced a policy bypass that had been live since v0.7.0.
- **State outside the repo:** logs and backups live in `~/.termaxa/`, so a `git reset --hard` — or an agent deleting the project folder — can't destroy your audit trail. (This is fixed as of v0.8 — earlier versions kept state in-repo.)
- **Append-only audit:** every attempt, including blocked ones, is recorded and never overwritten.
- **Hash-chained audit (v0.16):** each entry carries the hash of the entry before it, so an edited or removed entry is detectable. Read the next section before treating this as a security boundary.

## What the audit chain does and does not prove

Since v0.16 each audit entry carries the hash of the one before it. `termaxa doctor` reports what it can verify:

```
✓ chain valid: entries 3-5
! 2 earlier entries are pre-chain
✗ audit chain broken at entry 4
```

**In basic mode — the default, and every Windows install — the chain is tamper-EVIDENT, not tamper-RESISTANT.**

The hook runs as the agent's own user, which means the audit log is written with the agent's own filesystem authority. Anything that can edit an entry can recompute the chain over it. The chain can expose accidental corruption, partial writes, and unsophisticated edits — what it catches depends on what changed and what remains readable. It does not stop, and cannot detect, a process in the agent's trust domain that rewrites the record deliberately and recomputes the hashes.

**Supervised mode (Unix, v0.17) changes this, and the reason is privilege rather than cryptography.** The supervisor owns the state directory, the agent's user has no access to it, and the audit log is written by an authority outside the agent's reach. The record becomes trustworthy because of who holds the pen — not because the hash got cleverer. A boundary rig with a second real account asserts each half of that: the agent cannot read, append to, or delete the log, and cannot list the directory holding it.

Stated plainly, so a changelog line reading "hash-chained audit log" is not mistaken for more than it is:

| mode | who writes the log | what the chain proves |
|---|---|---|
| basic (default, all platforms) | the agent's own user | corruption and casual edits are visible |
| supervised (Unix, v0.17) | the supervisor, outside the agent's reach | the record is one the agent cannot rewrite |

## Four grades, and what each one leaves open

Supervised mode (v0.17) is not a switch from "unsafe" to "safe". It is one of four topologies, each with a different authority story and a different residue. No grade claims containment, and the bottom row's honest limits are in the same table that sells it.

| grade | routing | authority | what the agent's domain can still do |
|---|---|---|---|
| **hook** (basic, default, all platforms) | the harness invokes the hook | the agent's own user | edit the policy and hook configs (advised against by the self-defence rules and the write matcher), delete the record, bypass via any non-hooked execution path |
| **hook + modes** (Unix, no daemon) | same | the agent's user, but policy and configs operator-owned | delete or edit the record and the backups; bypass via non-hooked paths |
| **wrapped** (`termaxa wrap -- <agent>`) | every command run *through a shell* reaches the gate, hooked or not | the agent's user | tamper with the record; escape via tools that execute without spawning through the wrapper — an absolute `/bin/sh`, or a direct `execve` |
| **supervised** (wrap + daemon + modes) | wrapped | **the operator's user** | attempt commands, each of which is denied and recorded; social-engineer the human; anything root-adjacent the OS itself permits |

Two things worth reading off that table rather than around it.

**Every grade is bypassable by an agent that is trying.** The top three are bypassable by an agent that is merely resourceful. The fourth narrows the agent's domain to "ask and be refused", but an agent that can talk to a human can still ask the human, and an OS misconfiguration is still an OS misconfiguration.

**The improvement between rows three and four is privilege, not cleverness.** Wrapped mode routes more commands through the same code; supervised mode moves *who runs that code*. That is the only step in the table that changes what the record is worth, which is why the audit chain section above draws its line exactly there.

Setup, the credential tradeoff, and what supervised mode has and has not been proved against: [docs/supervisor.md](docs/supervisor.md).

**What it has been proved against, and what that cost.** The boundary is asserted by an automated rig that creates a second real account and has it try — 23 assertions, each with a control leg proving the operator *can* do the thing, so a refusal means "blocked" rather than "impossible for everyone". It has also been run once with a real agent, and the [field report](docs/field-reports/2026-08-17-supervised-routing.md) is published including what broke: the first session found that agent commands never reached the supervisor at all, because a hook running as the agent resolved the socket path from *its own* `$HOME`. The walls held; the door led nowhere. 439 unit tests, 18 boundary assertions and three green CI platforms were all consistent with a working system, because every one of them ran the hook and the supervisor as the same user.

That is the honest state of this row: proved by a rig, proved once by a real session, and the one real session found a bug the rig could not see.

**Migration.** Entries written before v0.16 have no hash. They stay readable and are reported as pre-chain rather than as breaks: Termaxa can prove continuity from the boundary onward, and does not retroactively claim to have protected history it was not there for. A broken link names the entry and leaves the rest of the record readable, because one corrupt line making the whole log unreadable would destroy more evidence than the corruption did.

## Reporting a vulnerability

If you find a way to bypass a policy that *should* hold (e.g. a compound-command or quoting trick that sneaks a destructive command past a matching `deny` rule), please report it.

- Use [private vulnerability reporting](https://github.com/termaxa/termaxa/security/advisories/new) for anything sensitive — it opens a private thread with the maintainers, or
- Email **security@termaxa.com**, or
- Open a GitHub issue for non-sensitive reports.

Before reporting, please check the decision rule above: a bypass that only fires under deliberate evasion is a documented limit rather than a bug. Report it anyway if it surprises you — the boundary itself is worth arguing about, and the limitations list above exists because people did.

Bypass reports are the most valuable contribution you can make. The compound-command splitting in v0.7 exists because the first live agent found exactly such a bypass within minutes — that finding is now a named regression test. The v0.11.1 intent classifier for `find -exec`/`xargs` deletes exists for the same reason: a live Cursor agent found the gap. The v0.11.4 Cursor 3.11 fix exists because a live payload capture showed the gate had gone silent. And the whole of v0.14.1, plus most of the limitations listed above, exists because Tim Schipper read the source and then attacked it. We'd rather have yours the same way.
