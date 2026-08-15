# Changelog

All notable changes to Termaxa. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0, so minor versions may include breaking changes to the policy schema or CLI.

## Unreleased

### Changed

- **Path resolution takes an explicit cwd.** A hook runs in whatever directory
  the harness spawned it in, which is not the directory the agent's command
  runs in, so a relative target resolved against the process cwd found nothing
  and took no backup — silently, because "no such file" and "nothing to
  insure" are the same answer (#15). `resolve_path_in(raw, cwd)` replaces
  `resolve_path`; the hook passes the payload cwd, and the ambient fallback is
  deleted rather than deprecated — with every call site threaded, the compiler
  reported the old form as dead code, which is the proof nothing resolves
  ambiently any more.

- **One scanner for one grammar.** Segments and their redirect targets now
  come from the same walk: `split_segments` returns `Segment` values carrying
  the `Overwrite`s found in them, and `shell::redirect_targets` is deleted.
  Two parsers over the same input had already produced three bugs and, once
  their outputs were compared, two measurable disagreements: `>|` was split at
  its `|`, so the clobber was invisible to intent and policy (which split
  first) while backup, re-scanning the raw string, insured it; and the walks
  read `\"` differently outside quotes. `backup` now consumes per-segment
  redirects instead of re-scanning the raw command.

  Stated behavior change: **escapes outside single quotes are literal**, as a
  shell reads them. `echo \" ; rm -rf x` is now two segments — previously the
  escaped quote opened a quote, the `;` never split, and the whole line
  (including the `rm` the shell runs as its own command) could match a single
  permissive rule. Escaped separators (`\;`, `\&`) no longer split, because
  the shell runs one command there, and an escaped space in a redirect target
  keeps the filename whole. Each change is pinned by a labeled test with a
  control leg.

## v0.15.0 — stop treating commands as strings

### Changed

- **Stop treating commands as strings.** Four of the five changes in this
  release are the same bug: matching text where we mean to match a thing.
  Policy rules now evaluate every command in three readings — as written,
  tokenized (quotes gone), and tokenized case-preserved — and the most severe
  verdict governs, so `"rm" -rf /` and `rm -r''f /` can no longer slip a deny
  by quoting. Case sensitivity is an explicit `case_sensitive: true` rule
  field, never inferred from spelling; the starter policy opts in exactly
  once, on `git branch*-D*`, which can finally mean `-D`. Reported by
  **Tim Schipper**.

  Stated behavior change: a quoted spelling of an excepted command
  (`"cat" .termaxa/policy.yaml`) now fails closed where the plain spelling
  still allows — the same call the v0.14.2 self-defence rules made for
  unlisted reads.

- **Destruction by overwrite, the redirect half.** `>` truncates, and until
  now the operator was lexed and discarded: `cat /dev/null > .env` matched
  the read-only `cat *` rule and was allowed. Truncating redirects are now
  extracted (sinks like `/dev/null` excluded), classified `file-overwrite`,
  insured by copying the target aside before execution, and denied outright
  for paths whose loss is not recoverable from the repo (`.env`, `/etc/`,
  SSH keys). The overwrite denies sit above the `.termaxa` read exceptions,
  which would otherwise launder them. The breaker counts an overwrite only
  when a rule objected, so redirected build logs never accumulate toward a
  trip. **#12 stays open**: `cp`/`mv`/`tee`/`dd` destinations are not
  covered, so the incident that opened it is not closed by this release.

- **`doctor` proves the hook fires instead of grepping for its name.** The
  old check was a substring search over settings.json; a hook whose path was
  mangled at exec failed non-blocking and doctor said "configured" in green
  through two ungated sessions (observed on Windows, 2026-08-13). `doctor`
  now invokes the registered command through the shell with a synthetic
  must-deny payload and a two-second timeout, and reports configured-and-live,
  registered-but-not-firing, or absent. The probe runs only binaries named
  termaxa (settings files arrive in cloned repos), writes no state — proven
  against the real binary, with a control — and a live hook that does not
  deny the probe is flagged rather than failed. Live means "answered when
  doctor invoked it"; pair it with the log-recency check for the
  harness-side failures the probe cannot see.

- **Decline rather than allow.** Where the policy merely fails to object —
  the default path, not an explicit `allow` rule — the hook now emits no
  decision instead of asserting an approval it never formed. Gated to the
  dialects whose contract documents that silence means no opinion (Claude
  Code, Codex); Cursor and Copilot keep receiving explicit answers until a
  live capture says otherwise. Suggested by **Tim Schipper**.

- **The recoverability invariant.** A destructive rule may be `ask` only if
  something can undo it; `ask` under an auto-approving UI is `allow`. Every
  `ask` in the starter policy now carries a documented recovery path,
  enforced by a test, and the three that had none — `docker system prune`,
  `dd` onto a raw device, `mkfs` — are denies.

### Added

- **A write-tool matcher, so a shell deny cannot be routed around one tool over.**
  Contributed by **Tim Schipper** ([@AraneaDev](https://github.com/AraneaDev)),
  closing the half of his finding 1 that v0.14.2 left open.

  The self-defence rules added in v0.14.2 are shell rules, and an agent's
  file-writing tool produces no command for them to match. So an agent that hit
  the `rm -rf` deny on `.termaxa/policy.yaml` could reach for `Write` and get
  there anyway, without evading anything: routing around an obstacle is the most
  ordinary thing an agent does. By the decision rule in `SECURITY.md` that makes
  it a bug rather than a documented limit.

  `termaxa init` now registers a second `PreToolUse` entry with the matcher
  `Write|Edit|MultiEdit|NotebookEdit`. It reads the target path and nothing
  else, and denies a write that lands in `.termaxa/` or an agent hook config.

  Two properties worth stating, because both were deliberate:

  - **It does not gate file writes.** A path it does not recognise gets no
    decision at all, not an `allow`. Asserting `allow` on every file an agent
    writes would be Termaxa answering a question it has no way to form an
    opinion about, and at the harness boundary an `allow` is an answer rather
    than a shrug.
  - **The decision does not consult the policy.** It holds in a project with no
    `.termaxa/` and one whose policy will not parse, which are exactly the
    states where the shell path has nothing to say.

  Running `termaxa init --claude-code` again adds the new entry next to the
  existing `Bash` one; the idempotence check is keyed on the matcher, so an
  install that predates this release is upgraded rather than read as complete.

## v0.14.2 — the preview no longer runs anything on a denied command

Second review round from **Tim Schipper** ([@AraneaDev](https://github.com/AraneaDev)), who this time stopped reviewing and started attacking: 22 commands against the v0.14.1 starter policy, each destructive or gate-disabling. His first PR to this repo is in this release.

### Fixed

- **A denied command could still cause a subprocess.** (GHSA-m854-p747-v3gw; see also GHSA-gxg4-5fmj-534m, which was the first instance of this same structure.) `hook::run` generates the preview before returning the
  decision, so a DENIED `terraform destroy` still ran `terraform plan -destroy`
  in the agent's working directory.

  `terraform plan` re-evaluates `data` sources against existing state, and the
  `external` data source executes an arbitrary program named in the user's
  configuration. Confirmed end-to-end against Terraform 1.9.8: a command
  Termaxa denied executed the program, and no longer does.

  v0.14.1 fixed what the Postgres preview did with the arguments it was handed.
  That was the instance; this is the class.

  The fix is not to skip the preview on deny. The denial message is more useful
  with it, and the delete preview never spawned anything in the first place.
  "May this execute?" is now an argument to `preview::generate`, decided by the
  caller that already knows the verdict. A denied `DROP TABLE` still reports
  `| DROP users` — it just no longer connects to the database it was blocked
  from. `git push` previews, being entirely subprocess-derived, are absent on a
  deny.

- **The gate now defends its own configuration** (#16, by Tim Schipper). The
  starter policy had no rule about `.termaxa/` or the agent hook configs, so
  `echo 'default: allow' > .termaxa/policy.yaml` matched `echo *` and was
  allowed — one line replacing the policy with a permissive one. A cleanup
  script hits this without any intent to evade. Adds a self-defence block, with
  read-only exceptions narrow enough to keep the documented "policy is in-repo,
  reviewable in PRs" workflow: `git diff`/`add`/`log`/`show`, `cat`, and `cp`
  anchored so the copy only goes *out* of the directory.

- **Policy fingerprinting** (#16). `termaxa init` records a SHA-256 of the
  policy; `termaxa doctor` reports it and says whether it changed. What cannot
  be blocked can at least be noticed — an agent's file-writing tools never
  reach the hook, which registers with a `Bash` matcher. The baseline lives in
  the state dir, not in `.termaxa/`, because a baseline inside the directory it
  protects is erased by the same clobber it exists to catch.

- **`ls*` and `grep*` were prefixes, not commands** (#16). `ls*` also matched
  `lsof`, `lsblk` and `lsattr`; `grep*` matched `grepdiff`. Now `ls`, `ls *`
  and `grep *`, matching what `cat *` and `echo *` already did.

- **`rm --no-preserve-root -rf /`** (#16). The `rm -rf /*` rule is named for the
  command everyone quotes, but GNU `rm` refuses that one — `--no-preserve-root`
  is the spelling it obeys, and it does not contain the substring `rm -rf`.

- **`git push origin +main`** (#16). A leading `+` on a refspec is a force push
  and has no other meaning. The classifier now counts it, so the breaker sees
  it.

- **A latent race in the `paths` tests** (#17, by Tim Schipper). `TERMAXA_HOME`
  and the process cwd are per-process while cargo runs tests as threads in one
  process; three tests mutated them and deleted the trees they pointed at. It
  surfaced as a macOS-only CI failure after #16 changed the scheduling, and had
  been latent since those tests were written. The quieter half: the tests had
  been resolving into the developer's real `~/.termaxa` on every green run.

- **Test isolation is now a helper rather than a discipline** (#18, by Tim
  Schipper). `TestEnv` takes the lock, points `TERMAXA_HOME` at a tree it alone
  owns, and on drop restores the cwd and the variable, removes the tree, and
  **fails the test if state landed anywhere else**. That last check is the
  point: `resolve_from_uses_explicit_dir_not_process_cwd` asserts nothing about
  home and would have passed while polluting — the guard catches it alone.
  Verified by breaking both claims rather than reading them.

### Documentation

- SECURITY.md gains the self-defence limitation, stated plainly: these rules are
  a string filter over the command line, not a guard on a path. `git commit -am`
  commits a modified policy without naming the file.

### Not fixed, deliberately

Matching on the tokenized form (which would also recover case-sensitivity for
`-D` vs `-d`), and carrying the redirect target out of `split_segments`. Both
retire classes rather than instances and are the v0.15 work; the second is #14,
with #12 as the other half of the same category. Wiring the intent classifier
into the allow→ask ladder is a behaviour change across every policy and is
filed with them.

## v0.14.1 — security patch: the preview could execute the command

An unsolicited end-to-end code review by **Tim Schipper** ([@AraneaDev](https://github.com/AraneaDev)) — who compiled Termaxa's own functions into a standalone harness rather than arguing from a reading — found ten issues in v0.14.0. This release fixes the ones that fail in the quiet direction. **Anyone using the Postgres preview against a real database should upgrade.**

### Fixed

- **The Postgres preview executed the user's SQL file.** (CVE-class: unintended
  code execution in a safety tool.) `pg::introspect` copied the user's argv and
  stripped only `-c`. psql honours `-f` and `-c` in the same invocation, so
  `psql -d shop -f wipe.sql -c "DROP TABLE users"` made the *preview* run
  `wipe.sql`. `hook::run` generates the preview before returning a decision, so
  this happened on commands Termaxa then **denied** — the gate performed the
  damage it had just blocked. Confirmed end-to-end against a live database.

  The fix is not "also strip `-f`": a denylist loses. `-o` truncates an
  arbitrary file, `-L` writes one, `-W` blocks on a password prompt, and the
  attached form `-cSQL` slipped past an equality check on `-c` and re-executed
  the destructive statement itself. The invocation is now **rebuilt from an
  allowlist** of connection parameters (`-h/-p/-U/-d` plus a positional
  dbname), so nothing unrecognised can reach the child process. `-w` is forced
  so a preview can never hang on a prompt, and the catalog query runs under
  `default_transaction_read_only`.

- **A harmless psql flag silently voided insurance.** The same argv was passed
  to `pg_dump`, whose flag namespace disagrees with psql's: psql's `-t`
  (tuples-only) is pg_dump's `--table`, and `-X`, `-A`, `-1` are not pg_dump
  options at all. pg_dump exited non-zero, `backup::take` returned `Err`, and
  `hook` ignores `Err` — so `psql -X -d shop -c "TRUNCATE users"` got **no
  backup** while the identical command without `-X` got one. Same shape as the
  v0.14.0 bug where path *syntax* decided whether a backup existed. The restore
  path had the same passthrough, and indexed `conn[0]` on a possibly-empty
  array; it now derives its connection from the original command through the
  same allowlist, which also makes pre-0.14.1 backup records safe to restore.

- **The trench-coat bypass reopened on a single `&`.** `shell::split_segments`
  treated `&&` as a separator but not a lone `&`, so `git status & rm -rf /`
  stayed one segment, matched the starter policy's `git status*` rule, and was
  **allowed**. The original reasoning — that `2>&1` is more common than
  backgrounding — was true but answered the wrong question: an allow rule only
  has to be wrong once. Redirection forms (`2>&1`, `>&2`, `<&-`, `&>log`) are
  now excluded by shape instead.

- **One splitter, not two.** `intent.rs` carried its own copy that split on a
  lone `&` but not on newlines, while `shell.rs` did the reverse. So
  `git status & rm -rf /` was classified correctly and allowed anyway, and
  `"git status\nrm -rf /"` was denied by policy but invisible to the circuit
  breaker's counter. `intent` now calls `shell::split_segments`. Two parsers
  for one grammar is the failure `delete::command_head` was introduced to end.

- **`delete::short()` panicked on non-ASCII paths.** `&p[p.len() - 39..]`
  byte-sliced a filesystem path, so the cut could land inside a multi-byte
  codepoint — 22 of 207 realistic Cyrillic, CJK and Latin-1 paths in
  Schipper's sweep. It is reachable from `preview_for` → `preview::generate` →
  `hook::run`, so it fired *inside the gate*, on exactly the non-ASCII Windows
  profile the module was written for. A panicking hook is an ungated agent.

- **Starter policy ordering.** Read-only allows sat above the destructive
  denies, and matching is first-wins, so `git branch -D main` matched
  `git branch*` → **allow**, and `echo $(rm -rf /)` matched `echo *` before
  `*rm -rf*` could see it. Hard stops now come first; put your own exceptions
  above the deny you want them to override. `git branch -d/-D` is now an
  explicit `ask` (matching is case-insensitive, so a rule cannot separate the
  two — the action is chosen for the safer one).

- **`examples/policy.yaml` was materially weaker than what `init` writes** —
  28 rules against 44, missing every broad delete deny and the whole
  `circuit_breaker` block, with nothing to signal it was thinner. It is now
  generated from `STARTER_POLICY`, and a test fails the build if they drift.

### Documentation

Four claims that were false, all under headings asserting the opposite:

- `SECURITY.md` said "a preview never executes the analyzed statement." From
  v0.6.1 to v0.14.0 it could. The correction now sits in the file, dated.
- `SECURITY.md` said `/bin/rm` is not insured. Since v0.14.0 it is — the
  *classifier* is what misses it. The two engines' actual boundary is now
  stated.
- The README report sample's risk line read `Medium (... = 9)` while its own
  counts give 13, which is the High band — under a heading claiming every line
  is a fact with a source.
- The README's "Top projects" cannot be produced: state is per-project and
  `report::run` reads one state dir, so those are subdirectories of a single
  project. Renamed to "Top directories" in the output and the sample.
- README line count corrected (~5,500 → ~7,200).

### Upgrade note — existing projects keep the old policy

`termaxa init` writes `.termaxa/policy.yaml` once and never rewrites it, so
**upgrading the binary does not reorder an existing project's policy.** The
starter-policy fix above reaches new projects only. To pick it up in a project
you already have, diff your policy against the new starter and move the
destructive denies above the read-only allows:

```
termaxa init            # in an empty directory, to see the new ordering
```

Then reorder your own file, or delete `.termaxa/policy.yaml` and re-run `init`
if you have not customised it. Check the result with:

```
termaxa check "git branch -D main"      # expect ask, not allow
termaxa check "echo \$(rm -rf /)"        # expect deny, not allow
```

The code fixes (psql, `&`, `short()`) need no action — they ship with the
binary.

### Still open from the same review

Filed rather than fixed, because they need design rather than a patch: the
process-cwd leak into every engine except policy resolution (#15), output
redirection modelled nowhere so `cat /dev/null > .env` is still allowed (#14),
compound commands insuring only the first segment, `notify` posting command
text unredacted, and intent classification keyed on the raw first token.

## v0.14.0 — what a delete actually costs

Every other preview engine answers "what will this destroy?" with a real
number — commits lost, rows affected, resources destroyed. Deletes were the
gap: the most common destructive command produced no preview at all. This
release closes it, and in doing so uncovered two insurance bugs that had been
live for three versions.

### Added
- **Delete blast radius.** `rm`, `Remove-Item`, `del`, `rmdir`, `rd` and
  `unlink` now produce an impact preview before the decision:
  - the **resolved** target, including Git Bash (`/c/...`), WSL
    (`/mnt/c/...`), `~` and relative forms
  - whether it falls **outside the project root**, resolves to a **user
    profile**, or is a **filesystem root**
  - **sensitive children** one level deep — `.ssh`, `.aws`, `.gnupg`, `.env`,
    `.kube`, `id_rsa`, `.npmrc` and similar
  - a **recursive file count**, budgeted at 5,000 files or 300ms, whichever
    comes first. A capped count says it was capped: "5,000+" is never
    reported as "5,000".
  - whether the operation is **insurable**, and if not, which of the two
    reasons applies

  The preview flows into the agent's own confirmation prompt, so the person
  approving sees the consequence rather than just the command string.

### Fixed
- **Path syntax decided whether a backup existed.**
  `rm -rf C:\Users\x\Desktop` was fully insured;
  `rm -rf /c/Users/x/Desktop` — the identical target — silently got no
  backup at all, because the backup planner built paths from the raw token
  and the Git Bash form failed an existence check on Windows. Agents on
  Windows emit that form routinely, so this was the case where insurance
  mattered most and quietly wasn't there.
- **PowerShell and cmd deletes were never insured.** The backup planner
  matched only `rm`, so `Remove-Item`, `del`, `rmdir` and `rd` ran without a
  backup even though the classifier and policy had gated them since v0.11.
- The delete preview and the backup planner now share one implementation of
  target extraction, path resolution and flag parsing, so the two engines
  cannot disagree about what a command targets.

### Notes
- Insurance messages now name which fact is true — "too large to copy
  (5,000+ files)" versus "no backup covers this command". They are different
  situations and the ambiguous phrasing was hiding the bug above.
- Flag syntax is resolved per shell rather than by string shape: `/s` is a
  cmd switch and `/c` is a drive root, and a shape-based guess drops
  `rm -rf /c` — a whole-drive delete.
- **What this does NOT do:** it cannot know what you *meant*. Nothing here
  would have detected that a path contained a typo. It reports what the path
  contains; the gap between intent and contents is the thing being made
  visible.
  
## v0.13.0 — the first sixty seconds

Activation release: what a developer sees between `cargo install` and their
first intercepted command.

### Added
- **Welcome screen.** Bare `termaxa` now prints five lines and one runnable
  command instead of clap's help wall. The challenge (`termaxa check "rm -rf /"`)
  works with zero setup.
- **`termaxa doctor`.** Is the gate actually wired up? Reports binary, policy,
  which agents are detected and whether their hooks are configured, which
  preview tools are on PATH, and state — ending with a numbered fix list.
  Reports "configured", never "will fire": if an agent is wired but no hook
  entries exist, it says so and points at `TERMAXA_HOOK_DEBUG`, which is the
  diagnostic that would have caught the Cursor 3.11 silent-ungating in minutes.
  Read-only by construction (see below).
- **Colour across `check`, `report`, `log`, `stats`, and `backups`** —
  dependency-free ANSI behind a gate that respects `NO_COLOR`,
  `TERMAXA_NO_COLOR`, `CLICOLOR_FORCE`, and real TTY detection on Unix
  *and* Windows.

### Fixed
- `termaxa log` rendered post-execution receipts with the ✗ (denied) mark —
  the same bug fixed in `report` in v0.12, now sharing one implementation so
  every surface agrees.
- Column alignment when labels are colourised (padding counted escape bytes,
  producing `commandrm -rf /`). Found by live testing; pinned by a test that
  strips ANSI before asserting.
- Windows TTY detection: redirected output no longer contains escape
  sequences.

### Changed
- `paths::resolve_readonly` — a diagnostic must observe, never mutate.
  `termaxa doctor` no longer creates the state directories it reports on, and
  cannot trigger legacy migration.

### Notes
- No new dependencies. Colour is raw ANSI; Windows TTY detection is two FFI
  declarations rather than a crate.
- On Windows PowerShell 5.1, `>` redirection writes UTF-16 and mangles
  Unicode glyphs. That's the shell, not Termaxa — use PowerShell 7, or
  `termaxa report --md | Out-File -Encoding utf8 report.md`.

## v0.12.0 — the flight recorder

`termaxa report` becomes the answer to "what actually happened while my agent
was working?" — one command, no flags needed.

### Added
- **Destructive-intent breakdown.** Commands the classifier recognised,
  grouped by intent (file-delete, db-destroy, git-destructive, infra-destroy),
  with circuit-breaker trips shown as a separate line. Classified ≠ blocked,
  and the report now says so.
- **Insight.** When the breaker blocks the same intent repeatedly (≥3 in
  scope), the report names the usual causes — generated files, build
  directories, an agent retry loop — and suggests an explicit allow rule if
  the work is intentional. Diagnostic, not scolding: policy relaxation stays
  deliberate. Suggested by a reader in #4.
- **Recent events.** The last six decisions with their marks, so the report
  reads as a narrative rather than a stat block.
- **Last N days rollup.** Sessions, commands, decisions, backups, breaker
  trips, and top projects by working directory. `--days N` to change the
  window (default 30).
- Previews, backups, and rollbacks surfaced as first-class counts.

### Fixed
- Post-execution receipts rendered with the ✗ (denied) mark. An executed,
  insured command is a success; it now shows ✓.

### Notes
- Everything here is derived from the existing append-only audit log. No new
  state, no schema change, no telemetry — the report reads what Termaxa
  already wrote locally.
- Token/cost accounting is deliberately **not** included: that requires the
  agent's own transcripts, and estimating it would put an invented number in
  an audit tool. Tracked separately.

## [0.11.4] — Cursor 3.11 hook compatibility + post-execution receipts
- **Fix (important): restore gating for Cursor 3.11+.** Cursor renamed its hook
  API (`preToolUse`/`postToolUse`, `tool_name:"Shell"`); Termaxa only knew the
  older `beforeShellExecution`/`afterShellExecution` shape, so on current Cursor
  it silently stopped intercepting commands. Now handles both. Verified live on
  Cursor 3.11.25. Old Cursor, Claude Code, Codex, Copilot unchanged.
- **Post-execution receipts.** Records a receipt when a command finishes (Claude
  Code `PostToolUse` and Cursor `postToolUse`, both verified live on Windows).
  The circuit breaker excludes human-approved commands from the retry threshold,
  so approving a legitimate command no longer nudges the agent toward an auto-deny.
  `termaxa init` now registers both pre- and post-execution hooks.
  
## [0.11.3] — Report surfaces breaker trips
- `termaxa report` now shows a `breaker` line counting circuit-breaker trips
  in scope, so auto-denied retry-storms are visible in the session summary.

## [0.11.2] — Zero-setup `check`
- `termaxa check` now works with no project setup: when no `.termaxa/policy.yaml`
  exists it evaluates against the built-in starter policy (read-only "demo mode"),
  so `cargo install termaxa && termaxa check "rm -rf /"` works immediately.
  `run` and `hook` still require an explicit project policy — enforcement stays
  deliberate.

## [0.11.1] — Classifier: delete indirection
- The intent classifier now recognizes deletes hidden behind command
  indirection: `find -exec/-execdir <rm>`, `find -delete`, `xargs rm`,
  `unlink`, and `shred -u`. Closes a bypass found in live agent testing
  where `find . -exec rm -rf {} +` slipped past the circuit breaker.

## [0.11.0] — Session circuit breaker
- When the same destructive intent (file delete, DB destroy, git force-op,
  infra destroy) is asked or denied twice in one agent session, further
  variants are automatically DENIED — closing the retry-with-different-syntax
  gap found in live Cursor testing. Configurable via `circuit_breaker:` in
  policy.yaml (enabled by default, threshold 2).
- Starter policy now DENIES bulk deletes by default (Unix, PowerShell, cmd
  forms): with auto-approving agent UIs, `ask` silently degrades to `allow`.
- Audit entries carry an `intent` classification (backward compatible;
  old log lines parse unchanged).

## v0.10.5 — 2026-07-09
- Formatting cleanup (`cargo fmt`); no functional changes from v0.10.4.

## v0.10.4 — 2026-07-08
- Fixed audit-path hash mismatch that caused empty audit logs.
- Documented honest enforcement limits; removed internal build notes.
- Multi-agent hook support (Cursor, Codex, Copilot dialects) and
  `termaxa init` flags landed in this series.
- Note: version numbers v0.10.0–v0.10.3 were internal iteration
  numbers and were never published; v0.10.4 is the first release
  of the 0.10 series.
  
## [0.9.0] — Launch

### Added
- **Terraform/OpenTofu previews.** `terraform apply|destroy` (and `tofu`) run `terraform plan` first and surface `+add ~change -destroy` counts, leading with destroyed resources. Local `terraform.tfstate` is backed up before apply.
- **Execution Report** (`termaxa report`) — session summary composed from the audit trail: commands by decision, blocked list, database/infra impact (from persisted preview summaries), backups with rollback availability, and a transparent risk score (`deny×3 + escalation×2 + ask×1`). `--session`, `--all`, `--md`.
- Preview summaries now persist on audit entries, so reports state impact as recorded fact.
- `termaxa paths` — show where policy (in-repo) and state (`~/.termaxa`) live.

### Fixed
- **Broken-pipe panic**: `termaxa report --md | head` (and any piped output) now exits cleanly on Unix instead of panicking.
- `--help` leads with a clear description and worked examples.

## [0.8.0] — Home-directory state
- Logs and backups moved from in-repo `.termaxa/` to `~/.termaxa/projects/<name>-<hash>/`, so a `git reset --hard` can no longer destroy the audit trail. Automatic one-time migration of legacy in-repo state, including path-rewriting inside the backup manifest. Policy stays in-repo as reviewable policy-as-code.

## [0.7.0] — Shell-aware evaluation
- Compound commands (`&&`, `||`, `;`, `|`) are split and judged per segment; the most dangerous segment governs. Closes a bypass where `git status && <anything>` rode a `git status*` allow rule (found by the first live Claude Code session; now a named regression test). `$(...)`/backtick command substitution escalates to a human.

## [0.6.1] — Loss-aware force-push previews
- Force pushes now show what the remote will **lose** (`HEAD..@{u}`), not just what it gains. Found in live use: the preview previously said "nothing to push" while a force push destroyed a commit.

## [0.6.0] — Insurance engine
- Automatic backups before destructive operations: git remote-ref pinning, mode-aware `pg_dump` (CASCADE pulls in FK dependents), file copies for `rm`. `termaxa backups` / `termaxa rollback <id>`.

## [0.5.0] — Operability
- Session tracking from hook events; `termaxa log` filters (`--decision`, `--source`, `--json`); `termaxa stats`; `termaxa notify --test`.

## [0.4.0] — Notifications
- Slack-compatible webhook on deny/ask, fire-and-forget (never blocks a decision). Log entries show approval + exit code.

## [0.3.0] — Postgres impact analysis
- Static (`NO WHERE CLAUSE` detection) and live (row estimates from `pg_class.reltuples`, FK dependents) analysis for `DROP`/`TRUNCATE`/`DELETE`, reusing the intercepted command's own connection.

## [0.2.0] — Git previews
- `git push` previews: commits and diffstat, with new-branch handling.

## [0.1.0] — Core
- Policy engine (YAML, first-match-wins, wildcard, normalized matching), Claude Code PreToolUse hook, context signals with one-way escalation, append-only JSONL audit, `init`/`check`/`run`/`log`.
