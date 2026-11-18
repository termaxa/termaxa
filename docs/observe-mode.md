# Observe mode

`mode: observe` in `.termaxa/policy.yaml` (or `TERMAXA_MODE=observe` on one
machine) makes the gate record what enforcement would have done without
interrupting execution, except for a floor it cannot lower. The default is
`enforce`. Observe mode applies in the hook and in `termaxa run`.

## What runs

Outside the floor, every command runs:

- An **allow** is recorded as in enforce mode and, since v0.21.10, not
  answered: the harness decides as it would alone. Until then the hook said
  `allow` wherever a rule allowed the command; Claude Code and Copilot CLI
  take a hook's `allow` as the approval, so switching the mode on skipped
  prompts they would have shown. A run that leaned on that answer, an
  unattended session that must prompt for nothing, gets its approvals from
  the harness's own settings, or from enforce mode, where an allow is an
  allow.
- An **ask** or **deny** runs after its insurance is taken (the same copy,
  pin or dump enforce mode takes before an allowed destructive command),
  and is recorded as the verdict enforcement would have given. The record
  line carries `mode: observe`, `enforced: false`, and a `coverage`:
  - `insured`: a copy was taken first;
  - `known-uninsured`: the gate understood the command and nothing could
    be copied (a remote ref it cannot pin, a database it has no dump for);
  - `unknown`: the gate could not read what the command changes (a script
    file, inline code, an unresolvable substitution).

A native write (`Write`, `Edit`, `Delete`, a patch's files) is observed the
same way since v0.21.10: a path rule's ask or deny outside the floor is
recorded with the mode's fields, the file is copied aside first, and nothing
is said to the harness; the floor below holds for it as for a command. Until
then a path rule's deny on a native write was enforced in observe mode, and
`Write .env` was refused where the shell's `echo KEY=2 > .env` ran after its
copy.

The hook says nothing: no output, exit 0, in every harness, whatever the
verdict outside the floor. Measured on Claude Code, Codex, Cursor 3.21.16
and Copilot CLI 1.0.83, silence leaves the harness's own decision in place,
so its prompts are exactly what they were without Termaxa and observe mode
grants nothing the harness would not have granted by itself. (v0.20.0
answered Cursor and Copilot `allow` for an observed verdict, and Copilot
treats a hook's `allow` as an approval: it skipped its own prompt. Fixed in
v0.20.1. A rule's allow was still answered until v0.21.10, above.) Observed
verdicts send no notifications.

## The floor

Three things are enforced in both modes:

1. Every rule marked `floor: true`. The starter marks 38 of its denies, in
   three groups: the gate's own configuration and state (hook configs,
   `.termaxa/` policy, record, backups, shims, `core.hooksPath`; since
   v0.21.3 these are path rules as well as string rules, so a write into
   one of those files is held however the command is spelled, and reading
   them, `cat .claude/settings.json` or `git diff .termaxa/policy.yaml`,
   is ordinary work); the machine and its recovery points (`rm -rf /`,
   `--no-preserve-root`, `/etc`, SSH keys, shadow copies, WMI/CIM
   deletion); and commands whose own reason says there is no recovery path
   (`mkfs`, `dd` to a device, `drop database`, `kubectl delete`, `docker
   system prune`, `terraform` and `tofu destroy`, `find -delete`,
   migration and schema resets).
2. Any command whose insurance cannot be taken at the moment it runs: a
   delete past the copy budget, a push that deletes a ref it cannot pin, a
   `--prune` or `--mirror` that would remove refs, a drop with no dump. A
   directory a build or an install rebuilds is the exception (v0.21.3):
   `rm -rf node_modules`, `.next`, `dist`, `build`, `out`, `target`,
   `.venv`, `__pycache__` and their kind, inside the project root, are
   past the budget and not a loss, so they run, recorded as
   `known-uninsured`, with nothing copied. The same directory under any
   other name, or outside the project, is held as before.
3. A line that holds a command the gate did not read to the end (v0.21.9):
   substitutions nested more than eight deep, more than a hundred of them
   on one line, or a `-c` string past the fourth. Nothing judged the
   command left over, so nothing can say the floor is not in it, and the
   line is refused with no rule named. Since v0.22.0 so is a line with a
   word the shell opens into more names than the gate reads: past 100,000
   words, more than 64 that a rule could be about, or a second spent
   asking which.

Since v0.21.9 the floor holds a floor command wherever the gate reads it on
the line: after another deny, as the first command of a substitution,
behind `timeout`, `time`, `exec`, `setsid`, `stdbuf`, `watch` or `!`, in a
`{ ...; }` group and in a function's body. Until then `rm -rf dist; kubectl
delete ns prod` carried the `*rm -rf*` deny, which is not on the floor, and
ran with `dist` copied aside, as 35 of the 38 floor rules did behind `rm
-rf dist;`. And the eight floor rules anchored on a command's first word
(`rm -rf /`, `kubectl delete*`, `terraform destroy*`, `mkfs*` and their
kind) did not see `x=$(rm -rf /)`, `cat <(kubectl delete ns prod)` or
`timeout 60 kubectl delete ns prod`, which ran
([GHSA-84qh-xh6v-3qhr](https://github.com/termaxa/termaxa/security/advisories/GHSA-84qh-xh6v-3qhr)).

Since v0.21.10 the floor's path rules hold a file the command does not
name: a file copied or moved into its directory (`cp x/settings.json
.claude/`), a tree landed over it (`cp -r template/. .`), its directory
removed or moved away (`rm -r .claude`, `mv .claude .claude.bak`), and what
a git discard, a stash or a clean would undo. Until then the first three
were asks, or the `*rm -rf*` deny, which is not on the floor, and ran. And
in a project as `init` leaves it, where the policy is an untracked
directory and the hook registration an uncommitted change to a settings
file git already tracks, `git stash`, `git reset --hard` and `git checkout
-- .` put the settings file back without the hook and `git clean -fd`
deleted the policy: all four ran
([GHSA-7g97-4pmr-2vrq](https://github.com/termaxa/termaxa/security/advisories/GHSA-7g97-4pmr-2vrq)).
Until the policy and the hook config are committed, which `init` now says
to do, the git commands that would undo them are held in that project;
after that they are observed as before.
Of 57 ways to copy, move, rename or delete a guarded file without naming it,
observe mode held 6 on 0.21.9 and holds 47 now; the ten left are a `.env`,
whose rule is not on the floor, two lines that touch nothing guarded, and
seven the gate does not read.

Since v0.22.0 the floor's path rules know a guarded file however the shell
spells its name, not only as it is typed. A line is judged as bash reads
it, and on Windows as cmd and PowerShell read it, and each word as the
shell opens it: an escape, a pattern, a brace list or a range, zsh's
groups. Until then `echo x > .ter\maxa/policy.yaml`, `echo x >
.clau[d]e/settings.json`, `echo x > .claud{e..e}/settings.json` and `cd
.cl\aude && echo x > settings.json` were allowed by `echo *` and ran in
observe mode
([GHSA-x6qc-h3gm-5fj2](https://github.com/termaxa/termaxa/security/advisories/GHSA-x6qc-h3gm-5fj2)).
And a hook config, or the gate's own record and copies, in a directory its
tool has moved (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `TERMAXA_HOME`) is held
as it is under the default name. Until then a write to the hook config
there was allowed in every mode, and observe mode let the copies under a
moved state directory be deleted
([GHSA-vh3g-qw73-h9gg](https://github.com/termaxa/termaxa/security/advisories/GHSA-vh3g-qw73-h9gg)).

What the gate does not read it cannot hold. A command behind a runner it
does not know (`strace`, `flock`, `chroot`, `docker exec`, `ssh`), piped
into a shell, in an interpreter's inline code or in a script is not read:
the line gets the verdict of its own words, which under the starter is an
ask for all of these but a `node <file>` script, and in observe mode it
runs, unless a floor rule spelled with a leading `*` matches the line as
typed; the anchored ones do not. The same goes for a guarded file changed
by `install`, `rsync`, `ln`, `find -exec` or an archive unpacked over the
project, and for one that git brings in from another commit: a branch
switch, a merge, a pull or `git stash pop` can replace a hook config, and
the floor does not see it. SECURITY.md has both lists.

Observe mode cannot relax any of them. Lowering the floor means editing the
policy, which the fingerprint records. A policy that asks for observe but
has no `floor: true` rule at all is enforced instead; `termaxa doctor`
says why. Policies written before v0.20 have no markers: add `floor: true`
to the rules you would never want relaxed, or take the 38 from
`examples/policy.yaml`.

## Watching: a project that has no policy

A hook that a plugin registers runs in every project on the machine, and
most of them have no `.termaxa/policy.yaml`. Any other hook refuses every
command there and says to run `termaxa init`; that has not changed. A
plugin's hook is registered as `termaxa hook --plugin` (v0.22.0), and with
that flag a project with no policy is watched:

- The built-in starter judges each command and each native write, in
  observe mode, whatever `TERMAXA_MODE` says. Nobody chose that policy, so
  nothing on the machine turns it into one that asks and refuses.
- The floor above is what is refused, all three parts of it, with the
  starter's 38 rules as the first. A refusal ends by saying that the
  project is watched by the built-in starter and that `termaxa init` writes
  a policy. The gate's own files are on that floor, so a session cannot
  write the policy, or the hook registration, that would end the watching.
- The record, the witness and the copies are kept as for any project, in
  the state directory of the checkout the command ran in; outside a
  checkout, of the directory the session was started in. That is the state
  directory a later `termaxa init` at the checkout's root resolves to, so
  the project's own policy continues the record. Nothing is written into
  the project.
- Record lines carry `mode: watch`. `termaxa report`, `log`, `stats`,
  `backups`, `rollback` and `paths` read a watched project's record from
  inside it; `doctor` says the project is watched. `run`, `notify` and
  `breaker` still need a policy.
- A session is told once, when it starts: the hook answers `SessionStart`
  with a `systemMessage`, the field Claude Code's hooks reference describes
  as a warning shown to the user, and with no context for the model. Not
  after `/clear` or a compaction, which restart a session the person is
  already in.
- The circuit breaker does not run. It escalates asks, and nothing is
  asked; and a trip outlives its session in the state directory, where the
  policy `init` writes later would inherit it.

A project that has a policy is judged by it as written, in its own mode,
whoever registered the hook.

And a project that wires the hook itself is left to that hook. Claude Code
runs a plugin's handler beside a settings file's identical one, so without
this every command would be judged, recorded and copied twice. Where
`.claude/settings.json` or `.claude/settings.local.json` in the directory
the session started in, or the user's `settings.json`, registers `termaxa
hook` under `PreToolUse`, the plugin's hook answers nothing and leaves no
record, no witness and no copy, for any event. It reads only a
`settings*.json` in a `.claude` directory or in the directory
`CLAUDE_CONFIG_DIR` names, the files the floor holds against a session's
own writes. A registration it does not recognise (a
wrapper script that runs the hook from inside) leaves both hooks running:
a second record, and nothing taken away.

It reads those files at each call, and a registration counts once it has
been in its file for ten seconds. Claude Code's file watcher picks up a
hook edited into a settings file while a session runs, normally within a
few seconds, so a registration `termaxa init` wrote a moment ago is not
yet a hook that runs: for those seconds both hooks judge. If the hook has
not appeared in `/hooks` after that, the watcher missed the change and
the plugin's hook has stood down for a hook that is not running: restart
the session, which is what Claude Code's hooks guide says of a missed
change.

When `termaxa init` writes the policy in a project that was watched, it
reads that record first and proposes the project's own rules from it:

- What is proposed is what asked because nothing in the starter decided
  it, the policy's default. An ask a rule chose (`git push`, `curl`) stays
  an ask, and a refusal is not proposed away.
- Each proposal names the action as it was typed, `npm run build`, `npx
  prisma generate`, `python3 manage.py migrate`, `supabase migration new`,
  with how often it asked and the commands themselves. A runner is never
  proposed on its own: `npx *`, `npm run *` and `python3 *` run whatever
  they are handed, so a runner comes with the script, package or module it
  ran, or not at all.
- Not proposed, and listed as such: a command the gate reads as removing,
  overwriting or discarding files (the ask is where its preview is shown),
  one whose own words delete, drop, reset or destroy, an install of a
  package named on the line, anything run as another user, code given on
  the line (`python3 -c`, `node -e`), a database client's statements, a
  shell in a container or on another machine, and anything that asked once.
- At a terminal, each proposal is put to you, `y` to accept, anything else
  to drop. With no terminal (an agent running `init`, a script), every
  proposal is written as a comment that changes no verdict until you take
  the `# ` off and run `termaxa init` again.
- Accepted rules go at the end of the rules, below every rule of the
  starter, so they decide only what nothing above them decides: the floor
  and every refusal keep their place. `init` says how many of the record's
  asks they would have let run.

`init` also says what to do about a Claude Code session already open in the
project: restart it, so that it runs the project's own hook; the plugin's
hook stands down there ten seconds after the registration is written.

Under a supervisor (`termaxa supervise`) a plugin's hook forwards as any
hook does, and the supervisor refuses a project that has no policy:
watching is the unsupervised hook's.

## What you read

`termaxa report` adds a section:

```
Observed, not enforced
enforcement would have asked N and denied N
  insured             N   a copy was taken first
  known, uninsured    N   understood, nothing could be copied
  consequence unknown N   the gate could not read what they change
  held by the floor   N   denied even in observe mode
ran with no copy: N
```

"Ran with no copy" is the exposure: the commands observe mode let run that
enforce mode would have interrupted and that nothing insured. `termaxa log`
shows the lines themselves, and since v0.22.0 marks a verdict that was not
enforced (`→ observed, not enforced`, or `→ watched, not enforced`), since
the mark beside it is the verdict's and the command ran. `termaxa doctor`
names the mode in force, where it came from (the policy file,
`TERMAXA_MODE`, or the default) and the floor-rule count.

The report's `Asks` line counts the asks that were put to somebody. Until
v0.22.0 it counted an observed ask as well, and took that command's own
execution receipt for the answer: a session observed from end to end
reported every ask approved, and the report called it a habit. An ask that
was recorded and not enforced is in the section above and nowhere else. A
watched project's report has one more line, `Watched`, with the number of
lines the built-in starter judged while the project had no policy.

## Switching

Change `mode` to `enforce`, or remove the line. Everything observe mode
recorded stays in the record; the asks it would have asked start asking.
