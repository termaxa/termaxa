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
   line is refused with no rule named.

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
shows the lines themselves. `termaxa doctor` names the mode in force,
where it came from (the policy file, `TERMAXA_MODE`, or the default) and
the floor-rule count.

## Switching

Change `mode` to `enforce`, or remove the line. Everything observe mode
recorded stays in the record; the asks it would have asked start asking.
