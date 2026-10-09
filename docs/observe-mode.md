# Observe mode

`mode: observe` in `.termaxa/policy.yaml` (or `TERMAXA_MODE=observe` on one
machine) makes the gate record what enforcement would have done without
interrupting execution, except for a floor it cannot lower. The default is
`enforce`. Observe mode applies in the hook and in `termaxa run`.

## What runs

Outside the floor, every command runs:

- An **allow** behaves as in enforce mode.
- An **ask** or **deny** runs after its insurance is taken (the same copy,
  pin or dump enforce mode takes before an allowed destructive command),
  and is recorded as the verdict enforcement would have given. The record
  line carries `mode: observe`, `enforced: false`, and a `coverage`:
  - `insured`: a copy was taken first;
  - `known-uninsured`: the gate understood the command and nothing could
    be copied (a remote ref it cannot pin, a database it has no dump for);
  - `unknown`: the gate could not read what the command changes (a script
    file, inline code, an unresolvable substitution).

The hook says nothing: no output, exit 0, in every harness. Measured on
Claude Code, Codex, Cursor 3.21.16 and Copilot CLI 1.0.83, silence leaves
the harness's own decision in place, so its prompts are exactly what they
were without Termaxa and observe mode grants nothing the harness would not
have granted by itself. (v0.20.0 answered Cursor and Copilot `allow`
instead, and Copilot treats a hook's `allow` as an approval: it skipped its
own prompt. Fixed in v0.20.1.) Observed verdicts send no notifications.

## The floor

Two things are enforced in both modes:

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

Observe mode cannot relax either. Lowering the floor means editing the
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
