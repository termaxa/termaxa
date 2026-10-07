# Found in the wild

Every defect in Termaxa's own behaviour that was found through real use rather
than by its test suite or in review: a live agent session, a replay of real
transcripts, a deployment, a measurement on a real harness, or a report from
outside. Each entry says what was wrong, how it was found, and where it was
fixed. The number on the site is this list's length; when an entry is added,
the number changes.

Fixes found by the test suite or by reading the code are not here. They are in
the [changelog](../CHANGELOG.md), which this list is drawn from, with the
wording of each entry kept close to the changelog's own.

Entries are dated by the day the changelog gives for the finding; where it
gives none, by the release that fixed it.

**34 bugs, in 21 episodes, as of v0.20.1.**

## 2026

### July 3 — the force-push preview said "nothing to push" while a commit was destroyed

The preview compared the branch with its upstream in one direction only, so a
force push that threw away a remote commit read as a no-op. Found in live use.
Fixed in [v0.6.1](https://github.com/termaxa/termaxa/releases/tag/v0.6.1): the
preview shows what the remote will *lose*. 1 bug.

### July 3 — `git status && <anything>` rode the `git status*` allow rule

A compound command was judged as one string, so a benign prefix lent its allow
to whatever followed. Found by the first live Claude Code session. Fixed in
[v0.7.0](https://github.com/termaxa/termaxa/releases/tag/v0.7.0): compound
commands are split and the most dangerous segment governs. Published later as
[GHSA-rv66-7qcx-c45j](https://github.com/termaxa/termaxa/security/advisories/GHSA-rv66-7qcx-c45j).
1 bug.

### July 16 — Cursor 3.11 renamed its hook API and the gate silently stopped intercepting

Cursor moved from `beforeShellExecution`/`afterShellExecution` to
`preToolUse`/`postToolUse` with `tool_name: "Shell"`; Termaxa knew only the
older shape, so on current Cursor it intercepted nothing, with every test still
green. Found when Cursor updated; verified live on Cursor 3.11.25. Fixed in
[v0.11.4](https://github.com/termaxa/termaxa/releases/tag/v0.11.4), which
handles both shapes. This is the episode behind the fail-open design note in the
README and the liveness probe below. 1 bug.

### August 6 — coloured labels broke the column alignment

Padding counted the escape bytes of a colourised label, so `check` printed
`commandrm -rf /`. Found by live testing. Fixed in
[v0.13.0](https://github.com/termaxa/termaxa/releases/tag/v0.13.0), pinned by a
test that strips ANSI before measuring. 1 bug.

### August 11 — Tim Schipper's report ([#16](https://github.com/termaxa/termaxa/issues/16))

Four bugs from one outside reading of the gate:

- the starter policy had no rule about `.termaxa/` or the agent hook configs,
  so `echo 'default: allow' > .termaxa/policy.yaml` was an ordinary write;
- `ls*` and `grep*` were prefixes, not commands: `lsof`, `lsblk`, `lsattr` and
  `grepdiff` matched them;
- `rm --no-preserve-root -rf /` was not the spelling the `rm -rf /*` rule named,
  and GNU `rm` refuses the one it did name;
- `git push origin +main` is a force push, and the classifier did not count it.

Fixed in [v0.14.2](https://github.com/termaxa/termaxa/releases/tag/v0.14.2),
with policy fingerprinting added so that what cannot be blocked is at least
seen. 4 bugs.

### August 13 — doctor said "configured" in green through two ungated sessions

Doctor checked for the hook by a substring search over `settings.json`. A hook
whose path was mangled at exec failed non-blocking, two full sessions ran
without the gate, and doctor reported it configured throughout (observed on
Windows, 2026-08-13). Fixed in
[v0.15.0](https://github.com/termaxa/termaxa/releases/tag/v0.15.0): doctor now
invokes the registered command with a synthetic must-deny payload and reports
configured-and-live, registered-but-not-firing, or absent. 1 bug.

### August 17 — supervised mode did not route

The first real agent session under supervised mode found that a hook running as
the agent resolved the socket path from *its own* `$HOME`, found nothing, and
fell back to deciding locally, so no command reached the supervisor. Fixed in
[v0.17.0](https://github.com/termaxa/termaxa/releases/tag/v0.17.0); the
[field report](field-reports/2026-08-17-supervised-routing.md) is published
with what broke. 1 bug.

### September 5–6 — the first real Codex session

Two findings. The hook was speaking the wrong contract to Codex on every value,
and `wrap` had never executed a command in its life: the runner's own `sh` resolved through the wrapper's shim
PATH, so an allowed command recursed until it was killed and an asked one asked
twice, then refused for lack of stdin
([#65](https://github.com/termaxa/termaxa/issues/65)). Fixed in
[v0.18.0](https://github.com/termaxa/termaxa/releases/tag/v0.18.0); Codex has
been live-tested since. 2 bugs.

### September 5 — a field report: `npx supabase db reset` under a UI task

Reported on r/ClaudeCode: an agent given a purely UI task ran
`npx supabase db reset`. The starter policy allowed `npx *` and `<pm> run *`,
commands that run anything, and had no hard stop for a database reset. Fixed in
[v0.18.1](https://github.com/termaxa/termaxa/releases/tag/v0.18.1). 1 bug.

### September 9 — `$1` and `$@` were not read as variables

[anthropics/claude-code#82165](https://github.com/anthropics/claude-code/issues/82165)
showed an agent composing commands through positional parameters, which the
resolver did not treat as variables. Fixed in
[v0.18.2](https://github.com/termaxa/termaxa/releases/tag/v0.18.2). 1 bug.

### September 10 — the first real agent under `wrap`

Four bugs from one session:

- `zsh -c -l "cmd"` was read as the command `-l`: a shell accepts its options in
  any order, and Claude Code puts `-l` after `-c`;
- an unattended ask was a hang: the runner prompted on stdin, the harness's pipe
  never closed, and the prompt blocked until Claude Code gave up at 120 s;
- the self-protection rule refused the agent's own startup, because the
  starter's `*.termaxa*` deny matched the PATH line `wrap` injects into every
  shell it starts;
- `wrap` shimmed a shell that was not installed, and Claude Code chose the shell
  the shim advertised.

Fixed in [v0.18.4](https://github.com/termaxa/termaxa/releases/tag/v0.18.4).
4 bugs.

### September 11 — Claude Code's preamble was judged as a command

Every Bash tool call arrives wrapped in scaffolding (`shopt -u extglob … ;
unset -f …`). The reader judged the scaffolding as part of the command, and the
context check took its `unset -f` for a destructive flag, escalating every
allowed command to an ask
([#92](https://github.com/termaxa/termaxa/issues/92)). Found with Claude Code
live under `wrap`. Fixed in
[v0.18.5](https://github.com/termaxa/termaxa/releases/tag/v0.18.5). 2 bugs.

### September 12 — `wrap` handed the agent a bash shim when it would have chosen zsh

Measured on Claude Code, on Linux with and without zsh. Fixed in
[v0.18.6](https://github.com/termaxa/termaxa/releases/tag/v0.18.6): the shim
named is the one for the shell the agent would have chosen itself
([#96](https://github.com/termaxa/termaxa/issues/96)). 1 bug.

### September 19 — Codex's `apply_patch` was read as a command, not a write

Captured live: a patch carries the files it writes, adds and deletes in its
headers, and the gate had been judging its name as a command string. Fixed in
[v0.19.1](https://github.com/termaxa/termaxa/releases/tag/v0.19.1)
([#104](https://github.com/termaxa/termaxa/issues/104)). 1 bug.

### September 19 — Cursor's `Delete` passed through

In live testing a Cursor agent, refused in the shell, switched to its file-delete
tool and removed files Termaxa never saw; `Delete` was not read as a write of
kind delete. Captured on Cursor 3.11.25. Fixed in
[v0.19.2](https://github.com/termaxa/termaxa/releases/tag/v0.19.2)
([#106](https://github.com/termaxa/termaxa/issues/106)). 1 bug.

### September 19–20 — the first replay of real transcripts, and the first deployment

`termaxa replay` was run over the project's own Claude Code transcripts, and
`$(git branch --show-current)`, which matched an allow, had been escalated to an
ask because any `$(…)` was a signal
([#108](https://github.com/termaxa/termaxa/issues/108)). The same days, building
the playground found that the Linux release asset needed glibc 2.39 and would
not start on Debian 12 or Ubuntu 22.04
([#109](https://github.com/termaxa/termaxa/issues/109)). Both fixed in
[v0.19.3](https://github.com/termaxa/termaxa/releases/tag/v0.19.3); the Linux
asset is a static musl build since. 2 bugs.

### September 20 — git's global options, and a link the insurance followed

A live Herdr session showed Claude Code spelling its git calls `git -C <path> …`,
and no rule saw past the `-C`. And a measurement on Windows with a real
junction, made after the Sep 20 incident that deleted 48,218 live files through
directory junctions, found the insurance copy branching on `is_dir()`, which
follows links: a directory holding a link into a large live tree passed the size
cap as a handful of entries and then copied the whole tree behind it, and a
rollback would have put the link back as a real directory. Both fixed in
[v0.19.4](https://github.com/termaxa/termaxa/releases/tag/v0.19.4). 2 bugs.

### September 27 — Claude Code's startup probe, and the spellings a rule did not see

Claude Code's startup probe (`sh -c "… for c in npm yarn pnpm; do command -v …;
done"`) was refused on its control-flow keywords
([#117](https://github.com/termaxa/termaxa/issues/117)). The same day, answering
a team's open question about their own Claude Code deny list, a measurement
showed string rules blind to spellings the resolver already knew
([#118](https://github.com/termaxa/termaxa/issues/118)). Fixed in
[v0.19.5](https://github.com/termaxa/termaxa/releases/tag/v0.19.5). 2 bugs.

### September 27 — Tim Schipper's second report: GHSA-36jf-95xr-37f2

Starter rules written for the reading form of a command also allowed options
that write or run; the files those options write were neither previewed nor
insured; and a push that removes refs (`:ref`, `--delete`, `--prune`,
`--mirror`) was described by the preview as an ordinary push. Reported by Tim
Schipper, fixed in
[v0.19.6](https://github.com/termaxa/termaxa/releases/tag/v0.19.6), published as
[GHSA-36jf-95xr-37f2](https://github.com/termaxa/termaxa/security/advisories/GHSA-36jf-95xr-37f2).
3 bugs.

### October 1 — the first `replay --against-record` found its own reader at fault

The first run of the record-against-transcript check flagged nine shell calls as
"never fired". Every one was a defect of the reader: it counted files an agent
had written that mentioned a command as shell calls, and read a
`powershell -Command` or `bash -lc` wrapper as its own name rather than as the
script it ran. The reader counts shell calls only since
[v0.20.0](https://github.com/termaxa/termaxa/releases/tag/v0.20.0)
([#128](https://github.com/termaxa/termaxa/issues/128)); the nine are tests. A
tool that can disprove its own findings is the point of the check. 1 bug.

### October 4 — observe mode's `allow` skipped Copilot's own prompt

v0.20.0's observe mode answered Cursor and Copilot `allow` for commands outside
the floor. Copilot CLI 1.0.83 treats a hook's `allow` as an approval and skipped
its own prompt. Measured on Windows with a probe hook that answered one way per
trial. Fixed the same day in
[v0.20.1](https://github.com/termaxa/termaxa/releases/tag/v0.20.1)
([#132](https://github.com/termaxa/termaxa/issues/132)): an observed verdict is
silence in every harness. 1 bug.

## Adding an entry

An entry needs the four things above: what was wrong, how it was found outside
the test suite, the release that fixed it, and a link that a reader can follow.
Then change the count at the top, and the number on the site with it.
