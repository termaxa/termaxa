# Dialects: how each harness talks to the gate

A dialect is the shape a harness sends a hook and the shape it expects back.
Every one below was captured from a live session before it was written; the
capture is the fixture test. The rule for a new one is the same: capture,
then fixture, then code, and no coverage claimed until a session has been
watched end to end.

## Capturing

```
TERMAXA_HOOK_DEBUG=/tmp/hook-capture.txt
```

With that set, `termaxa hook` appends every payload it receives, verbatim,
before doing anything with it. Run the harness through the action you want
covered (a shell command, a file write, a delete), and the capture has the
fields, the event names and the tool names as they arrive. Redact anything
personal and paste it into the issue; the fixture test is built from those
bytes.

## What is wired

| Harness | `init` flag | File written | Events | Honours |
| --- | --- | --- | --- | --- |
| Claude Code | `--claude-code` | `.claude/settings.json` | `PreToolUse` and `PostToolUse` on `Bash` and on `Write\|Edit\|MultiEdit\|NotebookEdit` | `allow`, `ask`, `deny`; no output means no opinion |
| Codex CLI | `--codex` | `.codex/hooks.json` | `PreToolUse` and `PostToolUse` on `Bash\|apply_patch` | `deny` only: an explicit `allow` is rejected, an `ask` is a refusal, a failed hook falls open to Codex's own prompt. Headless (`codex exec`) a hook runs only once trusted, or with `--dangerously-bypass-hook-trust` |
| Cursor | `--cursor` | `.cursor/hooks.json` | `beforeShellExecution` / `afterShellExecution` for the shell; `preToolUse` / `postToolUse` on `Write\|Delete` for the file tools (3.11) | `permission` in the JSON; exit 2 blocks; other non-zero exits fail open |
| Copilot CLI | `--copilot` | `.github/hooks/hooks.json`; also reads `.claude/settings.json` as repo settings | `toolName` / `toolArgs` (arguments as a JSON string) | top-level `permissionDecision`; a non-zero exit is a hook error, so a deny exits 0 |
| Hermes Agent | none yet (by hand, below) | the profile's `config.yaml` (`hooks:`) | `pre_tool_call` and `post_tool_call` on `terminal\|write_file\|patch\|execute_code` | a top-level `decision` or `action`: `block`, and `approve` for its approval gate; exit 2 blocks; a failure falls open unless the entry sets `fail_closed: true` |

A harness with no hooks runs under `termaxa wrap -- <agent>` (Unix), which
puts shims for `sh`, `bash` and `zsh` on `PATH` and hands the agent the shim
for the shell it would have chosen. Claude Code takes it from
`CLAUDE_CODE_SHELL`, which `wrap` sets; a harness that hardcodes its shell
and offers no such setting is outside this mechanism. Codex is one, measured
Sep 19, 2026 under `strace`: it runs the account's login shell by absolute
path (`/bin/bash -lc` here, `/bin/zsh -lc` on a Mac), ignores `$SHELL`, and
its configuration covers the environment and login-ness, not the binary.
`wrap` records nothing for Codex; its hooks are the way in.

## The response shapes

Claude Code, Codex and Copilot-through-repo-settings:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[termaxa] …"}}
```

Cursor (both spellings, since both have shipped):

```json
{"permission":"deny","agent_message":"…","user_message":"…","agentMessage":"…","userMessage":"…"}
```

Copilot CLI:

```json
{"permissionDecision":"deny","permissionDecisionReason":"[termaxa] …"}
```

Hermes Agent: `{"decision":"block","reason":"[termaxa] …"}`, and for an ask
`{"action":"approve","message":"…"}` (below).

Silence - no output, exit 0 - is the answer for an allow no rule named, and
only where the harness documents that no output means no opinion (Claude
Code; Codex and Hermes for every allow). Cursor and Copilot always get an
answer in enforce mode. An observed verdict (observe mode) is silence in every
harness, measured below, and since v0.21.10 so is an allow in observe mode:
outside the floor the mode answers nothing, and each harness decides as it
would without the hook.

## Silence, `allow` and `ask`, as measured (Oct 4, 2026, Windows)

A probe hook answered each harness exactly one way per trial, keyed by a
token in the command, and logged every call; the harness's own prompt was
declined whenever it appeared, so a written file means it ran with no human
yes.

| | Cursor 3.21.16 | Copilot CLI 1.0.83 |
| --- | --- | --- |
| No output | the harness decides as it would alone: Allowlist asks, Auto-review's reviewer decides | Copilot asks |
| `allow` | Allowlist still asks; Auto-review and Run Everything run | **Copilot skips its own prompt and runs** |
| `ask` | asks in Allowlist and in Run Everything ("Hook requested approval"); **Auto-review's reviewer overrides it and runs** | asks in manual approval (1.0.91); under `--allow-all-tools` not yet measured |
| `deny` | blocked | blocked |

Cursor runs the hook before its own approval prompt, once per attempt, and
says whether the attempt is sandboxed (`"sandbox": true|false`). On Windows
its sandbox cannot enforce filesystem isolation, so every command reaches
the unsandboxed attempt. The payload's `cwd` is empty; the project is in
`workspace_roots`. Nothing in the payload names the auto-run mode.
Copilot's `toolArgs` arrives as an inline object on Windows (tool
`powershell`), which the reader has accepted since the Sep 9 capture.

### Claude Code's bypass mode

A `PreToolUse` hook's `ask` is honoured under `--dangerously-skip-permissions`,
where an `ask` rule in `settings.json` is not
([anthropics/claude-code#95741](https://github.com/anthropics/claude-code/issues/95741),
open). Measured on Claude Code 2.1.283 (Sep 29, 2026) and again on 2.1.302
(Oct 16, 2026), on Linux, with a probe hook answering `ask` for a command that
creates a file only if it runs. Interactively, with the footer showing "bypass
permissions on", the dialog appears ("Hook PreToolUse:Bash requires
confirmation for this command … Do you want to proceed?") and declining
interrupts the call; headless (`claude -p`), the call is refused with the
hook's reason, listed under `permission_denials` in the result, and the agent
reports that it did not run. In both, the file is not created. So in bypass
mode the gate's `ask` still stops for a human, or refuses unattended, and
`deny` holds as everywhere.

## Native writes

The write matcher delivers `Write`, `Edit`, `MultiEdit` and `NotebookEdit`
(and any tool whose name carries `write`, `edit`, `create`, `patch`,
`replace`, `notebook` or `save`). A write to the gate's own files is refused
regardless of policy. Everything else is judged by its target against the
`match_path` rules only, with no default: nothing named, nothing said. A
patch (`*** Begin Patch` … `*** Delete File:` …) is read by its file headers
from whatever field carries it.

## Codex, as captured (Sep 19, 2026, codex-cli 0.155.1)

`PreToolUse` and `PostToolUse` arrive in Claude Code's shape: `session_id`,
`turn_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`,
`permission_mode`, `tool_name`, `tool_input`, `tool_use_id`, and on the post
event `tool_response`. `apply_patch` is `tool_name: "apply_patch"` with the
whole patch text in `tool_input.command` — the field a shell command lives
in, which is why the hook reads a tool with a write verb before it reads a
command. One patch can carry several files; it is one call and gets one
verdict, the most severe among its targets.

## Cursor's file tools, as captured (Sep 19, 2026, cursor 3.11.25)

`preToolUse` and `postToolUse` with `tool_name: "Write"` or `"Delete"`,
`tool_input.file_path` absolute, no `cwd` — the project is only in
`workspace_roots`, as a URI (`/C:/Users/…`), which the reader normalises —
plus `conversation_id`, `generation_id`, `model`, `tool_use_id`,
`session_id`, `cursor_version`, `user_email`, `transcript_path`, and a UTF-8
BOM in front of every payload. The post event adds `tool_output` (a JSON
string: `{"file_path":…,"success":true}` for a write,
`{"file_path":…,"deleted":true}` for a delete) and `duration`. `Delete` had
no verb the reader knew before this capture and passed through by default;
it is a delete, judged by its target.

## Hermes Agent, as captured (Nov 19, 2026, Hermes 0.23.2)

Hermes declares shell hooks in a profile's `config.yaml`, and they run for
every session the profile serves. A real session, driven by a scripted model
so that every step ran through Hermes's own code, sent `pre_tool_call` and
`post_tool_call` with `tool_name`, `tool_input`, `session_id`, `cwd`,
`profile` and an `extra` of ids (`post_tool_call` adds `result`, `status`,
`error_type`, `error_message` and `duration_ms` to it). Its shell is
`terminal` (`tool_input.command`, and a `workdir` when the model passes one);
`write_file` and `patch` write files (by `path`, or in a `*** Begin Patch`
text read by its headers); `execute_code` runs Python. A subagent's calls
arrive under the subagent's own session id, and a `terminal` call made from
inside `execute_code` arrives on its own.

Hermes reads a top-level `decision` or `action` and nothing else, so its
answers are:

```json
{"decision":"block","reason":"[termaxa] …"}
{"action":"approve","message":"[termaxa] asks: …"}
```

A deny also exits 2, which Hermes reads as a block by itself. An ask goes to
Hermes's approval gate: a person answers it in an interactive session; where
no one can, as in `hermes chat -q`, Hermes refuses the call; and `--yolo` or
`approvals.single_query_mode: approve` lets it through, so under either an
ask is an allow. Every allow is silence. `execute_code` is always an ask: its
Python cannot be read, as a script file cannot.

**The directory.** Hermes 0.23.2 puts the gateway process's own directory in
`cwd` (its install directory, or `~/.hermes`), not the session's:
NousResearch/hermes-agent#146570 reports it, and #139555 would fix it. A
terminal call's `workdir` is where Hermes runs the command, but it is the
agent's to choose. So a Hermes call is never judged by a policy found from a
directory. `termaxa hook --hermes` judges every Hermes call by one policy,
`hermes/.termaxa/policy.yaml` under termaxa's home (`~/.termaxa`, or
`TERMAXA_HOME`), or by the built-in starter while that file does not exist,
and keeps one record of them. A directory is read only for where a command's
paths land: `workdir` when it is given, and `cwd` when it is not Hermes's own
(inside Hermes's home, the one `HERMES_HOME` names or the platform's
default, or a directory holding Hermes's code). With neither, the directory
is unknown: a path rule matches a path by its end, as after a `cd "$X"`, and
only a path given in full is previewed and copied aside; the reason says so. Without `--hermes`, a Hermes call is refused, and the reason
names the flag.

**Wiring it.** `termaxa init --hermes` wires the profile a bare `hermes`
uses: the one `HERMES_HOME` names, or else the default home (`~/.hermes`,
and `%LOCALAPPDATA%\hermes` on Windows) or the profile its `active_profile`
file names. It writes the policy above from the starter when there is none,
adds these hooks to the profile's `config.yaml` (the file as it was is kept
beside it, as `config.yaml.before-termaxa`), approves both, and sends the
command a test call:

```yaml
hooks:
  pre_tool_call:
    - matcher: "terminal|write_file|patch|execute_code"
      command: "termaxa hook --hermes"
      timeout: 30
      fail_closed: true
  post_tool_call:
    - matcher: "terminal|write_file|patch"
      command: "termaxa hook --hermes"
      timeout: 30
```

On Windows the command is the binary's full path, because Windows looks for
a bare name in the directory Hermes runs from before it looks on PATH, and a
`termaxa.exe` left there would run in the gate's place. Elsewhere it is
`termaxa` when PATH finds the binary that ran `init`, which an upgrade that
moves the binary does not break, and the full path when PATH finds another
or none. A `config.yaml` with a `hooks:` block of its own is not edited:
`init` prints the entries to add to it, and approves them when run again.

With `fail_closed: true`, a missing or crashing `termaxa` refuses those four
tools, in Hermes's own words; without it, every failure lets the call run.
Hermes runs a hook only once its event and its exact command are approved in
the profile's `shell-hooks-allowlist.json`: a foreground `hermes chat` asks
the first time, while the gateway, cron and the desktop app skip an
unapproved hook with a line in `agent.log` and nothing else. `init` writes
the approvals that `hermes --accept-hooks` would, without the binary's
modification time, which every upgrade changes. `termaxa doctor` reads all of
it back: the entry, its matcher, the approval, the command's answer to a test
call, and the policy's fingerprint. `hermes hooks list` shows the hooks as
Hermes sees them; `hermes hooks doctor` looks for a bare `termaxa` as a file
in Hermes's own directory, so it reports one that PATH finds as missing.

Not covered: a deferred tool reached through `tool_call` (an MCP server's),
the Python inside `execute_code`, and a terminal backend other than `local`
(Docker, SSH, Modal and the rest run the command elsewhere, where a preview or
a copy made on this machine means nothing). Supervised mode does not carry
`--hermes` to its daemon, so a Hermes call is refused there.

## What is not captured yet

- Copilot CLI's file tools, if it has hookable ones.

Each of those is one capture away. Send it.
