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

Silence - no output, exit 0 - is the answer for an allow no rule named, and
only where the harness documents that no output means no opinion (Claude
Code; Codex for every allow). Cursor and Copilot always get an answer.

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

## What is not captured yet

- Any harness's silence semantics beyond Claude Code and Codex.
- Copilot CLI's file tools, if it has hookable ones.

Each of those is one capture away. Send it.
