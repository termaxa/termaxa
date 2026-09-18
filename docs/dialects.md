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
| Codex CLI | `--codex` | `.codex/hooks.json` | `PreToolUse` on `Bash\|apply_patch` | `deny` only: an explicit `allow` is rejected, an `ask` is a refusal, a failed hook falls open to Codex's own prompt |
| Cursor | `--cursor` | `.cursor/hooks.json` | `preToolUse` / `postToolUse` (3.11), `beforeShellExecution` (older) | `permission` in the JSON; exit 2 blocks; other non-zero exits fail open |
| Copilot CLI | `--copilot` | `.github/hooks/hooks.json`; also reads `.claude/settings.json` as repo settings | `toolName` / `toolArgs` (arguments as a JSON string) | top-level `permissionDecision`; a non-zero exit is a hook error, so a deny exits 0 |

A harness with no hooks runs under `termaxa wrap -- <agent>` (Unix), which
puts shims for `sh`, `bash` and `zsh` on `PATH` and hands the agent the shim
for the shell it would have chosen. Claude Code takes it from
`CLAUDE_CODE_SHELL`, which `wrap` sets; a harness that hardcodes its shell
and offers no such setting is outside this mechanism.

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

## What is not captured yet

- Codex's `PostToolUse` payload, and its `apply_patch` payload. The matcher
  is registered; the shapes are not claimed.
- Cursor's `Write` and `Delete` tool payloads under `preToolUse`.
- Any harness's silence semantics beyond Claude Code and Codex.

Each of those is one capture away. Send it.
