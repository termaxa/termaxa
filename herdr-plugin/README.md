# Termaxa for Herdr

A [Herdr](https://herdr.dev) plugin for [Termaxa](https://github.com/termaxa/termaxa),
the gate for the shell commands AI coding agents run. Three things:

- **Run an agent under the gate.** An action that splits a pane beside the
  current one and starts Claude Code under `termaxa wrap`, so every shell
  command it runs is previewed, insured, judged and recorded. A second
  action does the same for Codex through its hook (`termaxa init --codex`,
  then `codex`); Codex runs its shell by absolute path and the wrapper
  cannot reach it.
- **The record, live.** A pane running `termaxa log --follow` in the
  workspace's project: every verdict as it happens. **Termaxa: show the
  record** opens it as an overlay over the active pane; a refusal opens it
  as a split beside the agent's pane.
- **Why the agent stopped.** A watcher started with Herdr follows each
  workspace project's Termaxa record and reacts to a refusal the moment it
  is written: the pane gets `termaxa deny` as its state label and the
  reason as its message (`termaxa deny: rm -rf ./scratch — Recursive force
  delete …`), and the record opens in a split below the pane that caused
  it. Measured Sep 20, 2026 in
  a live session, this is why the watcher exists rather than a status hook
  alone: under `wrap` a refusal does not change the agent's detected
  status — Claude Code reports the refusal and carries on, or opens its own
  menu and waits — so `pane.agent_status_changed` never fired for three
  refused deletes. The status hook is still registered for the harnesses
  where a refusal does stop the agent; whichever sees the entry first
  reports it.

Requires `termaxa` installed (`brew install termaxa/tap/termaxa`,
`cargo install termaxa`, or a release binary) and Herdr 0.9 or later.
Linux and macOS. Herdr runs plugin commands with `HERDR_BIN_PATH` set and
its own PATH, not your login PATH, so the scripts resolve `herdr` from
`HERDR_BIN_PATH` and look for `termaxa` on PATH and then in
`~/.local/bin`, `/usr/local/bin`, `/opt/homebrew/bin` and `~/.cargo/bin`.
If yours is somewhere else, a symlink into one of those is enough; when it
cannot be found the hook says so in `herdr plugin log list`.

## Install

```
herdr plugin install termaxa/termaxa
```

The plugin lives in the Termaxa repository under `herdr-plugin/`; Herdr
finds the manifest there. From a checkout while developing:
`herdr plugin link /path/to/termaxa/herdr-plugin`.

## Use

In a workspace, invoke the action **Termaxa: Claude Code under the gate**
(or `herdr plugin action invoke gate-claude --plugin termaxa.gate`). The
agent starts in a new pane; a refused command shows up in the agent's own
terminal with Termaxa's reason, on the sidebar as the pane's blocked state,
and in the record overlay. **Termaxa: show the record** opens the record
pane by hand.

Unattended, an *ask* is a refusal: there is no terminal to answer it. The
starter policy is built for that, and `termaxa replay` on your own
transcripts shows what it would have asked about before you start.

## What it is not

Not a sandbox. Termaxa gates what goes through a shell resolved by name, and
native file tools only where a path rule names the file; the residues are in
[SECURITY.md](https://github.com/termaxa/termaxa/blob/main/SECURITY.md).

## Layout

- `herdr-plugin.toml` — the manifest: three actions, one event hook, one pane.
- `bin/gate.sh` — the gate action (`claude` or `codex`).
- `bin/record.sh` — the record pane. A plugin pane starts in the plugin
  root, so it takes the project from the launch context (`workspace_cwd`)
  and the openers pass `--cwd` as well.
- `bin/open-record.sh` — the open-record action.
- `bin/watch.sh` — the startup watcher: follows each project's record and
  reports refusals. One per machine (a lock under `$XDG_RUNTIME_DIR`), one
  follower per project.
- `bin/on-status.sh` — the `pane.agent_status_changed` hook, the secondary
  trigger.
- `bin/lib.sh` — JSON field extraction with `sed`, no python or jq needed.

MIT or Apache-2.0, at your option, like Termaxa.
