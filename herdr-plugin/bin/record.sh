#!/usr/bin/env bash
# Pane: the workspace project's Termaxa record, following. `termaxa log -f`
# prints the last entries and then each one as it is written.
. "$(dirname "$0")/lib.sh"
# A plugin pane starts in the PLUGIN ROOT, not the workspace (read from
# Herdr's `plugin_pane_cwd`, Sep 24, 2026; the record pane sat empty in a
# live session for exactly that reason). The project comes from the launch
# context first, then the workspace, then the pane.
cwd=""
ctx="${HERDR_PLUGIN_CONTEXT_JSON:-}"
[ -n "$ctx" ] && cwd=$(printf '%s' "$ctx" | field focused_pane_cwd)
[ -n "$cwd" ] || { [ -n "$ctx" ] && cwd=$(printf '%s' "$ctx" | field workspace_cwd); }
[ -n "$cwd" ] || [ -z "${HERDR_WORKSPACE_ID:-}" ] || cwd=$(workspace_cwd "$HERDR_WORKSPACE_ID")
[ -n "$cwd" ] || [ -z "${HERDR_PANE_ID:-}" ] || cwd=$(pane_cwd "$HERDR_PANE_ID")
[ -n "$cwd" ] && cd "$(project_of "$cwd")" 2>/dev/null
have_termaxa || { echo "termaxa not found: install it or put it on PATH"; exec sleep 5; }
if [ ! -d .termaxa ]; then
  echo "no .termaxa/ in $(pwd): run 'termaxa init' in the project first (or start an agent under the gate from this workspace)."
  exec sleep 30
fi
exec "$TERMAXA" log --follow -n 30
