#!/usr/bin/env bash
# Action: open the record pane for the current workspace as an overlay.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
have_herdr || { echo "herdr not found: HERDR_BIN_PATH unset and not on PATH" >&2; exit 1; }
# An overlay targets the active pane and takes no --workspace; --cwd puts
# the pane in the project rather than the plugin root.
cwd=""
ctx="${HERDR_PLUGIN_CONTEXT_JSON:-}"
[ -n "$ctx" ] && cwd=$(printf '%s' "$ctx" | field focused_pane_cwd)
[ -n "$cwd" ] || { [ -n "$ctx" ] && cwd=$(printf '%s' "$ctx" | field workspace_cwd); }
[ -n "$cwd" ] || [ -z "${HERDR_WORKSPACE_ID:-}" ] || cwd=$(workspace_cwd "$HERDR_WORKSPACE_ID")
proj=$(project_of "${cwd:-$PWD}")
exec "$HERDR" plugin pane open --plugin termaxa.gate --entrypoint record --placement overlay --cwd "$proj"
