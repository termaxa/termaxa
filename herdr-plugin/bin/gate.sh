#!/usr/bin/env bash
# Action: start an agent under the gate in a new pane beside the current one.
#   gate.sh claude   → termaxa wrap -- claude   (the wrapper; measured on Claude Code)
#   gate.sh codex    → termaxa init --codex; codex   (Codex ignores the wrapper's shell; its hook is the way in)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
agent="${1:-claude}"
have_termaxa || { echo "termaxa not found: install it (https://github.com/termaxa/termaxa#install) or put it on PATH" >&2; exit 1; }
have_herdr || { echo "herdr not found: HERDR_BIN_PATH unset and not on PATH" >&2; exit 1; }
# The agent and termaxa must be findable from the pane's own shell, which is
# a login shell with the user's PATH, not this hook's.
command -v "$agent" >/dev/null 2>&1 || echo "note: $agent is not on the plugin's PATH; the pane's shell must find it" >&2
pane="${HERDR_PANE_ID:-}"
ws="${HERDR_WORKSPACE_ID:-}"
if [ -z "$pane" ]; then
  pane=$(h pane list ${ws:+--workspace "$ws"} | field pane_id)
fi
[ -n "$pane" ] || { echo "no pane to split from" >&2; exit 1; }
cwd=$(pane_cwd "$pane"); [ -n "$cwd" ] || cwd=$(workspace_cwd "$ws"); [ -n "$cwd" ] || cwd="$PWD"
before=$(h pane list ${ws:+--workspace "$ws"} | grep -o '"pane_id":"[^"]*"' | sort -u)
h pane split "$pane" --direction right --cwd "$cwd" --focus >/dev/null
after=$(h pane list ${ws:+--workspace "$ws"} | grep -o '"pane_id":"[^"]*"' | sort -u)
new=$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | head -n 1 | cut -d'"' -f4)
[ -n "$new" ] || { echo "could not find the new pane" >&2; exit 1; }
case "$agent" in
  claude) h pane run "$new" "$TERMAXA wrap -- claude" ;;
  codex)  h pane run "$new" "$TERMAXA init --codex >/dev/null 2>&1; codex" ;;
  *)      h pane run "$new" "$TERMAXA wrap -- $agent" ;;
esac
h pane rename "$new" "termaxa · $agent" >/dev/null 2>&1 || true
