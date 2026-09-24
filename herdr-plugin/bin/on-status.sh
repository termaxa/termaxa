#!/usr/bin/env bash
# Event hook for pane.agent_status_changed. When a pane settles, read the
# last entry of the Termaxa record in that pane's project; if it is a
# refusal from the last 90 seconds, put the reason on the pane and open the
# record. Nothing else: a pane whose record has nothing recent stays exactly
# as Herdr showed it.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
json="${HERDR_PLUGIN_EVENT_JSON:-}"
[ -n "$json" ] || exit 0
status=$(printf '%s' "$json" | field agent_status)
# Under `wrap` a refusal does not block the agent: it reports the refusal
# and finishes its turn, so Herdr sees `idle` or `done`, not `blocked`
# (measured in a live Herdr 0.9.1 session, Sep 20, 2026: the hook fired on
# four transitions, none of them blocked, and the pane ended `idle`). What
# matters is not which state it landed in but that the gate refused
# something a moment ago, so any settled state counts and the record
# decides.
case "$status" in blocked|idle|done) ;; *) exit 0 ;; esac
pane=$(printf '%s' "$json" | field pane_id)
[ -n "$pane" ] || exit 0
cwd=$(pane_cwd "$pane"); [ -n "$cwd" ] || exit 0
proj=$(project_of "$cwd")
[ -d "$proj/.termaxa" ] || exit 0
have_termaxa || { echo "termaxa not found on PATH or in the usual places" >&2; exit 0; }
have_herdr || { echo "herdr not found: HERDR_BIN_PATH unset and not on PATH" >&2; exit 1; }
last=$(cd "$proj" && t log -n 1 --json 2>/dev/null | tail -n 1)
[ -n "$last" ] || exit 0
decision=$(printf '%s' "$last" | field decision)
case "$decision" in deny|ask) ;; *) exit 0 ;; esac
ts_ms=$(printf '%s' "$last" | sed -n 's/.*"ts_ms":\([0-9]*\).*/\1/p')
now_ms=$(( $(date +%s) * 1000 ))
[ -n "$ts_ms" ] && [ $(( now_ms - ts_ms )) -le 90000 ] || exit 0
# Once per entry: report-agent itself changes the pane's state.
mark="${XDG_STATE_HOME:-$HOME/.local/state}/termaxa-herdr"
mkdir -p "$mark"
[ "$(cat "$mark/$pane" 2>/dev/null)" = "$ts_ms" ] && exit 0
printf '%s' "$ts_ms" > "$mark/$pane"
reason=$(printf '%s' "$last" | field reason)
cmd=$(printf '%s' "$last" | field command)
label=$(h pane get "$pane" 2>/dev/null | field agent); [ -n "$label" ] || label="agent"
# Keep the state Herdr detected and put the reason beside it: a refusal the
# agent already reported is not the agent waiting for input. Only a refusal
# while the agent is genuinely blocked stays blocked.
state="$status"
case "$state" in blocked) ;; *) state="idle" ;; esac
h pane report-agent "$pane" --source termaxa --agent "$label" --state "$state" \
  --message "termaxa ${decision}: ${cmd:0:60} — ${reason:0:140}" >/dev/null \
  || echo "report-agent failed for $pane" >&2
h pane report-metadata "$pane" --source termaxa \
  --state-label "${state}=termaxa ${decision}" >/dev/null \
  || echo "report-metadata failed for $pane" >&2
# The record, as an overlay, so "why did it stop?" is one glance away.
h plugin pane open --plugin termaxa.gate --entrypoint record \
  --placement split --target-pane "$pane" --direction down --cwd "$proj" >/dev/null \
  || echo "pane open failed for $pane" >&2
echo "termaxa ${decision} reported on $pane: ${cmd:0:60}"
