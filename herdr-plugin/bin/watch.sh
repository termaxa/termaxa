#!/usr/bin/env bash
# Startup watcher: the record itself is the event source.
#
# `pane.agent_status_changed` was the obvious hook and it is not enough.
# Measured Sep 20, 2026 in a live Herdr 0.9.1 session: under `wrap` a
# refusal does not change the agent's detected status at all — Claude Code
# reports the refusal and keeps its turn, or opens its own menu and waits —
# so three refused deletes produced no status event and the hook never ran.
# What does happen, every time and immediately, is a line in the Termaxa
# record. So this follows the record and reacts to the refusal itself.
#
# One watcher per workspace project, started when Herdr starts and
# refreshed as workspaces come and go. Each `termaxa log --follow` is a
# child; they are killed when this exits.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

have_herdr || { echo "herdr not found: HERDR_BIN_PATH unset and not on PATH" >&2; exit 1; }
have_termaxa || { echo "termaxa not found; the watcher has nothing to follow" >&2; exit 0; }

# One follower per project, and only one watcher per machine: a second
# copy of either would report the same refusal twice (seen in testing when
# `scan` re-ran and started a second follower).
RUN="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/termaxa-herdr-$(id -u)"
mkdir -p "$RUN" 2>/dev/null
# The newer watcher wins. `herdr server stop` does not kill the processes
# Herdr spawned, so the previous session's watcher survives as an orphan
# holding the lock and running the script it was started with (measured
# Sep 24, 2026: the fresh one exited with "already running"). The pid in
# the lock is ours; it is told to stop, and the lock is taken over.
if ! mkdir "$RUN/watcher.lock" 2>/dev/null; then
  old=$(cat "$RUN/watcher.pid" 2>/dev/null)
  if [ -n "$old" ] && [ "$old" != "$$" ] && kill -0 "$old" 2>/dev/null; then
    echo "replacing the previous termaxa watcher (pid $old)"
    kill "$old" 2>/dev/null
    sleep 1
    kill -9 "$old" 2>/dev/null || true
  fi
  rm -rf "$RUN/watcher.lock" 2>/dev/null
  mkdir "$RUN/watcher.lock" 2>/dev/null || { echo "cannot take the watcher lock" >&2; exit 0; }
fi
printf '%s' "$$" > "$RUN/watcher.pid"

declare -A WATCHED=()
CHILDREN=()
cleanup() {
  for p in "${CHILDREN[@]:-}"; do kill "$p" 2>/dev/null; done
  rm -rf "$RUN/watcher.lock" "$RUN/watcher.pid" 2>/dev/null
}
trap cleanup EXIT INT TERM

# Follow one project's record and report every refusal on the pane that
# caused it. The record names the agent's cwd, so the pane is the one whose
# cwd matches, and its own state is left alone: only the label and the
# message say what the gate did.
follow_project() { # follow_project PROJECT_DIR
  local proj="$1"
  local since=$(( $(date +%s) * 1000 ))
  (
    cd "$proj" || exit 0
    t log --follow -n 0 --json 2>/dev/null | while IFS= read -r line; do
      case "$line" in *'"decision":"deny"'*|*'"decision":"ask"'*) ;; *) continue ;; esac
      # `--follow -n 0` prints only new entries, but a restart mid-second
      # could replay one: ignore anything older than this follower.
      local ts_ms
      ts_ms=$(printf '%s' "$line" | sed -n 's/.*"ts_ms":\([0-9]*\).*/\1/p')
      [ -n "$ts_ms" ] && [ "$ts_ms" -ge "$since" ] || continue
      local decision cmd reason cwd pane ws
      decision=$(printf '%s' "$line" | field decision)
      cmd=$(printf '%s' "$line" | field command)
      reason=$(printf '%s' "$line" | field reason)
      cwd=$(printf '%s' "$line" | field cwd)
      [ -n "$cwd" ] || cwd="$proj"
      pane=$(pane_for_cwd "$cwd")
      [ -n "$pane" ] || continue
      # `--state-label` is STATUS=TEXT and STATUS must be one of Herdr's own
      # states (`unknown state label: termaxa`, measured Sep 20, 2026): the
      # text goes on the state the pane is in.
      local st; st=$(state_of "$pane")
      h pane report-metadata "$pane" --source termaxa \
        --state-label "${st}=termaxa ${decision}" >/dev/null \
        || echo "report-metadata failed for $pane" >&2
      h pane report-agent "$pane" --source termaxa --agent "$(agent_of "$pane")" \
        --state "$(state_of "$pane")" \
        --message "termaxa ${decision}: ${cmd:0:60} — ${reason:0:140}" >/dev/null \
        || echo "report-agent failed for $pane" >&2
      # An overlay targets the ACTIVE pane and refuses --workspace; a split
      # targets an existing pane by --target-pane. The refusal happened in
      # `$pane`, so split beside it and let the record land next to the
      # agent that caused it (measured Sep 20, 2026: the overlay form was
      # refused with "overlay and popup plugin panes target the active
      # pane").
      # `--cwd`: a plugin pane starts in the plugin root otherwise.
      h plugin pane open --plugin termaxa.gate --entrypoint record \
        --placement split --target-pane "$pane" --direction down --cwd "$proj" >/dev/null \
        || echo "pane open failed for $pane" >&2
      echo "termaxa ${decision} on ${pane}: ${cmd:0:60}"
    done
  ) &
  CHILDREN+=($!)
}

# The pane whose foreground cwd is inside the given directory; the agent's
# own pane when there is one, else any.
pane_for_cwd() { # pane_for_cwd DIR
  local dir="$1" best="" any=""
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    local json c
    json=$(h pane get "$p" 2>/dev/null) || continue
    c=$(printf '%s' "$json" | field foreground_cwd)
    [ -n "$c" ] || c=$(printf '%s' "$json" | field cwd)
    case "$c" in "$dir"|"$dir"/*) ;; *) continue ;; esac
    any="$p"
    printf '%s' "$json" | grep -q '"agent":' && { best="$p"; break; }
  done < <(all_pane_ids)
  printf '%s' "${best:-$any}"
}
all_pane_ids() { h pane list 2>/dev/null | grep -o '"pane_id":"[^"]*"' | cut -d'"' -f4 | sort -u; }
agent_of() { h pane get "$1" 2>/dev/null | field agent | grep . || echo agent; }
state_of() { local s; s=$(h pane get "$1" 2>/dev/null | field agent_status); case "$s" in blocked) echo blocked ;; *) echo idle ;; esac; }

# Every workspace's project, refreshed: a workspace opened later is picked
# up within the poll interval, and a project already followed is not
# followed twice.
scan() {
  local ws cwd proj
  while IFS= read -r ws; do
    [ -n "$ws" ] || continue
    cwd=$(workspace_cwd "$ws")
    [ -n "$cwd" ] || continue
    proj=$(project_of "$cwd")
    [ -d "$proj/.termaxa" ] || continue
    [ -n "${WATCHED[$proj]:-}" ] && continue
    WATCHED[$proj]=1
    echo "watching $proj"
    follow_project "$proj"
  done < <(h workspace list 2>/dev/null | grep -o '"workspace_id":"[^"]*"' | cut -d'"' -f4 | sort -u)
}

echo "termaxa watcher started"
misses=0
while :; do
  # A watcher whose Herdr has gone exits, so a stopped server does not
  # leave a follower behind; three missed polls, thirty seconds, is the
  # allowance for a restart.
  if h workspace list >/dev/null 2>&1; then
    misses=0
    scan
  else
    misses=$((misses + 1))
    [ "$misses" -ge 3 ] && { echo "herdr is gone; the watcher exits"; exit 0; }
  fi
  sleep 10
done
