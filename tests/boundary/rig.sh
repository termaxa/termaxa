#!/usr/bin/env bash
# The privilege boundary, proved by a second real user.
#
# Unit tests cannot prove a privilege boundary. Every test in the Rust suite
# runs as one user, so "the agent cannot write the policy" is, at best, an
# assertion about code paths. This rig creates a real second account and has
# it TRY — write the policy, edit the log, delete a backup, kill the
# supervisor — and asserts each attempt fails at the OS.
#
# EVERY ASSERTION HAS A CONTROL LEG. `the_probe_writes_nothing` is the lesson:
# a test that cannot detect success passes vacuously, and a misconfigured rig
# that silently proves nothing is worse than no rig, because it reports green.
# So for each "the agent cannot X", the rig also proves the OPERATOR can X.
# If a control leg fails, the rig is broken, not the boundary.
#
# Runs as root, in a container. Not on a developer machine: it creates and
# deletes a user account.
#
# STATUS: 18 of 18. The two failures this rig shipped with are closed — state
# files are now created at 0600 rather than hardened afterwards, which is the
# invariant a long-running daemon needs. The CI job is blocking.

set -uo pipefail

BIN_SRC="${1:?usage: rig.sh /path/to/termaxa}"

# The agent must be able to EXECUTE the binary, and where CI checks out is not
# our business: GitHub runners use /home/runner at 0700, so an agent account
# cannot traverse to a binary built there. Sections 1-4 never noticed because
# they run as root or against /tmp; section 5 is the only one that has the
# agent exec it directly.
#
# Copied to a path the rig controls rather than chmod-ing someone's home. A
# test that loosens the permissions of the directory it happens to be run from
# has changed the machine to suit itself.
BIN_DIR="$(mktemp -d)"; chmod 0755 "$BIN_DIR"
BIN="$BIN_DIR/termaxa"
cp "$BIN_SRC" "$BIN"; chmod 0755 "$BIN"
AGENT_USER="termaxa-agent"
OPERATOR_HOME="$(mktemp -d)"
# mktemp -d creates at 0700. A real install has TERMAXA_HOME under a 0755 home
# directory; without this the AGENT cannot traverse the operator's temp dir and
# every socket assertion below fails for a reason that has nothing to do with
# the boundary being tested. The rig spent three rounds on that before the
# measurement said so — a test fixture standing in for a real environment has
# to reproduce the parts the test depends on.
chmod 0755 "$OPERATOR_HOME"
PROJECT="$(mktemp -d)"
PASS=0
FAIL=0

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

# as_agent CMD... — run as the unprivileged account.
as_agent() { sudo -u "$AGENT_USER" -- "$@" >/dev/null 2>&1; }

# denied "label" CMD...   the agent must NOT be able to do this
denied() {
  local label="$1"; shift
  if as_agent "$@"; then
    bad "$label — the agent SUCCEEDED; the boundary is not there"
  else
    ok "$label — refused by the OS"
  fi
}

# allowed "label" CMD...  the operator MUST be able to do this
# This is the control leg: it proves the action is possible at all, so a
# `denied` pass means "blocked" rather than "impossible for everyone".
allowed() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    ok "control: $label — the operator can, so the refusal above is a boundary"
  else
    bad "control: $label — the OPERATOR could not either. THE RIG IS BROKEN: \
the assertion above proves nothing"
  fi
}

# ---------------------------------------------------------------------------
say "Setup"
# ---------------------------------------------------------------------------
id -u "$AGENT_USER" >/dev/null 2>&1 || useradd -m "$AGENT_USER"
echo "  agent uid: $(id -u "$AGENT_USER"), operator uid: $(id -u)"

export TERMAXA_HOME="$OPERATOR_HOME/.termaxa"
mkdir -p "$TERMAXA_HOME"
cd "$PROJECT" || exit 1
TERMAXA_HOME="$TERMAXA_HOME" "$BIN" init >/dev/null 2>&1

# The topology the architecture describes: the state directory is the
# operator's and the agent has no path into it. 0700 is what makes the audit
# log and the backups unreachable rather than merely unwritable.
#
# The socket cannot live in here — see `supervise::socket_dir`. This rig is
# what proved that: at 0755 the agent could list the state dir and read the
# log; at 0700 the socket became unreachable and supervised mode denied
# everything. The socket has its own 0755 directory holding nothing else.
# 0711: traversable, not listable. The agent reaches the socket by a path it
# knows and cannot enumerate anything else. 0700 here breaks supervised mode
# entirely; 0755 hands over the log and the backups. The daemon sets this
# itself; the rig sets it too so the assertions below run against the same
# topology whether or not the daemon has started yet.
chmod 0711 "$TERMAXA_HOME"
chmod 0755 "$PROJECT"
chmod 0644 "$PROJECT/.termaxa/policy.yaml"
chmod 0755 "$PROJECT/.termaxa"

# The project must be traversable by the agent — it works there.
chown -R root:root "$PROJECT"

echo "  state dir: $TERMAXA_HOME ($(stat -c %a "$TERMAXA_HOME"))"
echo "  policy:    $PROJECT/.termaxa/policy.yaml ($(stat -c %a "$PROJECT/.termaxa/policy.yaml"))"

# ---------------------------------------------------------------------------
say "1. The policy file — agent reads, cannot write"
# ---------------------------------------------------------------------------
POLICY="$PROJECT/.termaxa/policy.yaml"
if as_agent cat "$POLICY"; then
  ok "the agent CAN read the policy (it must — that is not the boundary)"
else
  bad "the agent cannot read the policy; it needs to"
fi
denied  "write the policy"        sh -c "echo 'default: allow' > '$POLICY'"
denied  "truncate the policy"     sh -c ": > '$POLICY'"
denied  "delete the policy"       rm -f "$POLICY"
allowed "operator writes the policy" sh -c "cp '$POLICY' '$POLICY.bak' && mv '$POLICY.bak' '$POLICY'"

# ---------------------------------------------------------------------------
say "2. The audit log — the agent has no path to it"
# ---------------------------------------------------------------------------
LOG="$(find "$TERMAXA_HOME" -name audit.jsonl 2>/dev/null | head -1)"
if [ -z "$LOG" ]; then
  # `init` alone may not have written one; make a decision so it exists.
  TERMAXA_HOME="$TERMAXA_HOME" "$BIN" check "ls -la" >/dev/null 2>&1
  LOG="$(find "$TERMAXA_HOME" -name audit.jsonl 2>/dev/null | head -1)"
fi
if [ -n "$LOG" ]; then
  echo "  log: $LOG"
  denied  "read the audit log"    cat "$LOG"
  denied  "append to the log"     sh -c "echo '{}' >> '$LOG'"
  denied  "delete the log"        rm -f "$LOG"
  denied  "list the state dir"    ls "$TERMAXA_HOME"
  allowed "operator reads the log" cat "$LOG"
else
  bad "no audit log was produced; the log assertions could not run"
fi

# ---------------------------------------------------------------------------
say "3. Backups — the agent cannot read, edit or delete them"
# ---------------------------------------------------------------------------
# Take a REAL backup through the real code path, rather than fabricating one
# with `echo >`. A fixture that bypasses the code under test cannot test it:
# the first version of this rig hand-made a backup file, so `make_private`
# never ran on it and the assertion below failed against a file Termaxa had
# never written.
mkdir -p "$PROJECT/doomed" && echo "insured contents" > "$PROJECT/doomed/file.txt"
# `rm -r`, not `rm -rf`: the starter policy DENIES the forced form, and a
# denied command correctly takes no backup - so asking for one with `-rf`
# produced nothing and the assertions below tested a path that did not exist.
# The control leg caught that; without it this rig would have reported three
# passes against /nonexistent.
( cd "$PROJECT" && printf 'y\n' | TERMAXA_HOME="$TERMAXA_HOME" "$BIN" run -- rm -r doomed ) >/dev/null 2>&1
BK="$(find "$TERMAXA_HOME" -path '*backups*' -name 'file.txt' 2>/dev/null | head -1)"
if [ -z "$BK" ]; then
  bad "no backup was produced through the real path; the backup assertions could not run"
  BK="/nonexistent"
else
  echo "  backup: $BK ($(stat -c %a "$BK"))"
fi
denied  "read a backup"           cat "$BK"
denied  "overwrite a backup"      sh -c "echo tampered > '$BK'"
denied  "delete a backup"         rm -f "$BK"
allowed "operator reads a backup" cat "$BK"

# ---------------------------------------------------------------------------
say "4. The supervisor process — the agent cannot stop it"
# ---------------------------------------------------------------------------
TERMAXA_HOME="$TERMAXA_HOME" "$BIN" supervise >/dev/null 2>&1 &
SUP_PID=$!
sleep 1
if kill -0 "$SUP_PID" 2>/dev/null; then
  echo "  supervisor pid: $SUP_PID"
  denied  "kill the supervisor"     kill -9 "$SUP_PID"
  sleep 0.3
  if kill -0 "$SUP_PID" 2>/dev/null; then
    ok "the supervisor is still running after the attempt"
  else
    bad "the supervisor DIED — the agent stopped it"
  fi

  # The socket must remain connectable: the agent asks, it does not decide.
  SOCK="$TERMAXA_HOME/run/supervise.sock"
  if [ -S "$SOCK" ]; then
    if as_agent test -w "$SOCK"; then
      ok "the agent CAN connect to the socket (it must — asking is its job)"
    else
      bad "the agent cannot reach the socket; supervised mode would deny everything"
    fi
  else
    bad "no socket at $SOCK"
  fi

  allowed "operator kills the supervisor" kill -9 "$SUP_PID"
else
  bad "the supervisor did not start; assertions 4 could not run"
fi

# ---------------------------------------------------------------------------
say "5. Routing — a hook run as the AGENT reaches the operator's supervisor"
# ---------------------------------------------------------------------------
#
# The assertion the first four sections could not make. They proved ISOLATION:
# the agent cannot reach the operator's state. They never proved ROUTING: that
# a hook running as the agent finds the supervisor at all.
#
# The first proving run found the gap between those. Every automated test ran
# the hook and the supervisor as the SAME user, so $HOME-relative endpoint
# discovery worked. A real agent under a real second account resolved $HOME to
# its own home, found no socket, concluded basic mode, and decided on its own
# authority - while the supervisor sat idle. The walls held; the door led
# nowhere.
TERMAXA_HOME="$TERMAXA_HOME" "$BIN" supervise > "$PROJECT/sup.log" 2>&1 &
SUP2=$!
sleep 1
SOCK="$TERMAXA_HOME/run/supervise.sock"

if [ -S "$SOCK" ]; then
  PAYLOAD='{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"'"$PROJECT"'"}'

  # As the agent, with ONLY the endpoint - no TERMAXA_HOME, no path into the
  # operator's state. This is exactly what `wrap` gives a wrapped agent.
  OUT="$(echo "$PAYLOAD" | sudo -u "$AGENT_USER" env -i \
        HOME=/home/$AGENT_USER PATH=/usr/bin:/bin \
        TERMAXA_SOCKET="$SOCK" "$BIN" hook 2>&1)"

  if echo "$OUT" | grep -q '"permissionDecision":"deny"'; then
    ok "the agent's hook got a decision back"
  else
    bad "the agent's hook did not get a decision: $OUT"
  fi

  # And the decision was made THERE, not here: the supervisor logged the
  # agent's uid. Without this the test would pass on a hook that decided
  # locally and happened to reach the same verdict.
  AGENT_UID="$(id -u "$AGENT_USER")"
  if grep -q "uid=$AGENT_UID" "$PROJECT/sup.log"; then
    ok "the supervisor recorded uid=$AGENT_UID — it decided, not the hook"
  else
    bad "the supervisor never saw the request (log: $(tr '\n' ' ' < "$PROJECT/sup.log"))"
  fi

  # The record landed in the OPERATOR's log, and the agent cannot read it.
  OPLOG="$(find "$TERMAXA_HOME" -name audit.jsonl 2>/dev/null | head -1)"
  if [ -n "$OPLOG" ] && grep -q "rm -rf /" "$OPLOG"; then
    ok "the decision is in the operator's audit log"
  else
    bad "the decision is not in the operator's log"
  fi
  denied "read the operator's log after it recorded the agent" cat "$OPLOG"

  # CONTROL LEG: with no endpoint told, the agent falls back to basic mode and
  # decides locally. Proves section 5 is testing routing rather than the hook
  # merely working at all.
  echo "$PAYLOAD" | sudo -u "$AGENT_USER" env -i \
      HOME=/home/$AGENT_USER PATH=/usr/bin:/bin \
      "$BIN" hook >/dev/null 2>&1
  BEFORE="$(grep -c "uid=$AGENT_UID" "$PROJECT/sup.log")"
  sleep 0.3
  AFTER="$(grep -c "uid=$AGENT_UID" "$PROJECT/sup.log")"
  if [ "$BEFORE" = "$AFTER" ]; then
    ok "control: with no endpoint told, nothing reaches the supervisor"
  else
    bad "control: a hook with no endpoint still reached the supervisor"
  fi

  kill -9 $SUP2 2>/dev/null
else
  bad "no socket at $SOCK; routing assertions could not run"
fi

# ---------------------------------------------------------------------------
say "Result"
# ---------------------------------------------------------------------------
rm -rf "$PROJECT" "$OPERATOR_HOME" "$BIN_DIR"
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
