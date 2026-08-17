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
# CURRENT STATUS: 16 of 18 pass. Two fail, and they are REAL GAPS, not rig
# bugs: an agent can `cat` the audit log and a backup by full path. The
# supervisor hardens directories when it starts, but files the daemon writes
# AFTERWARDS are created with the default mode, so anything appended or copied
# during a session is readable by anyone who knows the path — and the paths are
# documented.
#
# Left failing on purpose. A rig tuned until it is green reports what its
# author wanted; a rig left red reports what is true, and these two are exactly
# what v0.17 must close before it ships. The fix belongs in `audit.rs` and
# `backup.rs` — create at 0600 rather than harden after — with this rig as the
# acceptance test.

set -uo pipefail

BIN="${1:?usage: rig.sh /path/to/termaxa}"
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
mkdir -p "$TERMAXA_HOME/backups/b-rig"
echo "insured contents" > "$TERMAXA_HOME/backups/b-rig/file.txt"
BK="$TERMAXA_HOME/backups/b-rig/file.txt"
denied  "read a backup"           cat "$BK"
denied  "overwrite a backup"      sh -c "echo tampered > '$BK'"
denied  "delete a backup"         rm -rf "$TERMAXA_HOME/backups/b-rig"
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
say "Result"
# ---------------------------------------------------------------------------
rm -rf "$PROJECT" "$OPERATOR_HOME"
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
