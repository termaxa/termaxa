#!/usr/bin/env bash
# Shared helpers.
#
# Herdr runs a plugin's commands with `HERDR_BIN_PATH` pointing at its own
# binary, and does NOT add the user's `~/.local/bin` to PATH. Measured Sep
# 20, 2026 in a live session: with the runtime's PATH, bare `herdr` and
# bare `termaxa` are both "command not found", so a hook that calls them by
# name does nothing and says nothing. Everything here resolves both
# explicitly.
HERDR="${HERDR_BIN_PATH:-}"
[ -x "$HERDR" ] || HERDR=$(command -v herdr 2>/dev/null) || true
[ -x "$HERDR" ] || for c in "$HOME/.local/bin/herdr" /usr/local/bin/herdr /opt/homebrew/bin/herdr; do
  [ -x "$c" ] && { HERDR="$c"; break; }
done
TERMAXA=$(command -v termaxa 2>/dev/null) || true
[ -x "$TERMAXA" ] || for c in "$HOME/.local/bin/termaxa" /usr/local/bin/termaxa /opt/homebrew/bin/termaxa "$HOME/.cargo/bin/termaxa"; do
  [ -x "$c" ] && { TERMAXA="$c"; break; }
done

have_herdr() { [ -n "$HERDR" ] && [ -x "$HERDR" ]; }
have_termaxa() { [ -n "$TERMAXA" ] && [ -x "$TERMAXA" ]; }
h() { "$HERDR" "$@"; }        # herdr, resolved
t() { "$TERMAXA" "$@"; }      # termaxa, resolved

field() { # field NAME <<< JSON  → first value of "NAME":"…"
  sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -n 1
}
pane_cwd() { # pane_cwd PANE_ID → the pane's cwd (foreground first), or empty
  local json; json=$(h pane get "$1" 2>/dev/null) || return 1
  local cwd; cwd=$(printf '%s' "$json" | field foreground_cwd)
  [ -n "$cwd" ] || cwd=$(printf '%s' "$json" | field cwd)
  printf '%s' "$cwd"
}
workspace_cwd() { # workspace_cwd WS_ID → the workspace's cwd, or empty
  h workspace get "$1" 2>/dev/null | field cwd
}
project_of() { # project_of DIR → nearest ancestor with .termaxa/, or DIR
  local d="$1"
  while [ -n "$d" ] && [ "$d" != "/" ]; do
    [ -d "$d/.termaxa" ] && { printf '%s' "$d"; return; }
    d=$(dirname "$d")
  done
  printf '%s' "$1"
}
