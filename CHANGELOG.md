# Changelog

All notable changes to Termaxa. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0, so minor versions may include breaking changes to the policy schema or CLI.

## [0.11.2] — Zero-setup `check`
- `termaxa check` now works with no project setup: when no `.termaxa/policy.yaml`
  exists it evaluates against the built-in starter policy (read-only "demo mode"),
  so `cargo install termaxa && termaxa check "rm -rf /"` works immediately.
  `run` and `hook` still require an explicit project policy — enforcement stays
  deliberate.
  
## [0.11.1] — Classifier: delete indirection
- The intent classifier now recognizes deletes hidden behind command
  indirection: `find -exec/-execdir <rm>`, `find -delete`, `xargs rm`,
  `unlink`, and `shred -u`. Closes a bypass found in live agent testing
  where `find . -exec rm -rf {} +` slipped past the circuit breaker.

## [0.11.0] — Session circuit breaker
- When the same destructive intent (file delete, DB destroy, git force-op,
  infra destroy) is asked or denied twice in one agent session, further
  variants are automatically DENIED — closing the retry-with-different-syntax
  gap found in live Cursor testing. Configurable via `circuit_breaker:` in
  policy.yaml (enabled by default, threshold 2).
- Starter policy now DENIES bulk deletes by default (Unix, PowerShell, cmd
  forms): with auto-approving agent UIs, `ask` silently degrades to `allow`.
- Audit entries carry an `intent` classification (backward compatible;
  old log lines parse unchanged).

## v0.10.5 — 2026-07-09
- Formatting cleanup (`cargo fmt`); no functional changes from v0.10.4.

## v0.10.4 — 2026-07-08
- Fixed audit-path hash mismatch that caused empty audit logs.
- Documented honest enforcement limits; removed internal build notes.
- Multi-agent hook support (Cursor, Codex, Copilot dialects) and
  `termaxa init` flags landed in this series.
- Note: version numbers v0.10.0–v0.10.3 were internal iteration
  numbers and were never published; v0.10.4 is the first release
  of the 0.10 series.
  
## [0.9.0] — Launch

### Added
- **Terraform/OpenTofu previews.** `terraform apply|destroy` (and `tofu`) run `terraform plan` first and surface `+add ~change -destroy` counts, leading with destroyed resources. Local `terraform.tfstate` is backed up before apply.
- **Execution Report** (`termaxa report`) — session summary composed from the audit trail: commands by decision, blocked list, database/infra impact (from persisted preview summaries), backups with rollback availability, and a transparent risk score (`deny×3 + escalation×2 + ask×1`). `--session`, `--all`, `--md`.
- Preview summaries now persist on audit entries, so reports state impact as recorded fact.
- `termaxa paths` — show where policy (in-repo) and state (`~/.termaxa`) live.

### Fixed
- **Broken-pipe panic**: `termaxa report --md | head` (and any piped output) now exits cleanly on Unix instead of panicking.
- `--help` leads with a clear description and worked examples.

## [0.8.0] — Home-directory state
- Logs and backups moved from in-repo `.termaxa/` to `~/.termaxa/projects/<name>-<hash>/`, so a `git reset --hard` can no longer destroy the audit trail. Automatic one-time migration of legacy in-repo state, including path-rewriting inside the backup manifest. Policy stays in-repo as reviewable policy-as-code.

## [0.7.0] — Shell-aware evaluation
- Compound commands (`&&`, `||`, `;`, `|`) are split and judged per segment; the most dangerous segment governs. Closes a bypass where `git status && <anything>` rode a `git status*` allow rule (found by the first live Claude Code session; now a named regression test). `$(...)`/backtick command substitution escalates to a human.

## [0.6.1] — Loss-aware force-push previews
- Force pushes now show what the remote will **lose** (`HEAD..@{u}`), not just what it gains. Found in live use: the preview previously said "nothing to push" while a force push destroyed a commit.

## [0.6.0] — Insurance engine
- Automatic backups before destructive operations: git remote-ref pinning, mode-aware `pg_dump` (CASCADE pulls in FK dependents), file copies for `rm`. `termaxa backups` / `termaxa rollback <id>`.

## [0.5.0] — Operability
- Session tracking from hook events; `termaxa log` filters (`--decision`, `--source`, `--json`); `termaxa stats`; `termaxa notify --test`.

## [0.4.0] — Notifications
- Slack-compatible webhook on deny/ask, fire-and-forget (never blocks a decision). Log entries show approval + exit code.

## [0.3.0] — Postgres impact analysis
- Static (`NO WHERE CLAUSE` detection) and live (row estimates from `pg_class.reltuples`, FK dependents) analysis for `DROP`/`TRUNCATE`/`DELETE`, reusing the intercepted command's own connection.

## [0.2.0] — Git previews
- `git push` previews: commits and diffstat, with new-branch handling.

## [0.1.0] — Core
- Policy engine (YAML, first-match-wins, wildcard, normalized matching), Claude Code PreToolUse hook, context signals with one-way escalation, append-only JSONL audit, `init`/`check`/`run`/`log`.
