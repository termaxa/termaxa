# Termaxa — Roadmap

## Shipped (v0.1 → v0.7.0)

| Release | Delivered | Proven by |
|---|---|---|
| **v0.1** | Policy engine (YAML, first-match-wins, wildcard, normalized matching), Claude Code PreToolUse hook, context signals with one-way escalation, append-only JSONL audit, `init/check/run/log`, scriptable exit codes (0/3/4) | 4 unit tests; live checks on Windows |
| **v0.1.1** | `check` writes audit entries | first user code modification |
| **v0.2** | Git push previews (commits + diffstat) on check/run/hook; "compared to what?" case analysis incl. new-branch | real local remote (bare repo) |
| **v0.3** | Postgres impact analysis: SQL extraction/parsing, static tier (`NO WHERE CLAUSE`), live tier (reltuples estimates, FK dependents) via connection-reuse; blast radius in hook deny reasons | PostgreSQL 16, 410k-row FK schema |
| **v0.4** | Slack-compatible webhook notifications (fire-and-forget, 3s timeout, never blocks — 51 ms with dead endpoint); log outcome display | live webhook.site delivery |
| **v0.5** | Session tracking from hook events, `log` filters + `--json`, `termaxa stats`, `notify --test` (loud probe) | backward-compat parse of pre-v0.5 logs |
| **v0.6** | Insurance engine: git remote-ref pinning, mode-aware `pg_dump` (+ CASCADE dependents), `rm` file copies; `backups` / `rollback <id>`; `insurance:` preview line; `backup` audit field | 3 destroy→resurrect cycles incl. 410k rows; live Windows commit resurrection |
| **v0.6.1** | Force-push **loss** preview (`⚠ remote will LOSE n commit(s)`) — user-found blind spot; warning-clean build; README refresh | replay of the discovering scenario |
| **v0.7** | Shell-aware evaluation: quote-aware segment splitting, worst-segment-governs (+ explicit-rule tie-break), `$(...)`/backtick escalation, per-segment previews/backups — closes the live-agent bypass | 16 tests incl. field-report regression; live allow+deny verification |

**Milestone**: live Claude Code session governed end-to-end — hook fired, reason surfaced in the agent's permission prompt, first AI-written audit entries (`hook 2 / sessions 1`).

## Vision-doc scorecard

| Engine (original doc) | Status |
|---|---|
| Runtime | ✅ hook + `termaxa run` (cooperative; OS-sandbox explicitly out of scope) |
| Policy | ✅ + context engine + shell-aware segments |
| Simulation | ✅ git (gain **and loss**) + postgres (blast radius); terraform pending |
| Approval | ✅ 3 tiers + notifications; remote/interactive approval pending (Cloud) |
| Audit | ✅ + sessions, filters, stats, outcomes; replay pending |
| — (not in doc) | ✅ Insurance/rollback engine |

## Next — ordered

1. **v0.8 — Home-directory state** (`~/.termaxa/` for logs + backups, per-project keying; policy stays in-repo as reviewable policy-as-code). Closes the "git ate my audit log" failure class *by construction*. Small build, big safety.
2. **Terraform preview plugin** — wrap `terraform plan`, parse add/change/destroy counts into the approval prompt. One more branch in `preview.rs`.
3. **Plugin registry** (`termaxa add <tool>`) — per-tool bundles: policy fragment + preview + backup + risk model. The scaling story; refactor preview/backup dispatch into a trait.
4. **More harnesses** — Cursor, OpenHands adapters; PATH shims for non-agent terminal coverage ("no *accidental* bypass").
5. **Approval routing v2** — risk tiers → channels; interactive Slack approve/deny (needs an inbound callback — first genuinely Cloud-shaped feature).
6. **Replay & fleet** — reconstruct a session's command timeline from audit (`termaxa replay <session>`); central log shipping; team policies; dashboards (Termaxa Cloud).

## Known gaps & honest limits

- Cooperative interception only: raw shell outside hook/`run` is ungoverned (OS sandboxing is a complementary layer, not planned here).
- Shell analysis covers operators + substitution *detection*; subshells `( )`, env-var-expanded commands, and exotic quoting are judged conservatively, not deeply.
- `rm` insurance keys on literal `rm` (PowerShell aliases differ); Windows path coverage for file backups untested.
- Notifications are one-way; no remote approval yet.
- Backup pruning/retention not implemented; manifests grow unbounded.
- Context heuristics have false positives by design (safe only because escalation is one-way).
