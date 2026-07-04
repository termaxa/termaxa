# Termaxa — Session Log

**One session, eight releases**: from a strategy document to a field-tested security gate for AI agents, written in Rust, verified live on Windows against real Claude Code.

- Repo: `C:\Users\User\code\termaxa` (source) — commit `2f09684`, 16 files, 3,021 lines, tags `v0.6.1`, `v0.7.0`
- Governed playground: `C:\Users\User\code\termaxa-demo` (+ bare remote `demo-origin.git`)
- Binary: `C:\Users\User\.cargo\bin\termaxa.exe` — currently **v0.7.0**

---

## Phase 0 — Environment (Windows)

```powershell
# Rust via rustup (https://win.rustup.rs/x86_64), option 1 = install VS C++ Build Tools
rustc --version    # 1.96.1
cargo --version
cargo new termaxa && cd termaxa && cargo run   # Hello, world! = toolchain proven
```

Windows adjustments learned along the way:
- Use PowerShell (or Git Bash), not cmd — quoting differs.
- `echo "x" > file` writes UTF-16 (git sees binary); use `Set-Content` / `Add-Content` for text files.
- Install binaries with `cargo install --path . --force` → lands on PATH via `.cargo\bin`.
- `-g` npm installs are global; the folder you *launch* a tool from is what binds it to a project.

## Phase 1 — v0.1 core (policy · hook · audit · CLI)

Files: `policy.rs` (Action enum, Rule/Policy via serde, wildcard matcher, first-match-wins, walk-up `.termaxa/` discovery), `context.rs` (branch/flags/prod/SQL signals; **one-way escalation** allow→ask only), `audit.rs` (append-only JSONL), `hook.rs` (Claude Code PreToolUse: JSON stdin → `permissionDecision` stdout; unknown input = silently step aside), `runner.rs` (`termaxa run --` with y/N), `init.rs` (scaffold, tool/agent detection, hook auto-install into `.claude\settings.json`), `main.rs` (clap).

```powershell
cargo test                     # 4 passed
cargo install --path .
cd <project> ; termaxa init --claude-code
termaxa check "git push --force origin main"    # deny + reason + context signals
termaxa run -- git status                        # gated execution
termaxa log
```

Key early fix: **case/whitespace normalization** — uppercase `DROP TABLE` sailed past a lowercase rule during testing; matcher now lowercases + collapses whitespace (regression test added).

**v0.1.1** — first user modification: `check` writes audit entries (`source: "check"`); `cargo install --path . --force` to refresh the installed binary.

## Phase 2 — v0.2.0 execution previews (git)

`preview.rs`: `generate(cmd) -> Option<Preview>` — plugin-shaped; previews are best-effort (`None` never blocks). Push preview answers "compared to what?": upstream → `@{u}..HEAD`; else `origin/<branch>`; else "entire branch is new". Shown in `check`, before y/N in `run`, and as a compact summary inside the hook reason.

Demo setup (local "GitHub"):
```powershell
git init --bare demo-origin.git
git clone demo-origin.git termaxa-demo   # or: git remote add origin <path>
# commit, push, commit again → termaxa check "git push origin main" shows commits + diffstat
```

## Phase 3 — v0.3.0 postgres impact analysis

`pg.rs` (~440 lines): quote-aware tokenizer → extract SQL from `psql -c` → hand-rolled parser for `DROP TABLE / TRUNCATE / DELETE FROM` → **two tiers**: static (no DB needed; flags `NO WHERE CLAUSE`) and live (row estimates from `pg_class.reltuples` — never `COUNT(*)`; FK dependents from `pg_constraint`). **Connection-reuse trick**: strip `-c <sql>` from the intercepted command, append our own read-only query — host/user/password env inherited verbatim.

Container verification against PostgreSQL 16, seeded schema (`users` 50k ← `orders` 240k, `sessions` 120k, `audit_log`; `standalone` 777):
```
DROP TABLE users → rows 50,000 · referenced by audit_log, orders, sessions ·
                   without CASCADE: this DROP will FAIL
```
Hook deny reason now carries blast radius back to the model. Policy tuned from audit evidence: `*delete from*` → ask, `*truncate *` → ask.

## Phase 4 — v0.4.0 notifications

`notify.rs` + optional `notify:` block in policy.yaml (`webhook:`, `on: [deny, ask]`). Fire-and-forget (3s timeout, errors swallowed): a dead Slack can never delay a decision (proved: deny with dead endpoint = 51 ms). Dependency cost noted: ureq's TLS stack took the crate count 66 → 117. Verified live end-to-end with webhook.site (🛑 payload received in browser). Log polish: entries show `→ approved, exit 0`.

## Phase 5 — v0.5.0 operability

- `session_id` captured from hook events → `[hook (e117cfe2)]` in logs. Backward compat via `#[serde(default)]` — old JSONL lines still parse.
- `termaxa log --decision deny --source hook --json`
- `termaxa stats` — totals, by source, escalations, sessions, top denied
- `termaxa notify --test` — the loud counterweight to fire-and-forget (born from a silent placeholder-URL failure earlier the same day). Verified both HTTP 200/exit 0 and refused/exit 1.

## Phase 6 — v0.6.x insurance engine

`backup.rs` (~360 lines): before destructive ops on `run`/`hook` (never deny), take a backup, record in `.termaxa/backups/manifest.jsonl`, stamp the audit entry.

| Threat | Insurance | Restore |
|---|---|---|
| `git push --force` | fetch + pin remote head to `termaxa/backup/<id>` branch | force-push the pinned sha back |
| `DROP/TRUNCATE/DELETE` | `pg_dump` (data-only if table survives; `--clean` for DROP); **CASCADE pulls FK dependents into the dump** | `psql -f` |
| `rm` | copy targets into `.termaxa/backups/<id>/` | copy back |

```powershell
termaxa backups
termaxa rollback b-1783006590625     # y/N gate — restores are writes too
```

Verified destroy→resurrect cycles: a remote commit (destroyed by force push, restored by id — **reproduced live on Windows**: `44510f1 sacrificial commit`); 410,000 rows across three tables (TRUNCATE CASCADE; the dump auto-covered dependents); deleted files.

Three bugs, three lessons:
1. `argv.join(" ")` destroyed quoting → backup parsed no table → **`shell_join` re-quotes**; token boundaries are information.
2. `--clean` dump couldn't restore a PK other tables reference → **dump mode per statement type**; restore semantics ≠ dump semantics.
3. `.termaxa/` committed in the demo repo → `git reset --hard` reverted policy (twice: restoring old tracked versions, and *deleting* files when resetting across the untracking boundary) → **runtime state doesn't belong in the repo it protects**.

**v0.6.1** — user-found blind spot: preview said "nothing to push" while a force push destroyed a commit. Gain (`@{u}..HEAD`) and loss (`HEAD..@{u}`) are different directions; force pushes now show `⚠ remote will LOSE n commit(s)` with the doomed shas. Verified on the machine that found it.

## Phase 7 — Live Claude Code test

```powershell
npm install -g @anthropic-ai/claude-code
cd termaxa-demo ; claude          # trust folder, approve hooks
> Force push this branch to origin
```
Results: model itself hesitated first (defense in depth); the force push surfaced Termaxa's reason in Claude Code's own permission prompt; audit gained its first AI-written lines; `stats` finally showed `hook 2 / sessions 1`. **And the test filed a bug**: the agent's compound `git status && echo && ...` rode the `git status*` prefix as one allowed string — five commands under one wildcard.

## Phase 8 — v0.7.0 shell-aware evaluation

`shell.rs`: quote-aware split on `&&` `||` `;` `|` `\n` (single `&` preserved — `2>&1` is a redirection); `$(...)`/backtick detection. `Policy::evaluate_command`: judge every segment, **worst governs** (deny > ask > allow), reason names the guilty segment; ties prefer explicitly-matched rules over default fallthrough. Substitution presence escalates allow→ask. Previews/backups route per segment. Starter policy gained `echo *`, `git remote -v`, `git fetch*`. Regression test: `compound_commands_cannot_hide_behind_prefixes`. 16 tests.

Verified live on Windows:
```
git status && rm -rf /   → deny — segment 2/2 `rm -rf /`
<agent's real 5-segment command, rules added> → allow
```

## Source control

```powershell
Set-Content .gitignore "/target"
git init -b main ; git add . ; git commit -m "termaxa v0.6.1 — ..." ; git tag v0.6.1
# after v0.7: git add . ; git commit -m "v0.7.0 - compound-command splitting" ; git tag v0.7.0
```

## Engineering lessons (the transferable ones)

1. **Fail closed on policy, fail open on plumbing** — unknown command → ask; broken hook input → step aside.
2. **Normalize before matching** — case, whitespace; attackers and agents don't type canonically.
3. **Escalation is one-way** — heuristics may raise alarm, never lower it; that's what makes cheap heuristics safe.
4. **Reasons travel with verdicts** — a blocked agent that's told *why* pivots; one that isn't retries.
5. **Audit the attempt, not just the action** — blocked attempts are the interesting entries; append-only JSONL; `#[serde(default)]` respects the log's past.
6. **Best-effort layers never block enforcement** — previews, notifications, backups all degrade to nothing rather than to failure.
7. **Quoting is information; `join(" ")` destroys it.** Wildcards see one string; shells see many commands — split, then judge.
8. **Insurance must cover the blast radius the preview measures** (CASCADE dependents).
9. **Runtime state outside the repo it protects** — git ate the audit log; never again by construction (→ v0.8).
10. **Tests verify what you imagined; live use finds what you didn't** — both shipped fixes (loss preview, compound split) came from contact, minutes into real use.
11. Process craft: grep before replace (anchors from memory failed repeatedly); all-or-nothing patch scripts (a mid-script assert saved a half-patched file); never chain debugging steps with `&&`; version-number every install (`termaxa --version` = what's actually on PATH).
