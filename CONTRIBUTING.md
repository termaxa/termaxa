# Contributing

Termaxa is a Rust CLI that gates the shell commands and native file writes a
coding agent makes. Its working rules come from a summer of incidents, and
every one of them is in `CHANGELOG.md` with a receipt. Three of them govern
contributions.

## 1. Measured, then written

A change ships with the thing that showed it was needed and the thing that
shows it works: an incident, a captured payload, a run whose output is in the
PR. A claim without one is not made. In particular:

- **No harness is claimed as covered until it has been watched.** A new
  dialect starts with a capture (`TERMAXA_HOOK_DEBUG=<file>` writes every
  payload the hook receives), then a fixture test built from the captured
  bytes, then the code. `docs/dialects.md` has the procedure and what each
  harness is known to honour.
- **The preview and the insurance name the same files.** Anything that reads
  a command - policy, classifier, preview, delete extractor, insurance - goes
  through `shell::split_segments_deep`, so two engines cannot disagree about
  what a command touches.
- **Fail closed on drift.** A shape the reader does not recognise falls to
  the policy default, never to allow. A harness preamble that changed, a
  patch header that moved, a payload field that was renamed: the default,
  with the unrecognised segment named in the refusal.

## 2. The gate

Every PR runs the same four legs CI runs (`.github/workflows/ci.yml`:
ubuntu, macos and windows, plus fmt and clippy). Locally:

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

On Windows, `cargo clean -p termaxa` before the final `cargo test --all`; an
incremental build has reported a stale binary as green before. A test is
named as the sentence it proves (`a_redirection_is_not_a_delete_target`),
asserts on the world - the file on disk, the manifest line, the audit entry -
and not on a return value alone, and pins a receipt where it has one: the
verbatim command from the log, the payload as captured.

Tests that read the environment take it as an argument (`install_shims_on`,
`real_shell_on`): environment variables are process-global, the test binary
runs on many threads, and a guard that rewrites `PATH` under another test's
walk lost a macOS run once.

## 3. One change per PR

One PR carries one change and its tests, with a title that reads as the
release note it will become and a body that says what was measured before,
what changed, and what was measured after. A release is a separate PR
(`RELEASING.md`), and a shipped claim that turns out wrong is corrected under
the changelog entry that made it, dated, in the fix release.

## Where things are

| Module | What it owns |
| --- | --- |
| `shell.rs` | Splitting a command line into segments; `-c` strings and `eval` read as wrappers; harness scaffolding; bindings |
| `policy.rs` | Rules, `match` and `match_path`, the most-severe-wins tournament, the starter |
| `delete.rs`, `resolve.rs` | What a command deletes or writes, resolved to paths, with shapes (outside the project, a user profile, unresolvable) |
| `preview.rs`, `pg.rs` | Blast radius: files and directories, bytes lost, Postgres row counts, terraform plans, forced pushes |
| `backup.rs` | Insurance before an approved command; retention; `rollback` |
| `hook.rs` | The dialects, payload in and decision out; native writes |
| `runner.rs`, `wrap.rs` | `run` and the shims `wrap` puts in front of a harness |
| `audit.rs`, `report.rs`, `intent.rs` | The hash-chained record, the report, the circuit breaker |
| `init.rs`, `doctor.rs` | Wiring a harness; saying what is wired |

## Reporting

An incident, with the command the agent ran and what the gate said, is the
most useful thing you can send. Open an issue; include the `termaxa log`
line if there is one, and the payload from `TERMAXA_HOOK_DEBUG` if the gate
did not fire at all. Every dialect this project supports began as one of
those.
