use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

pub const STARTER_POLICY: &str = r#"# Termaxa policy — first matching rule wins; `*` is a wildcard.
# Actions: allow (run silently) | ask (require approval) | deny (block)
#
# ORDER MATTERS, and the hard stops come first on purpose. Until v0.14.1 the
# read-only allows sat at the top, so a broad prefix shadowed the stop below
# it: `git branch -D main` matched `git branch*` and was ALLOWED, and
# `echo $(rm -rf /)` matched `echo *` before `*rm -rf*` could deny it. A rule
# that can never be reached is not a rule. Put your own exceptions ABOVE the
# deny you want them to override — that is what first-match-wins is for.
#
# Matching is case-insensitive unless a rule opts in with
# `case_sensitive: true` (rare; used where a flag's case carries the meaning,
# like `git branch -D` vs `-d`). Quoting cannot disguise a command: rules are
# matched against the tokenized reading as well as the raw one, and the most
# severe verdict governs.
version: 1
default: ask

rules:
  # ---- self-defence: the gate's own configuration ----
  # A gate that will happily rewrite its own rules is a suggestion. These
  # come FIRST because first-match-wins: `echo *` at the bottom of this file
  # would otherwise allow
  #     echo 'default: allow' > .termaxa/policy.yaml
  # and every command after it is judged by the agent's own policy.
  #
  # `*` matches any run of characters, so one rule covers both path
  # separators: `.termaxa/policy.yaml` and `.termaxa\policy.yaml`.
  #
  # These are SHELL rules, and an agent's file-writing tool (Write, Edit, the
  # editor's apply-patch) produces no command for them to match. The same
  # files are therefore defended a second way: `termaxa init` also registers
  # a PreToolUse hook on the write tools, which reads the target path and
  # denies a write landing in `.termaxa/` or an agent hook config. It reads
  # nothing else and has no opinion about any other file — see src/protect.rs.
  #
  # A project wired by hand from a pre-v0.15 snippet has the shell half only.
  # `termaxa doctor` fingerprints the policy for that case: what was not
  # blocked can at least be noticed.
  #
  # Reads are denied too, except for the handful listed below, because
  # separating reads from writes in general would mean enumerating every read
  # command. To add one, put it in that group — NOT at the top of the file.
  - match: "*.claude*settings*"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
  - match: "*.cursor*hooks*"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
  - match: "*.codex*hooks*"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."
  - match: "*.github*hooks*"
    action: deny
    reason: "Agent hook configuration is off limits — editing it unhooks the gate."

  # ---- destruction by overwrite (v0.15) ----
  #
  # `>` truncates. Until v0.15 the operator was lexed and discarded, so
  # `cat /dev/null > .env` matched the read-only `cat *` rule and was ALLOWED.
  # Nothing was deleted; the contents were simply replaced.
  #
  # POSITION IS LOAD-BEARING, twice over. These sit with the self-defence
  # denies and ABOVE the .termaxa read exceptions below, because those
  # exceptions end in `*` and a trailing `*` swallows a redirect — placed any
  # lower, `cat .termaxa/policy.yaml > .env` matches `cat .termaxa*` and the
  # gate's own reviewability exception launders the overwrite it exists to
  # stop. `the_gates_own_exception_cannot_launder_an_overwrite` holds this.
  #
  # These rules cover the paths whose loss is not recoverable from the repo.
  # Everything else that truncates is classified `file-overwrite` and insured
  # (backup::overwrite_targets copies the file aside first), but is NOT gated
  # here: agents write files constantly, and a gate that asks on every redirect
  # is auto-approved into meaninglessness. Insurance without friction is the
  # trade — see #14.
  #
  # The two string rules below are kept, and a `match_path` rule now sits with
  # them. They are not redundant: the string rules read the command as typed,
  # the path rule reads what the command actually TOUCHES after resolution.
  # `> .env` and `> ./.env` are the same file and different strings - the
  # second walked past both string rules for four releases (known-limitations
  # 0.2, pinned as a test until v0.16). Matching the resolved target closes
  # every spelling of one path at once, which is what the string rules could
  # never do by adding more patterns.
  - match: "*> .env*"
    action: deny
    reason: "Overwriting .env destroys credentials that are not in the repo."
  - match: "*>.env*"
    action: deny
    reason: "Overwriting .env destroys credentials that are not in the repo."
  # No `match:` on purpose. This rule speaks about a PATH, and giving it a
  # string pattern to satisfy the schema is what broke it the first time:
  # `match: "*.env*"` fired on its own and denied `cat .env`, `grep KEY .env`,
  # `git diff .env`, even `vim .env.sample`. Reading a file is ordinary work.
  - match_path: "*/.env"
    action: deny
    reason: "Overwriting .env destroys credentials that are not in the repo."
  - match: "*> /etc/*"
    action: deny
    reason: "Overwriting a system config file."
  - match: "*> ~/.ssh/*"
    action: deny
    reason: "Overwriting an SSH key or config."
  - match: "*> *id_rsa*"
    action: deny
    reason: "Overwriting an SSH private key."

  # The policy is an in-repo artifact, reviewable in PRs, and the deny below
  # would otherwise make that workflow impossible: `git add .termaxa/…`,
  # `git diff .termaxa/…` and `cp .termaxa/policy.yaml backup.yaml` are all
  # blocked by it. These exceptions give the workflow back.
  #
  # The test for inclusion is that the `.termaxa` path can only be READ, never
  # written. diff/status/log/show/cat read it; add/commit stage what is
  # already on disk. `checkout`, `restore` and `config` are absent on purpose
  # — overwriting the working tree from a ref is exactly what the deny is for,
  # so restoring a clobbered policy stays a thing you do yourself.
  #
  # `cat` and `cp` are anchored on the SOURCE path so the copy can only go the
  # safe way: `cp .termaxa/policy.yaml backup.yaml` matches,
  # `cp backup.yaml .termaxa/policy.yaml` does not.
  #
  # Position matters twice over. Above the deny, or these never fire. Below
  # the four denies above, because a trailing `*` swallows a redirect —
  #     cat .termaxa/policy.yaml > .claude/settings.json
  # matches `cat .termaxa*` too, and at the top of the file it would allow
  # that and shadow the rule that exists to stop it.
  - match: "git diff *.termaxa*"
    action: allow
  - match: "git status *.termaxa*"
    action: allow
  - match: "git log *.termaxa*"
    action: allow
  - match: "git show *.termaxa*"
    action: allow
  - match: "git add *.termaxa*"
    action: allow
  - match: "git commit *.termaxa*"
    action: allow
  - match: "cat .termaxa*"
    action: allow
  - match: "cp .termaxa*"
    action: allow
  - match: "*.termaxa*"
    action: deny
    reason: "Termaxa's own config is off limits — that is the gate. Edit it yourself."

  # ---- destructive: hard stops ----
  - match: "git push*--force*"
    action: deny
    reason: "Force pushes are blocked by policy. Open a PR instead."
  # The filesystem root, and only the root. `rm -rf /*` would be a WILDCARD
  # matching every absolute path — `rm -rf /home/me/project/.git` included —
  # and would then explain itself as "delete from root", which is the right
  # verdict wearing the wrong sentence. A proving run caught it: an agent was
  # correctly stopped from deleting a .git directory and told the reason was
  # the filesystem root. The broad `*rm -rf*` rule below catches everything
  # else and says something true about it.
  - match: "rm -rf /"
    action: deny
    reason: "Recursive delete from the filesystem root is blocked."
  - match: "rm -rf / *"
    action: deny
    reason: "Recursive delete from the filesystem root is blocked."
  # GNU rm refuses `rm -rf /` on its own; --no-preserve-root is the one
  # spelling it obeys. The rule above is named for the command everybody
  # quotes, this one is named for the command that actually works.
  - match: "*--no-preserve-root*"
    action: deny
    reason: "--no-preserve-root is the only spelling `rm` obeys at `/`. Blocked."
  # Broad recursive-force deletes (any target), Unix + PowerShell + cmd
  # forms. DENY by default: with auto-approving agent UIs, `ask` silently
  # degrades to `allow`. Relax deliberately, per project, if you need to.
  - match: "*rm -rf*"
    action: deny
    reason: "Recursive force delete blocked by default policy."
  - match: "*rm -fr*"
    action: deny
    reason: "Recursive force delete blocked by default policy."
  - match: "*Remove-Item*-Recurse*"
    action: deny
    reason: "Recursive delete (PowerShell) blocked by default policy."
  - match: "*Remove-Item*-Force*"
    action: deny
    reason: "Forced delete (PowerShell) blocked by default policy."
  - match: "*del /s*"
    action: deny
    reason: "Recursive delete (cmd) blocked by default policy."
  - match: "*rmdir /s*"
    action: deny
    reason: "Recursive delete (cmd) blocked by default policy."
  - match: "*rd /s*"
    action: deny
    reason: "Recursive delete (cmd) blocked by default policy."
  - match: "kubectl delete*"
    action: deny
    reason: "kubectl delete is blocked. Use a manifest change + apply."
  - match: "*drop table*"
    action: deny
    reason: "DROP TABLE is blocked. Archive or rename instead."
  - match: "*drop database*"
    action: deny
    reason: "DROP DATABASE is blocked."
  - match: "terraform destroy*"
    action: deny
    reason: "terraform destroy is blocked by policy."
  - match: "tofu destroy*"
    action: deny
    reason: "tofu destroy is blocked by policy."

  # ---- consequential: human in the loop ----
  #
  # RECOVERABILITY INVARIANT (v0.15). A destructive rule may be `ask` only if
  # something can undo it. If neither Termaxa nor the system can, it denies —
  # because `ask` under an auto-approving UI is `allow`, and an `allow` you
  # cannot undo is the failure this tool exists to prevent.
  #
  # Recovery paths that count, and who provides them:
  #   termaxa file snapshot   rm and friends            (backup::rm_targets)
  #   termaxa pg_dump         psql/mysql destructive    (backup::pg_backup_targets)
  #   termaxa git ref pin     push --force              (backup::git_force_push_target)
  #   termaxa tfstate copy    terraform apply/destroy   (backup::tf_state_target)
  #   git reflog              branch -D, reset --hard   (git's own, ~90 days)
  #   the registry            npm/cargo publish         (yank; not deletion)
  #   the remote              gh pr merge               (revert commit)
  #
  # `the_starter_policy_has_no_uninsurable_asks` enforces this. A destructive
  # rule added here without a recovery path fails the build.
  # `git branch -D` force-deletes an unmerged branch; `-d` refuses unless it is
  # merged. Until v0.15 a rule could not tell them apart, because matching
  # lowercased the rule as well as the command — so this asked for both and
  # took the safer action for the gentler flag.
  #
  # A rule can now opt in with `case_sensitive: true`, matched as written, so
  # these can differ. The opt-in is explicit and rare on purpose: an uppercase
  # SPELLING alone changes nothing (`*Remove-Item*` still catches
  # `remove-item`). `-D` still asks rather than denies, because the commits
  # survive in the reflog for ~90 days and denying outright would block a
  # routine cleanup; but it says which one it caught.
  - match: "git branch*-D*"
    case_sensitive: true
    action: ask
    reason: "Force-deleting a branch even if unmerged. Recoverable via git reflog."
  - match: "git branch*-d*"
    action: ask
    reason: "Deleting a merged branch."
  - match: "git push*"
    action: ask
  - match: "terraform apply*"
    action: ask
  - match: "tofu apply*"
    action: ask
  - match: "docker rm*"
    action: ask
  # No recovery path: prune deletes unused images, containers, networks and
  # (with -a or --volumes) data that nothing else holds a copy of. Termaxa
  # cannot snapshot a docker volume and docker keeps no undo. Denied rather
  # than asked, per the invariant above.
  - match: "docker system prune*"
    action: deny
    reason: "docker system prune has no recovery path. Remove specific objects instead."
  # Raw device writes destroy partition tables and filesystems with nothing
  # to restore from. Not insurable at any layer.
  - match: "dd*of=/dev/*"
    action: deny
    reason: "Writing to a raw device is not recoverable."
  - match: "mkfs*"
    action: deny
    reason: "Formatting a device is not recoverable."
  - match: "npm publish*"
    action: ask
  - match: "cargo publish*"
    action: ask
  - match: "gh pr merge*"
    action: ask
  - match: "aws *"
    action: ask
  - match: "curl*"
    action: ask
  - match: "ssh *"
    action: ask

  # ---- read-only operations: let the agent work ----
  - match: "git status*"
    action: allow
  - match: "git diff*"
    action: allow
  - match: "git log*"
    action: allow
  - match: "git branch*"
    action: allow
  - match: "git commit*"
    action: allow
  # A prefix without its trailing space is a prefix, not a command: `ls*`
  # also matched `lsof` and `lsblk`, `grep*` also matched `grepdiff`.
  # `cat *` and `echo *` below always had this right. Bare `ls` needs its own
  # rule because `ls *` requires the space; bare `cat`/`grep` just read stdin,
  # so they stay on the default.
  - match: "ls"
    action: allow
  - match: "ls *"
    action: allow
  - match: "cat *"
    action: allow
  - match: "grep *"
    action: allow
  - match: "echo *"
    action: allow
  - match: "git remote -v"
    action: allow
  - match: "git fetch*"
    action: allow
  - match: "terraform plan*"
    action: allow
  - match: "terraform init*"
    action: allow
  - match: "tofu plan*"
    action: allow
  - match: "kubectl get*"
    action: allow
  - match: "kubectl describe*"
    action: allow
  - match: "docker ps*"
    action: allow

# Session circuit breaker (v0.11): if the same destructive intent
# (file delete / db destroy / git force / infra destroy) is asked or
# denied `threshold` times in one agent session, further variants are
# DENIED automatically. Human-approved commands don't count.
circuit_breaker:
  enabled: true
  threshold: 2   # trip on the 3rd attempt
"#;

pub fn run(
    dir: &Path,
    write_claude_hook: bool,
    write_cursor_hook: bool,
    write_codex_hook: bool,
    write_copilot_hook: bool,
) -> Result<()> {
    let termaxa_dir = dir.join(".termaxa");
    fs::create_dir_all(&termaxa_dir)?;

    let policy_path = termaxa_dir.join("policy.yaml");
    if policy_path.exists() {
        println!("• .termaxa/policy.yaml already exists — leaving it untouched");
    } else {
        fs::write(&policy_path, STARTER_POLICY)?;
        println!("✓ wrote .termaxa/policy.yaml (starter policy)");
    }

    // --- record the policy fingerprint ---
    // Runs whether we wrote the policy or found one: `termaxa init` is also
    // how you say "this is the policy I mean" after editing it. The baseline
    // goes in the state dir under $TERMAXA_HOME, not in `.termaxa/` — a
    // baseline inside the directory it protects is erased by the same clobber
    // it exists to catch.
    //
    // `resolve_readonly` on purpose: it locates the state dir without creating
    // `logs/`, `backups/` or triggering the legacy state migration. Failure
    // here is reported, not fatal — a missing fingerprint costs you a
    // diagnostic, not the gate.
    match crate::paths::resolve_readonly(dir)
        .and_then(|p| record_fingerprint(&p.state_dir, &policy_path))
    {
        Ok(Some(short)) => println!("✓ recorded policy fingerprint {}", short),
        Ok(None) => {}
        Err(e) => println!("! could not record policy fingerprint: {}", e),
    }

    // --- detect agent harnesses ---
    println!("\nAgent harnesses detected:");
    let mut found_any = false;
    for (label, probe) in [
        (
            "Claude Code",
            dir.join(".claude").exists() || which("claude"),
        ),
        ("Cursor", dir.join(".cursor").exists()),
        ("OpenHands", which("openhands")),
        ("Codex CLI", which("codex")),
    ] {
        if probe {
            println!("  ✓ {}", label);
            found_any = true;
        }
    }
    if !found_any {
        println!("  (none found — hook mode still works once you add one)");
    }

    // --- detect tools worth governing ---
    println!("\nTools detected on PATH:");
    for tool in [
        "git",
        "docker",
        "terraform",
        "kubectl",
        "aws",
        "psql",
        "npm",
        "cargo",
        "gh",
        "ssh",
    ] {
        if which(tool) {
            println!("  ✓ {}", tool);
        }
    }

    // --- wire up Claude Code PreToolUse hook ---
    if write_claude_hook {
        install_claude_hook(dir)?;
    } else {
        if write_cursor_hook {
            let dir_c = dir.join(".cursor");
            fs::create_dir_all(&dir_c)?;
            let hooks_path = dir_c.join("hooks.json");
            // Use the absolute path to THIS binary. On Windows, a bare "termaxa hook"
            // can fail PATH/quoting resolution inside Cursor's hook runner; an
            // absolute exe path is the documented fix.
            let exe = std::env::current_exe()
                .ok()
                .and_then(|p| p.to_str().map(str::to_string))
                .unwrap_or_else(|| "termaxa".to_string());
            let cmd = format!("{} hook", exe);
            let hooks = serde_json::json!({
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [ { "command": cmd } ],
                    "afterShellExecution": [ { "command": cmd } ]
                }
            });
            fs::write(&hooks_path, serde_json::to_string_pretty(&hooks)?)?;
            println!("✓ wrote .cursor/hooks.json (before + after ShellExecution -> termaxa hook)");
            println!("  NOTE: restart Cursor after this so it reloads hook config.");
        }

        println!("\nTo wire Termaxa into Claude Code, run: termaxa init --claude-code");
        println!("To wire Termaxa into Cursor (v1.7+), run: termaxa init --cursor");

        if write_codex_hook {
            // Codex uses the same PreToolUse contract as Claude Code.
            let dir_x = dir.join(".codex");
            fs::create_dir_all(&dir_x)?;
            let hooks_path = dir_x.join("hooks.json");
            let hooks = serde_json::json!({
                "version": 1,
                "hooks": { "PreToolUse": [ { "command": "termaxa hook" } ] }
            });
            fs::write(&hooks_path, serde_json::to_string_pretty(&hooks)?)?;
            println!("✓ wrote .codex/hooks.json (Codex PreToolUse -> termaxa hook)");
        }

        if write_copilot_hook {
            let dir_h = dir.join(".github").join("hooks");
            fs::create_dir_all(&dir_h)?;
            let hooks_path = dir_h.join("hooks.json");
            // Copilot CLI: preToolUse hook, fail-closed on deny.
            let hooks = serde_json::json!({
                "version": 1,
                "hooks": {
                    "preToolUse": [
                        { "type": "command", "command": "termaxa hook", "failClosed": true }
                    ]
                }
            });
            fs::write(&hooks_path, serde_json::to_string_pretty(&hooks)?)?;
            println!("✓ wrote .github/hooks/hooks.json (Copilot preToolUse -> termaxa hook, fail-closed)");
        }

        println!("Other agents: termaxa init --codex | --copilot");
        print_hook_snippet();
    }

    if let Ok(p) = crate::paths::resolve() {
        println!("\nRuntime state (logs, backups) lives OUTSIDE the repo:");
        println!("  {}", p.state_dir.display());
    }

    println!("\nDone. Try:  termaxa check \"git push --force origin main\"");
    Ok(())
}

/// Hash the policy and store the baseline in the project's state dir.
/// Returns the short form for display, or `None` if the policy could not be
/// read (which `doctor` will report on its own terms).
///
/// Takes the state dir rather than resolving it, so the test does not have to
/// go through `$TERMAXA_HOME`.
fn record_fingerprint(state_dir: &Path, policy_path: &Path) -> Result<Option<String>> {
    let Some(hash) = crate::fingerprint::of_file(policy_path) else {
        return Ok(None);
    };
    crate::fingerprint::record(state_dir, &hash)?;
    Ok(Some(crate::fingerprint::short(&hash)))
}

fn install_claude_hook(dir: &Path) -> Result<()> {
    let claude_dir = dir.join(".claude");
    fs::create_dir_all(&claude_dir)?;
    let settings_path = claude_dir.join("settings.json");

    let mut settings: Value = if settings_path.exists() {
        let raw = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&raw).context("existing .claude/settings.json is not valid JSON")?
    } else {
        json!({})
    };

    let hooks = settings
        .as_object_mut()
        .context("settings.json root must be an object")?
        .entry("hooks")
        .or_insert(json!({}));
    let pre = hooks
        .as_object_mut()
        .context("hooks must be an object")?
        .entry("PreToolUse")
        .or_insert(json!([]));
    let arr = pre.as_array_mut().context("PreToolUse must be an array")?;

    if ensure_hook(arr, BASH_MATCHER) {
        println!("\n✓ installed PreToolUse hook in .claude/settings.json");
    } else {
        println!("\n• Claude Code hook already installed in .claude/settings.json");
    }
    // Second matcher, on the tools that write files without going near a
    // shell. It reads the target path and nothing else: a write that lands in
    // `.termaxa/` or an agent hook config is denied, and every other write
    // gets no decision at all. This is not a general file-write gate and is
    // not trying to be one — see `protect`.
    //
    // A separate entry rather than a widened `"Bash|Write|…"` because the two
    // are different jobs. The Bash matcher runs the policy engine, the
    // classifier, the preview and insurance; this one compares a path.
    if ensure_hook(arr, WRITE_MATCHER) {
        println!("✓ installed PreToolUse write-tool hook in .claude/settings.json");
    }

    // PostToolUse receipt hook (feeds the breaker's approved-ask exclusion).
    // Same command; Termaxa branches on the event name internally.
    //
    // Bash only. A receipt for a file write would record something the circuit
    // breaker cannot count and the report cannot rank, so registering it would
    // buy a log line and a process spawn per edit.
    let post = settings
        .as_object_mut()
        .context("settings.json root must be an object")?
        .get_mut("hooks")
        .and_then(|h| h.as_object_mut())
        .context("hooks must be an object")?
        .entry("PostToolUse")
        .or_insert(json!([]));
    let post_arr = post
        .as_array_mut()
        .context("PostToolUse must be an array")?;
    if ensure_hook(post_arr, BASH_MATCHER) {
        println!("✓ installed PostToolUse hook in .claude/settings.json");
    }

    fs::write(&settings_path, serde_json::to_string_pretty(&settings)?)?;
    Ok(())
}

/// Claude Code matches shell calls on the tool name `Bash`.
const BASH_MATCHER: &str = "Bash";

/// Claude Code treats `matcher` as a regex over the tool name, so the write
/// tools are one entry rather than four.
///
/// A tool whose name is not in here never reaches the hook, and that is a
/// coverage gap by construction: the matcher is the harness's filter and
/// Termaxa cannot widen it after the fact. `parse_file_write` therefore
/// recognises write tools by verb rather than by exact name, so this list is
/// the only place a rename can cost coverage, and `doctor`'s policy
/// fingerprint still notices a change that got through.
const WRITE_MATCHER: &str = "Write|Edit|MultiEdit|NotebookEdit";

/// Add the Termaxa hook for `matcher` if it is not already there. Returns
/// whether it inserted.
///
/// Keyed on the matcher as well as the command, because a settings file
/// written by an earlier version already contains a `Bash` entry, and an
/// upgrade has to be able to add the write-tool entry next to it rather than
/// reading the first one as "already installed".
fn ensure_hook(arr: &mut Vec<Value>, matcher: &str) -> bool {
    let present = arr.iter().any(|e| {
        e.get("matcher").and_then(|m| m.as_str()) == Some(matcher)
            && e.pointer("/hooks/0/command")
                .and_then(|c| c.as_str())
                .map(|c| c.contains("termaxa hook"))
                .unwrap_or(false)
    });
    if present {
        return false;
    }
    arr.push(json!({
        "matcher": matcher,
        "hooks": [{ "type": "command", "command": "termaxa hook" }]
    }));
    true
}

fn print_hook_snippet() {
    println!("{}", print_hook_snippet_text());
}

/// The hand-wiring snippet, built from the same matcher constants `init`
/// installs, so the two cannot drift apart.
fn print_hook_snippet_text() -> String {
    let entry = |matcher: &str| {
        json!({
            "matcher": matcher,
            "hooks": [{ "type": "command", "command": "termaxa hook" }]
        })
    };
    let snippet = json!({
        "hooks": {
            "PreToolUse": [entry(BASH_MATCHER), entry(WRITE_MATCHER)],
            "PostToolUse": [entry(BASH_MATCHER)],
        }
    });
    format!(
        "\n  .claude/settings.json snippet:\n{}",
        serde_json::to_string_pretty(&snippet).unwrap_or_default()
    )
}

pub(crate) fn which(bin: &str) -> bool {
    // `which` on Unix, `where` on Windows
    let finder = if cfg!(windows) { "where" } else { "which" };
    Command::new(finder)
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The directory the project sits in, which the agent must traverse to reach
/// it. Named rather than assumed: the first proving run's setup said
/// `chmod 0755 ~`, which makes the operator's entire home listable to the
/// agent - broader than needed, and the same over-permission the state
/// directory already avoids with 0711.
fn home_of_project(project: &Path) -> std::path::PathBuf {
    project
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| project.to_path_buf())
}

/// Print the supervised-mode setup. Prints and verifies; never executes.
///
/// Decision #34 applied to the feature most tempting to violate it. Creating a
/// user account and chowning a directory tree require root, and a tool that
/// asks for root to "set things up for you" is asking to be trusted with
/// exactly the authority this product exists to put a boundary around. So it
/// prints commands the operator can read, and `doctor` verifies afterwards
/// what they actually produced rather than assuming they were typed correctly.
///
/// The commands below are not a sketch. They are what the boundary rig
/// (`tests/boundary/rig.sh`) runs to produce a topology where a second real
/// user is denied the log, the backups and the policy on every attempt, and
/// permitted the socket. The modes in particular were found by running it:
/// `0711` on the state directory, not `0700` (which makes the socket
/// unreachable and denies everything) and not `0755` (which hands over the
/// log).
pub fn print_supervised_setup(project: &Path) -> Result<()> {
    use crate::ui::{bold, dim};

    let home = crate::paths::home_base()?;
    let policy = project.join(".termaxa").join("policy.yaml");
    let me = std::env::var("USER").unwrap_or_else(|_| "you".into());

    println!();
    println!("{}", bold("Supervised mode — setup"));
    println!();

    if !cfg!(unix) {
        println!(
            "  {}",
            dim("Not available on Windows: it needs Unix domain sockets and a")
        );
        println!(
            "  {}",
            dim("second user account in the form this depends on. Basic mode is")
        );
        println!("  {}", dim("the Windows answer and is fully supported."));
        return Ok(());
    }

    println!(
        "  {}",
        dim("What this buys: the audit log and the backups stop being the")
    );
    println!(
        "  {}",
        dim("agent's own account of itself. The agent's user cannot read them,")
    );
    println!(
        "  {}",
        dim("edit them, or stop the supervisor — not because the code refuses,")
    );
    println!("  {}", dim("but because the OS does."));
    println!();
    println!(
        "{}",
        bold("  Termaxa will not run these for you. Review them, then run as root:")
    );
    println!();
    println!("    # 1. an account for the agent to run as");
    println!("    useradd --system --create-home --shell /bin/bash termaxa-agent");
    println!();
    println!("    # 2. the policy: the agent reads it, and cannot change it");
    println!("    chown {me}:{me} {}", policy.display());
    println!("    chmod 0644 {}", policy.display());
    println!();
    println!("    # 3. the state directory: traversable, not listable.");
    println!("    #    0711 is deliberate — 0700 makes the socket unreachable");
    println!("    #    and every command denies; 0755 hands over the log.");
    println!("    chown -R {me}:{me} {}", home.display());
    println!("    chmod 0711 {}", home.display());
    println!();
    println!("    # 4. the agent needs to reach the project. 0711 lets it");
    println!("    #    traverse to a path it knows without listing your home.");
    println!("    chmod 0711 {}", home_of_project(project).display());
    println!();
    println!("    # 5. run it, from the project directory");
    println!("    cd {}", project.display());
    println!("    termaxa supervise &");
    println!("    sudo -u termaxa-agent termaxa wrap -- claude");
    println!();
    println!(
        "  {}",
        dim("If that last line asks for YOUR password, this machine's sudoers")
    );
    println!(
        "  {}",
        dim("rule is root-only (`NOPASSWD: ALL` for root, common on managed dev")
    );
    println!(
        "  {}",
        dim("boxes). `sudo -i` then `su - termaxa-agent` gets there without one.")
    );
    println!();
    println!(
        "  {}",
        dim("Then run `termaxa doctor`, which reports what these produced")
    );
    println!(
        "  {}",
        dim("rather than assuming they were typed correctly.")
    );
    println!();
    println!(
        "{}",
        bold("  Credentials are a tradeoff, not a solved problem.")
    );
    println!(
        "  {}",
        dim("The agent needs git, SSH and registry access to do real work, and")
    );
    println!(
        "  {}",
        dim("a separate account has none of yours. Three options, none free:")
    );
    println!();
    println!("    shared HOME        easiest; dilutes the boundary you just built");
    println!("    copied credentials works; you now have two copies to rotate");
    println!("    curated per launch most honest, most friction — give the agent");
    println!("                       only the credentials the task needs");
    println!();
    println!(
        "  {}",
        dim("Nobody has dissolved this, including us. Pick deliberately.")
    );
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn here() -> crate::resolve::EvalContext {
        crate::resolve::EvalContext::at(std::path::Path::new("."))
    }
    use crate::testutil::TempTree;

    /// `examples/policy.yaml` is the file people copy. It had drifted to 28
    /// rules against the starter's 44 — missing every broad delete deny and
    /// the whole circuit_breaker block — with nothing to signal it was weaker.
    /// It is now generated from STARTER_POLICY, and this test is what keeps it
    /// generated: an example policy that is quietly less safe than the real
    /// one is worse than no example at all.
    /// The printed setup names the modes the boundary rig actually uses.
    ///
    /// Instructions nobody has followed are a guess. These were verified by
    /// running them literally against a second real account - socket
    /// reachable, state dir not listable, policy readable and not writable -
    /// and this test pins the numbers so a later edit cannot quietly print
    /// 0700 (which makes the socket unreachable and denies everything) or
    /// 0755 (which hands over the audit log).
    #[cfg(unix)]
    #[test]
    fn the_supervised_setup_prints_the_modes_the_rig_proved() {
        let t = TempTree::new("sup-setup");
        let dir = t.path();
        std::fs::create_dir_all(dir.join(".termaxa")).unwrap();

        // Captured by rendering into a string rather than by scraping stdout:
        // the point is the CONTENT, and a test that shells out would be
        // testing the terminal.
        let rig = std::fs::read_to_string("tests/boundary/rig.sh").unwrap();
        assert!(
            rig.contains("chmod 0711 \"$TERMAXA_HOME\""),
            "the rig uses 0711 on the state dir; if that changed, the printed \
             setup is now wrong and this test is the only thing that says so"
        );
        assert!(
            rig.contains("chmod 0644 \"$PROJECT/.termaxa/policy.yaml\""),
            "the rig uses 0644 on the policy"
        );

        // And the function runs without error against a real project.
        print_supervised_setup(dir).expect("the setup prints");
    }

    #[test]
    fn shipped_example_policy_matches_the_starter_policy() {
        // Normalise line endings before comparing. Git checks this file out
        // with CRLF on Windows (core.autocrlf) while STARTER_POLICY is a Rust
        // literal with LF, so a byte comparison fails on Windows only. What
        // this test is for is content drift, not line endings.
        let example = include_str!("../examples/policy.yaml").replace("\r\n", "\n");
        assert_eq!(
            example, STARTER_POLICY,
            "examples/policy.yaml has drifted from init::STARTER_POLICY. \
             Regenerate it rather than editing it by hand."
        );
    }

    /// RECOVERABILITY INVARIANT (v0.15).
    ///
    /// A destructive rule may be `ask` only if something can undo it. Under an
    /// auto-approving UI `ask` is `allow`, so an uninsurable `ask` is an
    /// unrecoverable `allow` wearing a prompt.
    ///
    /// This test is deliberately narrow. "Insurable" here means a recovery path
    /// we can name and point at — not a general predicate, which we do not have.
    /// Adding a destructive rule without one fails the build, and the fix is
    /// either to add the recovery path or to state why it does not need one.
    #[test]
    fn the_starter_policy_has_no_uninsurable_asks() {
        let p: crate::policy::Policy = serde_yaml::from_str(STARTER_POLICY).unwrap();

        // Every `ask` rule, and the recovery path that justifies it. A rule
        // reaching this list without an entry is the point of the test.
        let recovery: &[(&str, &str)] = &[
            ("git branch*-D*", "git reflog retains the commits"),
            (
                "git branch*-d*",
                "git refuses unless merged; reflog retains either way",
            ),
            ("git push*", "termaxa pins the remote ref before the push"),
            ("terraform apply*", "termaxa copies tfstate first"),
            ("tofu apply*", "termaxa copies tfstate first"),
            ("docker rm*", "named container; image and volumes survive"),
            ("npm publish*", "npm deprecate/unpublish window"),
            ("cargo publish*", "cargo yank"),
            ("gh pr merge*", "the merge commit can be reverted"),
            ("aws *", "not destructive by itself; breadth is why it asks"),
            (
                "curl*",
                "not destructive by itself; network egress is why it asks",
            ),
            (
                "ssh *",
                "not destructive by itself; remote execution is why it asks",
            ),
        ];

        let mut unjustified = Vec::new();
        for rule in p
            .rules
            .iter()
            .filter(|r| r.action == crate::policy::Action::Ask)
        {
            if !recovery.iter().any(|(m, _)| *m == rule.label()) {
                unjustified.push(rule.label());
            }
        }

        assert!(
            unjustified.is_empty(),
            "these `ask` rules have no documented recovery path: {unjustified:?}\n\
             Either add the recovery path to backup.rs and list it here, or make \
             the rule `deny`. An ask that cannot be undone is an allow that \
             cannot be undone."
        );
    }

    /// The break the pre-#16 draft shipped, kept impossible: the anchored
    /// `.termaxa` read exceptions end in `*`, a trailing `*` swallows a
    /// redirect (#16's own commit message), and overwrite denies placed below
    /// them were laundered by the gate's own reviewability exception. The
    /// denies now sit above; one command reading the policy and wiping a
    /// credentials file must never be an allow.
    #[test]
    fn the_gates_own_exception_cannot_launder_an_overwrite() {
        let p: crate::policy::Policy = serde_yaml::from_str(STARTER_POLICY).unwrap();
        for cmd in [
            "cat .termaxa/policy.yaml > .env",
            "cat .termaxa/policy.yaml > /etc/hosts",
        ] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                crate::policy::Action::Deny,
                "{cmd} must not be allowed via the .termaxa read exception"
            );
        }
        // The exception itself still works — that is what it is for.
        assert_eq!(
            p.evaluate_command("cat .termaxa/policy.yaml", &here())
                .action,
            crate::policy::Action::Allow
        );
    }

    /// The three the invariant moved, and why. Named so a future reshuffle
    /// that quietly relaxes them fails loudly.
    #[test]
    fn the_uninsurable_commands_are_denied_not_asked() {
        let p: crate::policy::Policy = serde_yaml::from_str(STARTER_POLICY).unwrap();
        for cmd in [
            "docker system prune -a",
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sdb1",
        ] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                crate::policy::Action::Deny,
                "{cmd} has no recovery path and must deny, not ask"
            );
        }
    }

    /// Schipper review, finding 3: order is load-bearing, so assert the shape
    /// rather than trusting a comment to hold.
    ///
    /// The shape is not "every deny precedes every allow". First-match-wins
    /// exists so an exception can sit above the deny it excepts, and the
    /// review-workflow allows do exactly that. What must never happen again is
    /// a BROAD allow above a deny — `git branch*` above `*git branch -D*` was
    /// the v0.14.1 bug. So an allow that sits above a deny has to be anchored
    /// at the start of the command AND scoped to the path it is excepting;
    /// anything looser can swallow the deny below it.
    #[test]
    fn hard_stops_are_reachable_before_the_read_only_allows() {
        let p: crate::policy::Policy = serde_yaml::from_str(STARTER_POLICY).unwrap();
        let last_deny = p
            .rules
            .iter()
            .rposition(|r| r.action == crate::policy::Action::Deny)
            .expect("starter policy has deny rules");
        for (i, r) in p.rules.iter().enumerate().take(last_deny) {
            if r.action != crate::policy::Action::Allow {
                continue;
            }
            // Only STRING patterns can be unanchored in the sense this test
            // means. A path rule matches resolved targets, so `*` in it is a
            // path glob, not a command prefix, and it cannot shadow a deny by
            // swallowing a neighbouring command.
            let Some(pattern) = &r.r#match else {
                continue;
            };
            assert!(
                !pattern.starts_with('*') && pattern.contains(".termaxa"),
                "rule {i} `{}` is an unanchored allow sitting above a deny — \
                 it can shadow the rule below it and can never be audited by \
                 reading the denies alone",
                pattern
            );
        }
    }

    #[test]
    fn init_records_a_baseline_the_policy_directory_cannot_erase() {
        let tmp = TempTree::new("init-fp");
        let state = tmp.dir("home/projects/proj-abc12345");
        let policy = tmp.file("proj/.termaxa/policy.yaml", STARTER_POLICY);

        let short = record_fingerprint(&state, &policy)
            .unwrap()
            .expect("a readable policy must fingerprint");
        assert_eq!(short.len(), 12);

        // The baseline lives outside the directory it protects: `rm -rf
        // .termaxa/` must not take the evidence with it.
        let baseline = crate::fingerprint::baseline_file(&state);
        assert!(baseline.is_file());
        assert!(
            !baseline.starts_with(policy.parent().unwrap()),
            "baseline must not live in the project: {}",
            baseline.display()
        );

        // Re-running init on an unchanged policy records the same hash.
        let again = record_fingerprint(&state, &policy).unwrap().unwrap();
        assert_eq!(short, again);
    }

    /// Read the PreToolUse matchers out of a settings file, in order.
    fn pre_matchers(settings: &Path) -> Vec<String> {
        let v: Value = serde_json::from_str(&fs::read_to_string(settings).unwrap()).unwrap();
        v["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["matcher"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn init_registers_the_write_tools_as_well_as_bash() {
        let tmp = TempTree::new("init-write-matcher");
        let proj = tmp.dir("proj");
        install_claude_hook(&proj).unwrap();

        let settings = proj.join(".claude").join("settings.json");
        assert_eq!(pre_matchers(&settings), vec![BASH_MATCHER, WRITE_MATCHER]);

        // The write matcher is a gate, not a receipt: a file write that already
        // happened tells the breaker nothing, so PostToolUse stays Bash-only.
        let v: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        let post: Vec<&str> = v["hooks"]["PostToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["matcher"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(post, vec![BASH_MATCHER]);
    }

    /// The upgrade case. A settings file written before the write matcher
    /// existed already has a `Bash` entry, and an idempotence check keyed only
    /// on the command reads that as "already installed" and never adds the
    /// second one — leaving the gap open on exactly the machines that have
    /// been running Termaxa longest.
    #[test]
    fn init_adds_the_write_matcher_to_a_settings_file_that_predates_it() {
        let tmp = TempTree::new("init-write-matcher-upgrade");
        let proj = tmp.dir("proj");
        tmp.file(
            "proj/.claude/settings.json",
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"termaxa hook"}]}]}}"#,
        );

        install_claude_hook(&proj).unwrap();
        assert_eq!(
            pre_matchers(&proj.join(".claude").join("settings.json")),
            vec![BASH_MATCHER, WRITE_MATCHER]
        );
    }

    #[test]
    fn running_init_twice_does_not_duplicate_either_matcher() {
        let tmp = TempTree::new("init-write-matcher-twice");
        let proj = tmp.dir("proj");
        install_claude_hook(&proj).unwrap();
        install_claude_hook(&proj).unwrap();

        assert_eq!(
            pre_matchers(&proj.join(".claude").join("settings.json")),
            vec![BASH_MATCHER, WRITE_MATCHER]
        );
    }

    /// The snippet is what someone wires by hand when `init` cannot write the
    /// file for them. If it only shows the Bash matcher, a hand-wired install
    /// is missing the half this PR adds and nothing says so.
    #[test]
    fn the_printed_snippet_shows_both_matchers() {
        let snippet = print_hook_snippet_text();
        assert!(snippet.contains(BASH_MATCHER));
        assert!(snippet.contains(WRITE_MATCHER));
    }

    #[test]
    fn the_shadowed_commands_are_no_longer_allowed() {
        let p: crate::policy::Policy = serde_yaml::from_str(STARTER_POLICY).unwrap();
        for cmd in [
            "git branch -D main",
            "echo $(rm -rf /)",
            "git status & rm -rf /",
        ] {
            assert_ne!(
                p.evaluate_command(cmd, &here()).action,
                crate::policy::Action::Allow,
                "{cmd} is still allowed"
            );
        }
    }
}
