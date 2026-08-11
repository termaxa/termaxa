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
# Matching is case-insensitive, so a rule cannot distinguish `-D` from `-d`.
# Where a flag's case carries the meaning (git branch -D, rm -R), the rule
# covers both and the action is chosen for the safer of the two.
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
  # This closes the SHELL path only. An agent's file-writing tool (Write,
  # Edit, the editor's apply-patch) never reaches the hook — the Claude Code
  # hook is registered with `"matcher": "Bash"` — so no rule here can see it.
  # `termaxa doctor` fingerprints the policy for exactly that reason: what
  # cannot be blocked can at least be noticed.
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
  - match: "rm -rf /*"
    action: deny
    reason: "Recursive delete from root is blocked."
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
  - match: "*Get-ChildItem*Remove-Item*"
    action: deny
    reason: "Bulk delete pipeline (PowerShell) blocked by default policy."
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
  # `git branch -D` force-deletes an unmerged branch. Case-insensitive
  # matching cannot separate it from the safe `-d`, so this asks rather than
  # denies; the commits remain in the reflog either way.
  - match: "git branch*-d*"
    action: ask
    reason: "Deleting a branch. `-D` force-deletes even if unmerged."
  - match: "git push*"
    action: ask
  - match: "terraform apply*"
    action: ask
  - match: "tofu apply*"
    action: ask
  - match: "docker rm*"
    action: ask
  - match: "docker system prune*"
    action: ask
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

    let hook_entry = json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "termaxa hook" }]
    });

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

    let already = arr.iter().any(|e| {
        e.pointer("/hooks/0/command")
            .and_then(|c| c.as_str())
            .map(|c| c.contains("termaxa hook"))
            .unwrap_or(false)
    });
    if already {
        println!("\n• Claude Code hook already installed in .claude/settings.json");
    } else {
        arr.push(hook_entry);
        println!("\n✓ installed PreToolUse hook in .claude/settings.json");
    }

    // PostToolUse receipt hook (feeds the breaker's approved-ask exclusion).
    // Same command; Termaxa branches on the event name internally.
    let post_entry = json!({
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "termaxa hook" }]
    });
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
    let post_already = post_arr.iter().any(|e| {
        e.pointer("/hooks/0/command")
            .and_then(|c| c.as_str())
            .map(|c| c.contains("termaxa hook"))
            .unwrap_or(false)
    });
    if !post_already {
        post_arr.push(post_entry);
        println!("✓ installed PostToolUse hook in .claude/settings.json");
    }

    fs::write(&settings_path, serde_json::to_string_pretty(&settings)?)?;
    Ok(())
}

fn print_hook_snippet() {
    println!(
        r#"
  .claude/settings.json snippet:
  {{
    "hooks": {{
      "PreToolUse": [
        {{
          "matcher": "Bash",
          "hooks": [{{ "type": "command", "command": "termaxa hook" }}]
        }}
      ]
    }}
  }}"#
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempTree;

    /// `examples/policy.yaml` is the file people copy. It had drifted to 28
    /// rules against the starter's 44 — missing every broad delete deny and
    /// the whole circuit_breaker block — with nothing to signal it was weaker.
    /// It is now generated from STARTER_POLICY, and this test is what keeps it
    /// generated: an example policy that is quietly less safe than the real
    /// one is worse than no example at all.
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
            assert!(
                !r.r#match.starts_with('*') && r.r#match.contains(".termaxa"),
                "rule {i} `{}` is an unanchored allow sitting above a deny — \
                 it can shadow the rule below it and can never be audited by \
                 reading the denies alone",
                r.r#match
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

    #[test]
    fn the_shadowed_commands_are_no_longer_allowed() {
        let p: crate::policy::Policy = serde_yaml::from_str(STARTER_POLICY).unwrap();
        for cmd in [
            "git branch -D main",
            "echo $(rm -rf /)",
            "git status & rm -rf /",
        ] {
            assert_ne!(
                p.evaluate_command(cmd).action,
                crate::policy::Action::Allow,
                "{cmd} is still allowed"
            );
        }
    }
}
