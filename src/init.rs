use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

pub const STARTER_POLICY: &str = r#"# Termaxa policy — first matching rule wins; `*` is a wildcard.
# Actions: allow (run silently) | ask (require approval) | deny (block)
version: 1
default: ask

rules:
  # ---- read-only operations: let the agent work ----
  - match: "git status*"
    action: allow
  - match: "git diff*"
    action: allow
  - match: "git log*"
    action: allow
  - match: "git branch*"
    action: allow
  - match: "ls*"
    action: allow
  - match: "cat *"
    action: allow
  - match: "grep*"
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
  - match: "tofu apply*"
    action: ask
  - match: "tofu destroy*"
    action: deny
    reason: "tofu destroy is blocked by policy."
  - match: "kubectl get*"
    action: allow
  - match: "kubectl describe*"
    action: allow
  - match: "docker ps*"
    action: allow

  # ---- destructive: hard stops ----
  - match: "git push*--force*"
    action: deny
    reason: "Force pushes are blocked by policy. Open a PR instead."
  - match: "rm -rf /*"
    action: deny
    reason: "Recursive delete from root is blocked."
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

  # ---- consequential: human in the loop ----
  - match: "git push*"
    action: ask
  - match: "git commit*"
    action: allow
  - match: "terraform apply*"
    action: ask
  - match: "terraform destroy*"
    action: deny
    reason: "terraform destroy is blocked by policy."
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
                    "beforeShellExecution": [ { "command": cmd } ]
                }
            });
            fs::write(&hooks_path, serde_json::to_string_pretty(&hooks)?)?;
            println!("✓ wrote .cursor/hooks.json (absolute path -> termaxa hook)");
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
        fs::write(&settings_path, serde_json::to_string_pretty(&settings)?)?;
        println!("\n✓ installed PreToolUse hook in .claude/settings.json");
    }
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

fn which(bin: &str) -> bool {
    // `which` on Unix, `where` on Windows
    let finder = if cfg!(windows) { "where" } else { "which" };
    Command::new(finder)
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
