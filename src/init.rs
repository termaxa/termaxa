use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

const STARTER_POLICY: &str = r#"# Aegis policy — first matching rule wins; `*` is a wildcard.
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
  - match: "terraform plan*"
    action: allow
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
"#;

pub fn run(dir: &Path, write_claude_hook: bool) -> Result<()> {
    let aegis_dir = dir.join(".aegis");
    fs::create_dir_all(aegis_dir.join("logs"))?;

    let policy_path = aegis_dir.join("policy.yaml");
    if policy_path.exists() {
        println!("• .aegis/policy.yaml already exists — leaving it untouched");
    } else {
        fs::write(&policy_path, STARTER_POLICY)?;
        println!("✓ wrote .aegis/policy.yaml (starter policy)");
    }

    // --- detect agent harnesses ---
    println!("\nAgent harnesses detected:");
    let mut found_any = false;
    for (label, probe) in [
        ("Claude Code", dir.join(".claude").exists() || which("claude")),
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
        "git", "docker", "terraform", "kubectl", "aws", "psql", "npm", "cargo", "gh", "ssh",
    ] {
        if which(tool) {
            println!("  ✓ {}", tool);
        }
    }

    // --- wire up Claude Code PreToolUse hook ---
    if write_claude_hook {
        install_claude_hook(dir)?;
    } else {
        println!("\nTo wire Aegis into Claude Code, run: aegis init --claude-code");
        print_hook_snippet();
    }

    println!("\nDone. Try:  aegis check \"git push --force origin main\"");
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
        "hooks": [{ "type": "command", "command": "aegis hook" }]
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
            .map(|c| c.contains("aegis hook"))
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
          "hooks": [{{ "type": "command", "command": "aegis hook" }}]
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
