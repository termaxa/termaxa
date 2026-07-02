use std::process::Command;

/// An execution preview: what will actually happen if this command runs.
///
/// This module is the seed of the plugin system. `generate` inspects the
/// command and returns a preview if some plugin knows how to produce one.
/// Previews are strictly best-effort: any failure (not a repo, no remote,
/// tool missing) yields `None` and enforcement proceeds exactly as before.
/// A preview must never block or break a decision.
#[derive(Debug)]
pub struct Preview {
    pub title: String,
    /// Full preview lines, shown in `run` and `check`.
    pub lines: Vec<String>,
    /// One-line summary, embedded in the hook reason for Claude Code prompts.
    pub summary: String,
}

pub fn generate(command: &str) -> Option<Preview> {
    let cmd = crate::policy::normalize(command);
    if cmd.starts_with("git push") {
        return git_push_preview(&cmd);
    }
    if cmd.starts_with("psql") || cmd.contains(" psql ") {
        return crate::pg::preview_for(command);
    }
    None
}

/// What would `git push` actually send?
///
/// The core question is "compared to what?" — three cases:
///   1. branch has an upstream        -> @{u}..HEAD
///   2. no upstream, origin/<b> exists -> origin/<b>..HEAD
///   3. brand-new branch               -> everything is new
fn git_push_preview(command: &str) -> Option<Preview> {
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?;
    let force = command.contains("--force") || command.contains(" -f ");

    let (range, baseline) = if git(&["rev-parse", "--abbrev-ref", "@{u}"]).is_some() {
        ("@{u}..HEAD".to_string(), "upstream".to_string())
    } else {
        let remote_branch = format!("origin/{}", branch);
        if git(&["rev-parse", "--verify", "--quiet", &remote_branch]).is_some() {
            (format!("{}..HEAD", remote_branch), remote_branch)
        } else {
            // Case 3: nothing on the remote to compare against.
            let count = git(&["rev-list", "--count", "HEAD"])?;
            return Some(Preview {
                title: format!("push preview ({} -> new remote branch)", branch),
                lines: vec![format!(
                    "entire branch is new to the remote: {} commit(s)",
                    count
                )],
                summary: format!("new branch, {} commit(s)", count),
            });
        }
    };

    let count: u32 = git(&["rev-list", "--count", &range])?.parse().ok()?;

    // A force push's damage is what the remote LOSES — the reverse range.
    // Discovered live in v0.6.0: the preview said "nothing to push" while a
    // force push destroyed a commit. Gain and loss are different directions.
    let loss_range = range.replace("..HEAD", "").replace("HEAD", "");
    let mut loss_lines: Vec<String> = Vec::new();
    let mut loss_count: u32 = 0;
    if force && !loss_range.is_empty() {
        let reverse = format!("HEAD..{}", loss_range);
        if let Some(n) = git(&["rev-list", "--count", &reverse]).and_then(|s| s.parse().ok()) {
            loss_count = n;
            if n > 0 {
                loss_lines.push(format!("  ⚠ remote will LOSE {} commit(s):", n));
                if let Some(log) = git(&["log", "--oneline", "--no-decorate", &reverse]) {
                    for l in log.lines().take(5) {
                        loss_lines.push(format!("    ✗ {}", l));
                    }
                }
            }
        }
    }

    if count == 0 && loss_count == 0 {
        return Some(Preview {
            title: format!("push preview ({} -> {})", branch, baseline),
            lines: vec!["nothing to push — remote is up to date".to_string()],
            summary: "nothing to push".to_string(),
        });
    }

    let mut lines = loss_lines;

    // The commits that would be sent (cap at 5 to keep the prompt readable).
    if let Some(log) = git(&["log", "--oneline", "--no-decorate", &range]) {
        for (i, l) in log.lines().enumerate() {
            if i == 5 {
                lines.push(format!("  ... and {} more", count as usize - 5));
                break;
            }
            lines.push(format!("  {}", l));
        }
    }

    // File-level impact: last line of --stat is the totals summary.
    let mut files_changed = String::from("? files changed");
    if let Some(stat) = git(&["diff", "--stat", &range]) {
        if let Some(total) = stat.lines().last() {
            files_changed = total.trim().to_string();
        }
        let file_lines: Vec<&str> = stat.lines().collect();
        if file_lines.len() > 1 {
            lines.push(String::new());
            for l in file_lines.iter().take(file_lines.len() - 1).take(8) {
                lines.push(format!("  {}", l.trim()));
            }
            if file_lines.len() - 1 > 8 {
                lines.push(format!("  ... and {} more files", file_lines.len() - 1 - 8));
            }
        }
    }

    let mut summary = format!("{} commit(s); {}", count, files_changed);
    if loss_count > 0 {
        summary = format!("remote LOSES {} commit(s); {}", loss_count, summary);
    }
    Some(Preview {
        title: format!("push preview ({} -> {})", branch, baseline),
        lines,
        summary,
    })
}

/// Run a git command, returning trimmed stdout on success, None on any failure.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
