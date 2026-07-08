use crate::audit::{AuditEntry, AuditLog};
use crate::backup;
use crate::paths::Paths;
use anyhow::Result;
use std::collections::HashMap;

/// The Execution Report — the payoff of every other engine.
///
/// Composes audit entries, persisted preview summaries, and the backup
/// manifest into the summary a human reads after an AI session.
///
/// Honesty rule: every line is a fact with a source in the data. Nothing is
/// invented — no fake "time saved" minutes, no guessed file counts. The risk
/// score prints its own inputs so nobody has to trust a black box.
pub struct Scope {
    pub session: Option<String>,
    pub all: bool,
}

pub fn run(paths: &Paths, scope: Scope, markdown: bool) -> Result<i32> {
    let log = AuditLog::new(&paths.state_dir)?;
    let mut entries = log.read_last(1_000_000)?;
    if entries.is_empty() {
        println!("(no activity to report)");
        return Ok(0);
    }

    // Scope resolution: explicit session > latest session seen > everything.
    let session = if scope.all {
        None
    } else {
        scope
            .session
            .or_else(|| entries.iter().rev().find_map(|e| e.session.clone()))
    };
    if let Some(s) = &session {
        entries.retain(|e| e.session.as_deref() == Some(s));
        if entries.is_empty() {
            println!("(no entries for session {})", s);
            return Ok(1);
        }
    }

    let r = compute(&entries, paths)?;
    if markdown {
        print_markdown(&r, session.as_deref());
    } else {
        print_terminal(&r, session.as_deref());
    }
    Ok(0)
}

struct Report {
    first_ts: String,
    last_ts: String,
    duration_min: u64,
    total: usize,
    allow: usize,
    ask: usize,
    deny: usize,
    escalated: usize,
    auto_flow: usize, // allowed without any human interruption
    blocked: Vec<String>,
    impacts: Vec<String>,           // persisted preview summaries on ask/deny
    backups: Vec<(String, String)>, // (kind, note)
    risk_score: u32,
    risk_label: &'static str,
}

fn compute(entries: &[AuditEntry], paths: &Paths) -> Result<Report> {
    let count = |d: &str| entries.iter().filter(|e| e.decision == d).count();
    let (allow, ask, deny) = (count("allow"), count("ask"), count("deny"));
    let escalated = entries.iter().filter(|e| e.escalated).count();

    let blocked: Vec<String> = entries
        .iter()
        .filter(|e| e.decision == "deny")
        .map(|e| e.command.clone())
        .collect();

    // Impacts: preview summaries where the gate actually intervened.
    let mut impacts: Vec<String> = entries
        .iter()
        .filter(|e| e.decision != "allow")
        .filter_map(|e| e.preview.clone())
        .collect();
    impacts.dedup();

    // Backups referenced by these entries, joined against the manifest.
    let ids: Vec<&str> = entries.iter().filter_map(|e| e.backup.as_deref()).collect();
    let manifest = backup::list(&paths.state_dir)?;
    let by_id: HashMap<&str, &backup::BackupRecord> =
        manifest.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut backups: Vec<(String, String)> = ids
        .iter()
        .filter_map(|id| by_id.get(id))
        .map(|r| (r.kind.clone(), r.note.clone()))
        .collect();
    backups.dedup();

    // Transparent risk arithmetic: deny×3 + escalation×2 + ask×1.
    let risk_score = (deny as u32) * 3 + (escalated as u32) * 2 + (ask as u32);
    let risk_label = match risk_score {
        0..=2 => "Low",
        3..=7 => "Medium",
        _ => "High",
    };

    let (first, last) = (&entries[0], &entries[entries.len() - 1]);
    let duration_min = last.ts_ms.saturating_sub(first.ts_ms) as u64 / 60_000;

    Ok(Report {
        first_ts: first.ts.clone(),
        last_ts: last.ts.clone(),
        duration_min,
        total: entries.len(),
        allow,
        ask,
        deny,
        escalated,
        auto_flow: allow,
        blocked,
        impacts,
        backups,
        risk_score,
        risk_label,
    })
}

fn print_terminal(r: &Report, session: Option<&str>) {
    println!("┌─ Termaxa Execution Report ─────────────────────────");
    println!(
        "│ scope     : {}",
        session.map(short).unwrap_or_else(|| "all activity".into())
    );
    println!(
        "│ window    : {} → {}  ({} min)",
        r.first_ts, r.last_ts, r.duration_min
    );
    println!(
        "│ commands  : {}   ✓ {} allow · ? {} ask · ✗ {} deny",
        r.total, r.allow, r.ask, r.deny
    );
    println!("│ escalated : {}", r.escalated);
    println!(
        "│ auto-flow : {} command(s) ran without interruption",
        r.auto_flow
    );
    if !r.blocked.is_empty() {
        println!("│ blocked   :");
        for b in r.blocked.iter().take(5) {
            println!("│   ✗ {}", b);
        }
    }
    if !r.impacts.is_empty() {
        println!("│ impact (previews at intervention points):");
        for i in r.impacts.iter().take(6) {
            println!("│   • {}", i);
        }
    }
    if r.backups.is_empty() {
        println!("│ backups   : none — no insured operations in scope");
    } else {
        println!(
            "│ backups   : {} — rollback available (`termaxa backups`)",
            r.backups.len()
        );
        for (kind, note) in r.backups.iter().take(5) {
            println!("│   🛟 [{}] {}", kind, note);
        }
    }
    println!(
        "│ risk      : {}  (deny×3 + escalation×2 + ask×1 = {})",
        r.risk_label, r.risk_score
    );
    println!("└──────────────────────────────────────────────────");
}

fn print_markdown(r: &Report, session: Option<&str>) {
    println!("# Termaxa Execution Report\n");
    println!(
        "- **Scope:** {}",
        session.map(short).unwrap_or_else(|| "all activity".into())
    );
    println!(
        "- **Window:** {} → {} ({} min)",
        r.first_ts, r.last_ts, r.duration_min
    );
    println!(
        "- **Commands:** {} — {} allow / {} ask / {} deny",
        r.total, r.allow, r.ask, r.deny
    );
    println!("- **Escalated by context:** {}", r.escalated);
    println!(
        "- **Auto-flow:** {} command(s) without interruption",
        r.auto_flow
    );
    if !r.blocked.is_empty() {
        println!("\n## Blocked\n");
        for b in &r.blocked {
            println!("- `{}`", b);
        }
    }
    if !r.impacts.is_empty() {
        println!("\n## Impact at intervention points\n");
        for i in &r.impacts {
            println!("- {}", i);
        }
    }
    println!("\n## Insurance\n");
    if r.backups.is_empty() {
        println!("No insured operations in scope.");
    } else {
        for (kind, note) in &r.backups {
            println!("- **[{}]** {}", kind, note);
        }
        println!("\nRollback available via `termaxa rollback <id>`.");
    }
    println!(
        "\n## Risk: {}\n\nScore {} — transparent formula: deny×3 + escalation×2 + ask×1.",
        r.risk_label, r.risk_score
    );
}

fn short(s: &str) -> String {
    format!("session {}", &s[..s.len().min(8)])
}
