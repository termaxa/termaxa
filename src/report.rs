use crate::audit::{AuditEntry, AuditLog};
use crate::backup;
use crate::paths::Paths;
use anyhow::Result;
use std::collections::HashMap;

/// The Execution Report — the flight recorder.
///
/// Answers one question: "what actually happened while my AI agent was
/// working?" Composes audit entries, persisted preview summaries, and the
/// backup manifest into the summary a human reads after an AI session, plus a
/// 30-day rollup for the longer view.
///
/// Honesty rule: every line is a fact with a source in the data. Nothing is
/// invented — no fake "time saved" minutes, no guessed file counts, no
/// estimated token costs (that needs the agent's own transcripts — see the
/// token-cost issue; it is deliberately NOT computed here). The risk score
/// prints its own inputs so nobody has to trust a black box.
pub struct Scope {
    pub session: Option<String>,
    pub all: bool,
    /// Rollup window for the "Last N days" section (default 30).
    pub days: u64,
}

impl Default for Scope {
    fn default() -> Self {
        Scope {
            session: None,
            all: false,
            days: 30,
        }
    }
}

pub fn run(paths: &Paths, scope: Scope, markdown: bool) -> Result<i32> {
    let log = AuditLog::new(&paths.state_dir)?;
    let all_entries = log.read_last(1_000_000)?;
    if all_entries.is_empty() {
        println!("(no activity to report)");
        return Ok(0);
    }

    // Scope resolution: explicit session > latest session seen > everything.
    let session = if scope.all {
        None
    } else {
        scope
            .session
            .clone()
            .or_else(|| all_entries.iter().rev().find_map(|e| e.session.clone()))
    };

    let mut entries: Vec<&AuditEntry> = all_entries.iter().collect();
    if let Some(s) = &session {
        entries.retain(|e| e.session.as_deref() == Some(s.as_str()));
        if entries.is_empty() {
            println!("(no entries for session {})", s);
            return Ok(1);
        }
    }

    let r = compute(&entries, paths)?;
    let rollup = compute_rollup(&all_entries, scope.days);

    if markdown {
        print_markdown(&r, &rollup, session.as_deref());
    } else {
        print_terminal(&r, &rollup, session.as_deref());
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
    auto_flow: usize,
    blocked: Vec<String>,
    impacts: Vec<String>,
    backups: Vec<(String, String)>,
    rollbacks: usize,
    breaker_trips: usize,
    /// (intent-label, count) for every destructive intent CLASSIFIED in scope,
    /// most frequent first. This counts commands the classifier recognised —
    /// not breaker trips. A legitimate `rm -rf ./build` is counted here.
    intents: Vec<(String, usize)>,
    /// (intent-label, count) restricted to entries the breaker actually
    /// escalated. This is the number the Insight keys off: repeated *blocked*
    /// attempts, not merely repeated destructive work.
    trips_by_intent: Vec<(String, usize)>,
    /// Last N audit lines as (mark, command) for the "Recent events" section.
    /// Mark is a String because it may carry ANSI colour (see `ui::mark`).
    recent: Vec<(String, String)>,
    risk_score: u32,
    risk_label: &'static str,
}

/// Map a decision (and source) to a terminal mark.
///
/// Delegates to `ui::mark` so every surface agrees on both the glyph and the
/// colour, and so the post-receipt rule lives in exactly one place: an
/// executed/post record is a success (✓), not a denial (✗).
fn mark_for(decision: &str, source: &str) -> String {
    crate::ui::mark(decision, source)
}

fn compute(entries: &[&AuditEntry], paths: &Paths) -> Result<Report> {
    let count = |d: &str| entries.iter().filter(|e| e.decision == d).count();
    let (allow, ask, deny) = (count("allow"), count("ask"), count("deny"));
    let escalated = entries.iter().filter(|e| e.escalated).count();

    let blocked: Vec<String> = entries
        .iter()
        .filter(|e| e.decision == "deny")
        .map(|e| e.command.clone())
        .collect();

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

    // Rollbacks: post-execution records whose command is a termaxa rollback,
    // OR entries the runner tagged as a rollback. We count "post" receipts
    // referencing a backup id as the honest proxy for a restore having run.
    let rollbacks = entries
        .iter()
        .filter(|e| e.source == "post" && e.command.contains("rollback"))
        .count();

    let breaker_trips = entries
        .iter()
        .filter(|e| e.matched_rule.as_deref() == Some(crate::intent::BREAKER_RULE))
        .count();

    // Per-intent breakdown: group the classified intent field, most first.
    let mut intent_map: HashMap<String, usize> = HashMap::new();
    for e in entries {
        if let Some(i) = &e.intent {
            *intent_map.entry(i.clone()).or_insert(0) += 1;
        }
    }
    let mut intents: Vec<(String, usize)> = intent_map.into_iter().collect();
    intents.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Trips by intent: only entries the circuit breaker escalated. This is
    // what "the breaker fired" means — distinct from "a destructive command
    // was classified", which is the `intents` map above.
    let mut trip_map: HashMap<String, usize> = HashMap::new();
    for e in entries {
        if e.matched_rule.as_deref() == Some(crate::intent::BREAKER_RULE) {
            if let Some(i) = &e.intent {
                *trip_map.entry(i.clone()).or_insert(0) += 1;
            }
        }
    }
    let mut trips_by_intent: Vec<(String, usize)> = trip_map.into_iter().collect();
    trips_by_intent.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Recent events: last 6 entries in scope, with corrected marks.
    let recent: Vec<(String, String)> = entries
        .iter()
        .rev()
        .take(6)
        .rev()
        .map(|e| (mark_for(&e.decision, &e.source), e.command.clone()))
        .collect();

    let risk_score = (deny as u32) * 3 + (escalated as u32) * 2 + (ask as u32);
    let risk_label = match risk_score {
        0..=2 => "Low",
        3..=7 => "Medium",
        _ => "High",
    };

    let (first, last) = (entries[0], entries[entries.len() - 1]);
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
        rollbacks,
        breaker_trips,
        intents,
        trips_by_intent,
        recent,
        risk_score,
        risk_label,
    })
}

/// The "Last N days" rollup — every session in the window, not just the
/// current one. Cheap: a single pass over the already-read log.
struct Rollup {
    days: u64,
    sessions: usize,
    commands: usize,
    allow: usize,
    ask: usize,
    deny: usize,
    backups: usize,
    breaker_trips: usize,
    top_dirs: Vec<String>,
}

fn compute_rollup(all: &[AuditEntry], days: u64) -> Rollup {
    let cutoff_ms = {
        let now = crate::audit::now().0;
        now.saturating_sub((days as u128) * 24 * 60 * 60 * 1000)
    };
    let win: Vec<&AuditEntry> = all.iter().filter(|e| e.ts_ms >= cutoff_ms).collect();

    let mut sessions: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for e in &win {
        if let Some(s) = &e.session {
            sessions.insert(s.as_str());
        }
    }

    let d = |dec: &str| win.iter().filter(|e| e.decision == dec).count();
    let backups = win.iter().filter(|e| e.backup.is_some()).count();
    let breaker_trips = win
        .iter()
        .filter(|e| e.matched_rule.as_deref() == Some(crate::intent::BREAKER_RULE))
        .count();

    // Most active working directories, by cwd basename. NOT projects: state
    // is stored per project (paths.rs) and `run` reads a single state dir, so
    // everything here comes from one project — these are its subdirectories.
    // The label used to say "Top projects", which implied a cross-project view
    // the command cannot produce.
    let mut proj: HashMap<String, usize> = HashMap::new();
    for e in &win {
        let name = e
            .cwd
            .rsplit(['/', '\\'])
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .to_string();
        if !name.is_empty() {
            *proj.entry(name).or_insert(0) += 1;
        }
    }
    let mut projects: Vec<(String, usize)> = proj.into_iter().collect();
    projects.sort_by_key(|p| std::cmp::Reverse(p.1));
    let top_dirs = projects.into_iter().take(3).map(|(n, _)| n).collect();

    Rollup {
        days,
        sessions: sessions.len(),
        commands: win.len(),
        allow: d("allow"),
        ask: d("ask"),
        deny: d("deny"),
        backups,
        breaker_trips,
        top_dirs,
    }
}

/// Human-readable Insight for a repeatedly-*blocked* intent. Diagnostic, not
/// scolding: we don't know *why* it recurred, so we name the usual causes and
/// leave the judgment to the developer.
///
/// Keyed off circuit-breaker TRIPS, not merely classified intents — three
/// legitimate `rm -rf ./build` runs are normal work and must not trigger a
/// lecture. Three *blocked* attempts of the same intent is a policy signal.
const INSIGHT_THRESHOLD: usize = 3;

fn insight_for(label: &str) -> Option<Vec<&'static str>> {
    match label {
        "file-delete" => Some(vec![
            "generated files being cleaned",
            "build/output directories",
            "an agent retry loop",
        ]),
        "git-destructive" => Some(vec![
            "force-pushing a rebased branch",
            "resetting a work-in-progress branch",
            "an agent retrying a blocked push",
        ]),
        "db-destroy" => Some(vec![
            "resetting a local/test database",
            "a migration teardown step",
            "an agent retrying a blocked drop",
        ]),
        "infra-destroy" => Some(vec![
            "tearing down ephemeral/test infra",
            "a CI cleanup step",
            "an agent retrying a blocked destroy",
        ]),
        _ => None,
    }
}

fn print_terminal(r: &Report, roll: &Rollup, session: Option<&str>) {
    let line = "──────────────────────────────────────────";

    use crate::ui::{amber, bold, dim, green, red};

    println!(
        "\n{}   {}",
        bold("Session"),
        dim(&session.map(short).unwrap_or_default())
    );
    println!("{}", dim(line));
    println!("Duration            {} min", r.duration_min);
    println!(
        "Commands            {}   {} {} · {} {} · {} {}",
        r.total,
        green("✓"),
        r.allow,
        amber("?"),
        r.ask,
        red("✗"),
        r.deny
    );
    println!("Escalated           {}", r.escalated);
    println!("Auto-flow           {}", r.auto_flow);
    println!("Previews            {}", r.impacts.len());
    println!("Backups             {}", r.backups.len());
    println!("Rollbacks           {}", r.rollbacks);

    // Destructive intents seen (classified commands), then trips separately.
    // These are different numbers: a legitimate `rm -rf ./build` is an intent,
    // not a trip. Keeping them apart keeps the report honest.
    if !r.intents.is_empty() {
        println!("\n{}", bold("Destructive intents"));
        println!("{}", dim(line));
        for (label, count) in &r.intents {
            println!("{:<20}{}", label, count);
        }
        println!("{:<20}{}", "breaker trips", r.breaker_trips);
    }

    // Insight: fires when the breaker blocked the SAME intent repeatedly.
    if let Some((label, count)) = r.trips_by_intent.first() {
        if *count >= INSIGHT_THRESHOLD {
            if let Some(causes) = insight_for(label) {
                println!("\n{}", bold(&amber("Insight")));
                println!("{}", dim(line));
                println!(
                    "The breaker blocked {} {} times in this scope.",
                    label, count
                );
                println!();
                println!("This often indicates:");
                for c in causes {
                    println!("• {}", c);
                }
                println!();
                println!("If this work is intentional, add an explicit allow rule");
                println!("scoped to the paths involved — relaxation is deliberate.");
            }
        }
    }

    // Recent events.
    if !r.recent.is_empty() {
        println!("\n{}", bold("Recent events"));
        println!("{}", dim(line));
        for (mark, cmd) in &r.recent {
            println!("{} {}", mark, cmd);
        }
    }

    // Insurance + risk.
    println!();
    if r.backups.is_empty() {
        println!("Backups   : none — no insured operations in scope");
    } else {
        println!(
            "Backups   : {} — rollback available (`termaxa backups`)",
            r.backups.len()
        );
        for (kind, note) in r.backups.iter().take(5) {
            println!("  🛟 [{}] {}", kind, note);
        }
    }
    let risk_coloured = match r.risk_label {
        "Low" => green(r.risk_label),
        "Medium" => amber(r.risk_label),
        _ => red(r.risk_label),
    };
    println!(
        "Risk      : {}  {}",
        risk_coloured,
        dim(&format!(
            "(deny×3 + escalation×2 + ask×1 = {})",
            r.risk_score
        ))
    );

    // Rollup.
    println!("\n{}", bold(&format!("Last {} days", roll.days)));
    println!("{}", dim(line));
    println!("Sessions        {}", roll.sessions);
    println!("Commands        {}", roll.commands);
    println!(
        "Decisions       {} {} · {} {} · {} {}",
        green("✓"),
        roll.allow,
        amber("?"),
        roll.ask,
        red("✗"),
        roll.deny
    );
    println!("Backups         {}", roll.backups);
    println!("Breaker trips   {}", roll.breaker_trips);
    if !roll.top_dirs.is_empty() {
        println!("\n{}", bold("Top directories"));
        for p in &roll.top_dirs {
            println!("  {}", p);
        }
    }
    println!();
}

fn print_markdown(r: &Report, roll: &Rollup, session: Option<&str>) {
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
    println!("- **Auto-flow:** {} without interruption", r.auto_flow);
    println!("- **Previews:** {}", r.impacts.len());
    println!("- **Backups:** {}", r.backups.len());
    println!("- **Rollbacks:** {}", r.rollbacks);

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
    if !r.intents.is_empty() {
        println!("\n## Destructive intents\n");
        for (label, count) in &r.intents {
            println!("- **{}** — {} classified", label, count);
        }
        println!("- **breaker trips** — {}", r.breaker_trips);
    }
    if let Some((label, count)) = r.trips_by_intent.first() {
        if *count >= INSIGHT_THRESHOLD {
            if let Some(causes) = insight_for(label) {
                println!("\n## Insight\n");
                println!(
                    "The breaker blocked **{}** {} times in this scope. This often indicates:\n",
                    label, count
                );
                for c in causes {
                    println!("- {}", c);
                }
                println!("\nIf this work is intentional, add an explicit allow rule scoped to the paths involved — relaxation is deliberate.");
            }
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
    println!("\n## Last {} days\n", roll.days);
    println!("- **Sessions:** {}", roll.sessions);
    println!("- **Commands:** {}", roll.commands);
    println!(
        "- **Decisions:** {} allow / {} ask / {} deny",
        roll.allow, roll.ask, roll.deny
    );
    println!("- **Backups:** {}", roll.backups);
    println!("- **Breaker trips:** {}", roll.breaker_trips);
    if !roll.top_dirs.is_empty() {
        println!("- **Top directories:** {}", roll.top_dirs.join(", "));
    }
}

fn short(s: &str) -> String {
    format!("session {}", &s[..s.len().min(8)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::Intent;
    use crate::testutil::TempTree;

    /// One audit line. Tests override only the fields they are about, so the
    /// thing under test is visible in the test rather than in the fixture.
    fn entry(decision: &str, command: &str) -> AuditEntry {
        AuditEntry {
            ts_ms: 0,
            ts: "2026-01-01T00:00:00Z".into(),
            source: "hook".into(),
            command: command.into(),
            decision: decision.into(),
            matched_rule: None,
            reason: "because".into(),
            signals: Vec::new(),
            escalated: false,
            session: None,
            backup: None,
            preview: None,
            intent: None,
            approved: None,
            exit_code: None,
            cwd: "/work/proj".into(),
            prev: None,
            hash: None,
        }
    }

    fn paths_in(tmp: &TempTree) -> Paths {
        Paths {
            project_dir: tmp.dir("proj/.termaxa"),
            state_dir: tmp.dir("state"),
        }
    }

    /// `compute` over a fresh state dir. The tree is returned so it outlives
    /// the report; dropping it early would delete the manifest under it.
    fn compute_for(entries: &[AuditEntry]) -> (Report, TempTree) {
        let tmp = TempTree::new("report");
        let paths = paths_in(&tmp);
        let refs: Vec<&AuditEntry> = entries.iter().collect();
        let report = compute(&refs, &paths).expect("compute must succeed");
        (report, tmp)
    }

    fn n_of(decision: &str, n: usize) -> Vec<AuditEntry> {
        (0..n)
            .map(|i| entry(decision, &format!("{decision}{i}")))
            .collect()
    }

    #[test]
    fn decision_counts_and_the_risk_formula_are_exact() {
        // 1 deny, 3 escalated, 5 ask: chosen so that every coefficient and
        // every operator in deny×3 + escalated×2 + ask×1 changes the answer
        // if it is swapped. Equal counts would let ×2 and +2 agree.
        let mut entries = vec![entry("deny", "rm -rf /")];
        entries.extend(n_of("ask", 5));
        for i in 0..3 {
            let mut e = entry("allow", &format!("escalated{i}"));
            e.escalated = true;
            entries.push(e);
        }

        let (r, _tree) = compute_for(&entries);
        assert_eq!(
            (r.total, r.allow, r.ask, r.deny, r.escalated),
            (9, 3, 5, 1, 3)
        );
        assert_eq!(r.risk_score, 3 + 6 + 5);
        assert_eq!(r.risk_label, "High");
        assert_eq!(r.auto_flow, r.allow, "auto-flow is the uninterrupted count");
    }

    #[test]
    fn the_risk_bands_are_pinned_at_their_boundaries() {
        // One ask is one point, so the count IS the score here.
        for (asks, label) in [
            (0, "Low"),
            (2, "Low"),
            (3, "Medium"),
            (7, "Medium"),
            (8, "High"),
        ] {
            let mut entries = vec![entry("allow", "ls")];
            entries.extend(n_of("ask", asks));
            let (r, _tree) = compute_for(&entries);
            assert_eq!(
                (r.risk_score, r.risk_label),
                (asks as u32, label),
                "{asks} asks should read as {label}"
            );
        }
    }

    #[test]
    fn blocked_lists_denials_and_impacts_skip_what_simply_ran() {
        let mut denied = entry("deny", "drop table users");
        denied.preview = Some("DROP TABLE users".into());
        let mut allowed = entry("allow", "select 1");
        allowed.preview = Some("SELECT 1 row".into());
        let mut asked = entry("ask", "delete from sessions");
        asked.preview = Some("DELETE ~120,000 rows".into());

        let (r, _tree) = compute_for(&[allowed, denied, asked]);
        assert_eq!(r.blocked, ["drop table users"]);
        // An allow's preview is not an intervention point: nothing intervened.
        assert_eq!(r.impacts, ["DROP TABLE users", "DELETE ~120,000 rows"]);
    }

    #[test]
    fn a_rollback_is_a_post_receipt_that_names_a_rollback() {
        let mut receipt = entry("allow", "termaxa rollback abc123");
        receipt.source = "post".into();
        let mut other_receipt = entry("allow", "ls -la");
        other_receipt.source = "post".into();
        // Two of these: a single one would let "not a post receipt" score the
        // same as the real rule and hide the swap.
        let asked_once = entry("ask", "termaxa rollback def456");
        let asked_twice = entry("ask", "termaxa rollback ghi789");

        let (r, _tree) = compute_for(&[receipt, other_receipt, asked_once, asked_twice]);
        assert_eq!(
            r.rollbacks, 1,
            "both halves hold: a post receipt AND a rollback command"
        );
    }

    #[test]
    fn intents_count_classifications_while_trips_count_blocks() {
        let breaker = crate::intent::BREAKER_RULE;
        let tripped = |command: &str, label: &str| {
            let mut e = entry("deny", command);
            e.matched_rule = Some(breaker.into());
            e.intent = Some(label.into());
            e
        };
        // Classified but never blocked: legitimate destructive work.
        let mut ordinary = entry("allow", "rm -rf ./build");
        ordinary.intent = Some("file-delete".into());

        let (r, _tree) = compute_for(&[
            tripped("rm -rf /", "file-delete"),
            tripped("rm -rf /etc", "file-delete"),
            ordinary,
            tripped("drop database prod", "db-destroy"),
        ]);

        assert_eq!(r.breaker_trips, 3);
        assert_eq!(
            r.intents,
            [
                ("file-delete".to_string(), 3),
                ("db-destroy".to_string(), 1)
            ],
            "intents count every classification, blocked or not"
        );
        assert_eq!(
            r.trips_by_intent,
            [
                ("file-delete".to_string(), 2),
                ("db-destroy".to_string(), 1)
            ],
            "trips count only what the breaker actually stopped"
        );
    }

    #[test]
    fn equally_frequent_intents_are_ordered_alphabetically() {
        // Ties have to break somewhere, or the report reorders itself between
        // runs on identical data.
        let with_intent = |label: &str| {
            let mut e = entry("allow", "cmd");
            e.intent = Some(label.into());
            e
        };
        let (r, _tree) = compute_for(&[
            with_intent("git-destructive"),
            with_intent("db-destroy"),
            with_intent("infra-destroy"),
        ]);
        let labels: Vec<&str> = r.intents.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(labels, ["db-destroy", "git-destructive", "infra-destroy"]);
    }

    #[test]
    fn recent_events_are_the_last_six_oldest_first() {
        let entries = n_of("allow", 8);
        let (r, _tree) = compute_for(&entries);

        let commands: Vec<&str> = r.recent.iter().map(|(_, c)| c.as_str()).collect();
        assert_eq!(
            commands,
            ["allow2", "allow3", "allow4", "allow5", "allow6", "allow7"]
        );
        assert!(r.recent[0].0.contains('✓'), "an allow is marked as success");
    }

    #[test]
    fn the_window_spans_the_first_and_last_entry() {
        let mut first = entry("allow", "first");
        first.ts_ms = 60_000;
        first.ts = "2026-01-01T00:01:00Z".into();
        let mut last = entry("allow", "last");
        last.ts_ms = 60_000 * 8;
        last.ts = "2026-01-01T00:08:00Z".into();

        let (r, _tree) = compute_for(&[first, last]);
        assert_eq!(r.duration_min, 7);
        assert_eq!(r.first_ts, "2026-01-01T00:01:00Z");
        assert_eq!(r.last_ts, "2026-01-01T00:08:00Z");
    }

    #[test]
    fn a_clock_that_went_backwards_reports_no_duration() {
        // saturating_sub: a line stamped before its predecessor must not
        // underflow into a duration of half a billion years.
        let mut first = entry("allow", "first");
        first.ts_ms = 60_000 * 8;
        let mut last = entry("allow", "last");
        last.ts_ms = 60_000;

        let (r, _tree) = compute_for(&[first, last]);
        assert_eq!(r.duration_min, 0);
    }

    #[test]
    fn backups_are_joined_against_the_manifest_and_unknown_ids_dropped() {
        let tmp = TempTree::new("report-backups");
        let paths = paths_in(&tmp);
        let manifest = tmp.dir("state/backups").join("manifest.jsonl");
        std::fs::write(
            &manifest,
            "{\"id\":\"b1\",\"ts\":\"t\",\"kind\":\"pg-dump\",\"command\":\"psql\",\
             \"data\":{},\"note\":\"dump of sessions\"}\n",
        )
        .expect("manifest must be writable");

        let mut insured = entry("allow", "psql -c 'truncate sessions'");
        insured.backup = Some("b1".into());
        let mut dangling = entry("allow", "psql -c 'truncate users'");
        // An id with no manifest record must not invent a backup line.
        dangling.backup = Some("b404".into());

        let refs = vec![&insured, &dangling];
        let r = compute(&refs, &paths).expect("compute must succeed");
        assert_eq!(
            r.backups,
            [("pg-dump".to_string(), "dump of sessions".to_string())]
        );
    }

    #[test]
    fn the_rollup_window_excludes_what_fell_out_of_it() {
        let now = crate::audit::now().0;
        let day_ms: u128 = 24 * 60 * 60 * 1000;

        let mut fresh = entry("allow", "fresh");
        fresh.ts_ms = now;
        fresh.session = Some("s1".into());
        fresh.backup = Some("b1".into());
        let mut stale = entry("deny", "stale");
        stale.ts_ms = now - 31 * day_ms;
        stale.session = Some("s2".into());

        let roll = compute_rollup(&[stale, fresh], 30);
        assert_eq!(roll.days, 30);
        assert_eq!(
            (
                roll.commands,
                roll.sessions,
                roll.allow,
                roll.ask,
                roll.deny
            ),
            (1, 1, 1, 0, 0),
            "the entry from 31 days ago is outside a 30-day window"
        );
        assert_eq!(roll.backups, 1);
    }

    #[test]
    fn the_rollup_cutoff_is_exactly_the_window_in_days() {
        // Days have to be converted to milliseconds by multiplication, all the
        // way down. Any other arithmetic lands the cutoff hours or minutes ago
        // instead of days, so an entry well inside the window falls out of it
        // — which is what these two entries are placed to detect.
        let now = crate::audit::now().0;
        let day_ms: u128 = 24 * 60 * 60 * 1000;
        let at = |ago: u128, command: &str| {
            let mut e = entry("allow", command);
            e.ts_ms = now - ago * day_ms;
            e
        };

        let roll = compute_rollup(&[at(9, "outside"), at(5, "inside")], 7);
        assert_eq!(
            roll.commands, 1,
            "five days ago is inside a seven-day window and nine days ago is not"
        );
    }

    #[test]
    fn the_rollup_counts_breaker_trips_not_everything_else() {
        let now = crate::audit::now().0;
        let tripped = |command: &str| {
            let mut e = entry("deny", command);
            e.ts_ms = now;
            e.matched_rule = Some(crate::intent::BREAKER_RULE.into());
            e
        };
        let mut ordinary = entry("allow", "ls");
        ordinary.ts_ms = now;
        ordinary.matched_rule = Some("allow-listing".into());

        // Two and one, not one and one: equal counts would let "everything
        // that is NOT a trip" score the same as the real rule.
        let roll = compute_rollup(&[tripped("rm -rf /"), tripped("rm -rf /etc"), ordinary], 30);
        assert_eq!(roll.breaker_trips, 2);
    }

    #[test]
    fn the_rollup_ranks_the_busiest_directories_by_basename() {
        let now = crate::audit::now().0;
        let in_dir = |cwd: &str| {
            let mut e = entry("allow", "cmd");
            e.ts_ms = now;
            e.cwd = cwd.into();
            e
        };
        let mut entries: Vec<AuditEntry> = Vec::new();
        for _ in 0..3 {
            entries.push(in_dir("/work/alpha"));
        }
        for _ in 0..2 {
            entries.push(in_dir("/work/beta/"));
        }
        entries.push(in_dir("C:\\work\\gamma"));
        entries.push(in_dir("/work/delta"));
        // A root cwd has no basename to report and must not become an entry.
        entries.push(in_dir("/"));

        let roll = compute_rollup(&entries, 30);
        assert_eq!(roll.top_dirs.len(), 3, "at most three are shown");
        assert_eq!(&roll.top_dirs[..2], ["alpha", "beta"], "busiest first");
        assert!(
            !roll.top_dirs.contains(&String::new()),
            "a nameless directory is not a directory: {:?}",
            roll.top_dirs
        );
    }

    #[test]
    fn a_session_label_is_shortened_for_display() {
        assert_eq!(short("0123456789abcdef"), "session 01234567");
        // Shorter than the cut is left whole rather than panicking on a slice.
        assert_eq!(short("abc"), "session abc");
    }

    #[test]
    fn a_report_with_no_activity_says_so_and_still_succeeds() {
        let tmp = TempTree::new("report-empty");
        let paths = paths_in(&tmp);
        assert_eq!(
            run(&paths, Scope::default(), false).expect("an empty log is not an error"),
            0
        );
    }

    #[test]
    fn asking_for_a_session_that_is_not_there_fails_rather_than_reporting_everything() {
        let tmp = TempTree::new("report-session");
        let paths = paths_in(&tmp);
        let log = AuditLog::new(&paths.state_dir).expect("log must be creatable");
        for command in ["one", "two"] {
            let mut e = entry("allow", command);
            e.session = Some("abc12345".into());
            log.append(&e).expect("append must succeed");
        }

        let scope = Scope {
            session: Some("nope".into()),
            ..Scope::default()
        };
        assert_eq!(
            run(&paths, scope, false).expect("an empty scope is not an error"),
            1,
            "a scope with nothing in it must not report the whole log instead"
        );

        // The same log, scoped the ordinary way, is a report.
        assert_eq!(run(&paths, Scope::default(), true).unwrap(), 0);
        assert_eq!(
            run(
                &paths,
                Scope {
                    all: true,
                    ..Scope::default()
                },
                false
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn post_receipt_renders_as_success_not_denial() {
        // The v0.11.4 post-execution receipt bug: an executed command was
        // rendering with the ✗ mark because its decision was still "ask".
        // `contains` rather than `assert_eq!` because the mark may carry ANSI
        // colour depending on whether stdout is a terminal.
        assert!(mark_for("ask", "post").contains('✓'));
        assert!(mark_for("deny", "post").contains('✓'));
        // Normal marks unaffected.
        assert!(mark_for("allow", "hook").contains('✓'));
        assert!(mark_for("ask", "hook").contains('?'));
        assert!(mark_for("deny", "hook").contains('✗'));
    }

    #[test]
    fn insight_causes_exist_for_every_intent_label() {
        // Every label the intent taxonomy can emit must have an Insight body,
        // or the section silently never fires for that intent.
        for label in [
            Intent::FileDelete.label(),
            Intent::DbDestroy.label(),
            Intent::GitDestructive.label(),
            Intent::InfraDestroy.label(),
        ] {
            assert!(
                insight_for(label).is_some(),
                "no Insight copy for intent label `{}`",
                label
            );
        }
        assert!(insight_for("not-an-intent").is_none());
    }

    #[test]
    fn insight_threshold_is_about_trips_not_classifications() {
        // Documents the semantic fix: three legitimate destructive commands
        // are normal work; three *blocked* attempts are a policy signal.
        // (Guards the constant against being re-pointed at `intents`.)
        assert_eq!(INSIGHT_THRESHOLD, 3);
    }
}
