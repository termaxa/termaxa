//! The circuit breaker's state: a trip is an event, and so is its release.
//!
//! Until Oct 1, 2026 a trip was recomputed on every ask from the record's
//! recent history, so it ended silently: when the session changed, or when
//! 64 KB of other activity pushed the earlier attempts out of the window it
//! read. Nothing decided the resume and nothing recorded it. A resume now
//! leaves the same trace as the trip (Tim Schipper's third suggestion, Sep
//! 2026: who or what decided, on what evidence, recorded before the run
//! continues). A trip holds for the project, across sessions, until a
//! person resumes it with `termaxa breaker resume --reason "…"`, or until
//! the policy's optional `circuit_breaker.resume_after` expires it, and
//! either release is written to the record before the next command is
//! judged.

use crate::audit::{AuditEntry, AuditLog};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One tripped intent, held for the project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trip {
    /// The intent label (`file-delete`, `git-destructive`, …).
    pub intent: String,
    pub tripped_ts_ms: u128,
    pub tripped_ts: String,
    /// The session the attempts were made in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The commands that tripped it, the earlier attempts first.
    pub attempts: Vec<String>,
    /// When `circuit_breaker.resume_after` releases it, if configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_ts_ms: Option<u128>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    #[serde(default)]
    pub trips: Vec<Trip>,
}

fn file(state_dir: &Path) -> PathBuf {
    state_dir.join("breaker.json")
}

/// Load the project's trips; a missing or unreadable file is no trips.
pub fn load(state_dir: &Path) -> State {
    std::fs::read_to_string(file(state_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(state_dir: &Path, state: &State) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("create {}", state_dir.display()))?;
    let text = serde_json::to_string_pretty(state)?;
    std::fs::write(file(state_dir), text)
        .with_context(|| format!("write {}", file(state_dir).display()))
}

/// `"24h"`, `"90m"`, `"7d"`, `"3600s"` → milliseconds.
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = num.parse().ok()?;
    let mult = match unit.trim() {
        "s" | "sec" | "secs" => 1_000,
        "m" | "min" | "mins" => 60_000,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// The trip still holding `intent` at `now_ms`, if any.
pub fn active<'a>(state: &'a State, intent: &str, now_ms: u128) -> Option<&'a Trip> {
    state
        .trips
        .iter()
        .find(|t| t.intent == intent && t.expires_ts_ms.is_none_or(|e| now_ms < e))
}

/// The trips whose expiry has passed at `now_ms`.
pub fn expired(state: &State, now_ms: u128) -> Vec<Trip> {
    state
        .trips
        .iter()
        .filter(|t| t.expires_ts_ms.is_some_and(|e| now_ms >= e))
        .cloned()
        .collect()
}

/// The operating-system user, for a resume's `actor`.
pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn event(
    source_actor: &str,
    decision: &str,
    command: &str,
    reason: String,
    trip: &Trip,
    cwd: &str,
) -> AuditEntry {
    let (ts_ms, ts) = crate::audit::now();
    AuditEntry {
        call_id: None,
        ts_ms,
        ts,
        source: "breaker".into(),
        actor: Some(source_actor.into()),
        decided_by: Some("breaker".into()),
        command: command.chars().take(200).collect(),
        decision: decision.into(),
        // Not the breaker rule: `termaxa report` counts that as a blocked
        // command, and an event is not one.
        matched_rule: None,
        reason,
        signals: vec![],
        escalated: false,
        session: trip.session.clone(),
        backup: None,
        preview: None,
        intent: Some(trip.intent.clone()),
        approved: None,
        exit_code: None,
        cwd: cwd.into(),
        prev: None,
        hash: None,
    }
}

/// Record a trip: the event line carries the attempts that caused it.
pub fn record_trip(log: &AuditLog, trip: &Trip, cwd: &str) -> Result<()> {
    let n = trip.attempts.len();
    let reason = format!(
        "circuit breaker tripped: {n} {} attempt(s) in one session — {}. Holds for this project until `termaxa breaker resume --reason \"…\"`{}",
        trip.intent,
        trip.attempts.join("; "),
        match trip.expires_ts_ms {
            Some(_) => ", or until it expires",
            None => "",
        }
    );
    let last = trip.attempts.last().cloned().unwrap_or_default();
    log.append(&event("breaker", "tripped", &last, reason, trip, cwd))
}

/// Record a release, by a person (with their reason) or by expiry.
pub fn record_resume(log: &AuditLog, trip: &Trip, by: &str, why: &str, cwd: &str) -> Result<()> {
    let reason = format!(
        "circuit breaker resumed by {by}: {why} — the trip of {} at {} after {} attempt(s): {}",
        trip.intent,
        trip.tripped_ts,
        trip.attempts.len(),
        trip.attempts.join("; ")
    );
    log.append(&event(
        by,
        "resumed",
        "termaxa breaker resume",
        reason,
        trip,
        cwd,
    ))
}

/// Release every expired trip, recording each, and return the state left.
pub fn release_expired(
    state_dir: &Path,
    log: &AuditLog,
    mut state: State,
    now_ms: u128,
    cwd: &str,
) -> Result<State> {
    let gone = expired(&state, now_ms);
    if gone.is_empty() {
        return Ok(state);
    }
    for t in &gone {
        record_resume(
            log,
            t,
            "policy",
            "circuit_breaker.resume_after expired",
            cwd,
        )?;
    }
    state.trips.retain(|t| !gone.contains(t));
    save(state_dir, &state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_and_nonsense_does_not() {
        assert_eq!(parse_duration("24h"), Some(86_400_000));
        assert_eq!(parse_duration("90m"), Some(5_400_000));
        assert_eq!(parse_duration("7d"), Some(604_800_000));
        assert_eq!(parse_duration("3600s"), Some(3_600_000));
        assert_eq!(parse_duration(" 2 hours "), Some(7_200_000));
        assert_eq!(parse_duration("soon"), None);
        assert_eq!(parse_duration("24"), None);
        assert_eq!(parse_duration("-1h"), None);
    }

    #[test]
    fn a_trip_holds_until_it_expires_and_survives_a_reload() {
        let tmp = crate::testutil::TempTree::new("breaker-state");
        let dir = tmp.path().join("state");
        let trip = Trip {
            intent: "file-delete".into(),
            tripped_ts_ms: 1_000,
            tripped_ts: "t".into(),
            session: Some("s1".into()),
            attempts: vec!["rm -rf .".into(), "del /s /q .".into(), "rd /s /q .".into()],
            expires_ts_ms: Some(5_000),
        };
        let state = State {
            trips: vec![trip.clone()],
        };
        save(&dir, &state).unwrap();
        let back = load(&dir);
        assert_eq!(back, state, "the state round-trips through the file");
        // Held before expiry, in any session; released after.
        assert_eq!(active(&back, "file-delete", 4_999), Some(&trip));
        assert!(active(&back, "git-destructive", 4_999).is_none());
        assert!(active(&back, "file-delete", 5_000).is_none());
        assert_eq!(expired(&back, 5_000), vec![trip]);
        assert!(expired(&back, 4_999).is_empty());
        // A missing file is no trips, not an error.
        assert_eq!(load(&tmp.path().join("nowhere")), State::default());
    }
}
