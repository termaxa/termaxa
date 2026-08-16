use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    /// Unix epoch milliseconds.
    pub ts_ms: u128,
    /// Human-readable UTC timestamp.
    pub ts: String,
    /// "hook" (agent-invoked) or "run" (CLI-invoked) or "check".
    pub source: String,
    pub command: String,
    /// allow | ask | deny
    pub decision: String,
    pub matched_rule: Option<String>,
    pub reason: String,
    /// Signals the context engine observed.
    pub signals: Vec<String>,
    /// Whether context escalated the base decision.
    pub escalated: bool,
    /// Agent session that caused this entry (from Claude Code hook events).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Backup taken before execution, if any (see `termaxa backups`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
    /// Preview summary at decision time (e.g. "DELETE ALL from sessions
    /// ~120,000 rows") — persisted so reports can aggregate impact as fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// Destructive-intent classification (v0.11+): file-delete | db-destroy
    /// | git-destructive | infra-destroy. Serde-defaulted so pre-v0.11 log
    /// lines parse as None (decision #7: backward-compatible audit schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// For "run": did the human approve an `ask`? For hook mode this is None
    /// (the agent harness owns the approval UI).
    pub approved: Option<bool>,
    /// For "run": process exit code if the command executed.
    pub exit_code: Option<i32>,
    pub cwd: String,

    // ---- provenance (v0.16, roadmap 2.6) ----
    //
    // Serde-defaulted, so pre-v0.16 lines parse as None (decision #7).
    /// Which agent harness produced this event: claude-code, cursor, codex,
    /// copilot. Absent for `run` and `check`, which are the human's own
    /// surfaces and have no harness to name.
    ///
    /// The hook has always known this - it picks the response format from it -
    /// and threw it away. With two harnesses active in one project the audit
    /// could not say which caused an entry.
    ///
    /// NOT the OS user. In basic mode the hook runs as the agent's own UID, so
    /// recording it would record the agent's claim about itself dressed as
    /// provenance. Supervised mode (v0.17) gets a peer UID from SO_PEERCRED,
    /// which is an identity the agent cannot forge, and that deserves its own
    /// field when it exists rather than an empty half of a struct now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// What determined the verdict: default (no rule matched), rule, context.
    ///
    /// Deliberately NOT called `source`, which on this struct already means
    /// something else - which SURFACE invoked Termaxa (hook, run, check,
    /// post). Two different questions, and one word for both would have made
    /// the record ambiguous in a way no query could recover from.
    ///
    /// This is `DecisionSource` persisted, not a second representation of the
    /// same fact. A silent default-allow is then a JOIN of fields that already
    /// exist - source=hook, decided_by=default, decision=allow - rather than a
    /// `silent_default_allow: bool` that would duplicate the information and
    /// eventually drift from it (#37).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,

    // ---- hash chain (v0.16, issue #13) ----
    //
    // Serde-defaulted so every pre-chain line parses as None, per decision #7:
    // the audit schema is append-only and backward compatible, and an upgrade
    // must not make existing history unreadable.
    /// Hash of the entry before this one, chaining the record together.
    /// `None` on pre-chain entries and on the boundary entry itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// This entry's own hash, over its content and `prev`. `None` on
    /// pre-chain entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl AuditEntry {
    /// The bytes this entry's hash covers: every field except `hash` itself,
    /// in the serialized form that was actually written.
    ///
    /// Computed from the serialized line rather than a hand-built string, so
    /// a field added later is covered automatically. A hand-built list is a
    /// second place to remember, and the one that gets forgotten.
    fn digest(&self) -> String {
        let mut bare: AuditEntry = self.clone();
        bare.hash = None;
        let json = serde_json::to_string(&bare).unwrap_or_default();
        crate::fingerprint::sha256_hex(json.as_bytes())
    }

    /// Was this entry written before the chain existed?
    pub fn is_pre_chain(&self) -> bool {
        self.hash.is_none()
    }
}

/// What a verification pass found.
///
/// Reports rather than refuses. A log with a broken link still has a readable
/// prefix and a readable suffix, and throwing all of it away because one line
/// is corrupt would destroy more evidence than the corruption did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Entries written before the chain existed. Readable, and explicitly not
    /// vouched for - the record has two eras and says so.
    pub pre_chain: usize,
    /// Entries covered by an intact chain.
    pub verified: usize,
    /// 1-based positions where the chain does not hold.
    pub breaks: Vec<usize>,
}

impl ChainReport {
    pub fn is_intact(&self) -> bool {
        self.breaks.is_empty()
    }
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Log lives at `<termaxa_dir>/logs/audit.jsonl`.
    pub fn new(termaxa_dir: &Path) -> Result<Self> {
        let dir = termaxa_dir.join("logs");
        fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        Ok(Self {
            path: dir.join("audit.jsonl"),
        })
    }

    /// Where this log lives. Used by tests that need to inspect or corrupt
    /// the file directly, which is the only way to test that tampering is
    /// detected.
    #[cfg(test)]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append an entry, linking it to the one before it.
    ///
    /// The chain starts at the first entry written by a version that has one;
    /// earlier entries keep `prev` and `hash` absent and are reported as
    /// pre-chain rather than as broken. An upgrade does not invalidate a
    /// record it was never able to protect.
    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        let mut entry = entry.clone();
        entry.prev = self.last_hash()?;
        entry.hash = Some(entry.digest());

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("cannot open {}", self.path.display()))?;
        let line = serde_json::to_string(&entry)?;
        writeln!(f, "{}", line)?;
        Ok(())
    }

    /// The hash of the last entry, or `None` when the log is empty or its
    /// tail predates the chain. A `None` here is what makes the first chained
    /// entry the boundary: it has a hash of its own and no `prev`.
    fn last_hash(&self) -> Result<Option<String>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&self.path)?;
        Ok(raw
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .and_then(|l| serde_json::from_str::<AuditEntry>(l).ok())
            .and_then(|e| e.hash))
    }

    /// Verify the chain, reporting what holds and what does not.
    ///
    /// THREAT MODEL, stated here because the word "hash chain" promises more
    /// than this delivers in basic mode: the hook writes this log as the
    /// AGENT's own UID, so anything that can edit an entry can recompute the
    /// chain over it. This is tamper-EVIDENT against corruption and
    /// unsophisticated edits, not tamper-RESISTANT against a hostile process
    /// with the same filesystem authority.
    ///
    /// That changes in supervised mode (v0.17), where the supervisor owns the
    /// state directory and the agent's UID cannot reach it. The record
    /// becomes trustworthy because the authority that writes it sits outside
    /// the agent's trust domain - not because the hash got cleverer.
    pub fn verify_chain(&self) -> Result<ChainReport> {
        let mut report = ChainReport {
            pre_chain: 0,
            verified: 0,
            breaks: Vec::new(),
        };
        if !self.path.exists() {
            return Ok(report);
        }
        let raw = fs::read_to_string(&self.path)?;
        let mut expected_prev: Option<String> = None;

        for (i, line) in raw.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let Ok(entry) = serde_json::from_str::<AuditEntry>(line) else {
                // An unparseable line is a break, not a reason to stop: the
                // entries after it are still readable and still chained to
                // each other.
                report.breaks.push(i + 1);
                continue;
            };
            if entry.is_pre_chain() {
                report.pre_chain += 1;
                continue;
            }
            let content_ok = entry.hash.as_deref() == Some(entry.digest().as_str());
            // The first chained entry is the boundary and has no predecessor
            // to point at; after that, each entry must name the one before.
            let link_ok = expected_prev.is_none() || entry.prev == expected_prev;
            if content_ok && link_ok {
                report.verified += 1;
            } else {
                report.breaks.push(i + 1);
            }
            expected_prev = entry.hash.clone();
        }
        Ok(report)
    }

    pub fn read_last(&self, n: usize) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&self.path)?;
        let mut entries: Vec<AuditEntry> = raw
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let len = entries.len();
        if len > n {
            entries.drain(0..len - n);
        }
        Ok(entries)
    }
}

pub fn now() -> (u128, String) {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    (
        ms,
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestEnv;

    /// Roadmap 2.6. Provenance the system can actually establish.
    ///
    /// `actor` is the harness; `decided_by` is what determined the verdict.
    /// The pair answers "which agent caused this, and why did it go that way"
    /// without either field guessing.
    #[test]
    fn an_entry_records_the_harness_and_what_decided_it() {
        let env = TestEnv::new("provenance");
        let log = AuditLog::new(env.root()).unwrap();

        let mut hook = entry("rm -rf x");
        hook.source = "hook".into();
        hook.actor = Some("claude-code".into());
        hook.decided_by = Some("rule".into());
        log.append(&hook).unwrap();

        // `check` is the human's own surface: no harness produced it, and
        // naming one would be false provenance.
        let mut check = entry("ls -la");
        check.source = "check".into();
        check.actor = None;
        check.decided_by = Some("default".into());
        log.append(&check).unwrap();

        let back = log.read_last(10).unwrap();
        assert_eq!(back[0].actor.as_deref(), Some("claude-code"));
        assert_eq!(back[0].decided_by.as_deref(), Some("rule"));
        assert_eq!(back[1].actor, None, "no harness, no actor");
        assert_eq!(back[1].decided_by.as_deref(), Some("default"));
    }

    /// A SILENT DEFAULT ALLOW is a join of fields that already exist, not a
    /// field of its own.
    ///
    /// `source = hook` + `decided_by = default` + `decision = allow` is the
    /// interesting case: an agent ran something, no rule had an opinion, and
    /// the human was never told. A `silent_default_allow: bool` would
    /// duplicate that and eventually drift from it (#37).
    #[test]
    fn a_silent_default_allow_is_reconstructible_without_its_own_field() {
        let env = TestEnv::new("silent-join");
        let log = AuditLog::new(env.root()).unwrap();

        let mut silent = entry("whatever-unmatched");
        silent.source = "hook".into();
        silent.decision = "allow".into();
        silent.decided_by = Some("default".into());
        log.append(&silent).unwrap();

        // Near misses that must NOT match the same join.
        let mut by_rule = entry("ls -la");
        by_rule.source = "hook".into();
        by_rule.decision = "allow".into();
        by_rule.decided_by = Some("rule".into());
        log.append(&by_rule).unwrap();

        let mut human = entry("ls -la");
        human.source = "check".into();
        human.decision = "allow".into();
        human.decided_by = Some("default".into());
        log.append(&human).unwrap();

        let all = log.read_last(10).unwrap();
        let silent: Vec<&AuditEntry> = all
            .iter()
            .filter(|e| {
                e.source == "hook"
                    && e.decided_by.as_deref() == Some("default")
                    && e.decision == "allow"
            })
            .collect();

        assert_eq!(
            silent.len(),
            1,
            "exactly one entry is a silent default allow"
        );
        assert_eq!(silent[0].command, "whatever-unmatched");
    }

    /// The chain links entries together and verifies clean.
    #[test]
    fn a_chain_verifies_and_each_entry_names_the_one_before_it() {
        let env = TestEnv::new("chain-ok");
        let log = AuditLog::new(env.root()).unwrap();
        for i in 0..4 {
            log.append(&entry(&format!("cmd {i}"))).unwrap();
        }

        let r = log.verify_chain().unwrap();
        assert_eq!(r.verified, 4);
        assert_eq!(r.pre_chain, 0);
        assert!(r.is_intact(), "breaks: {:?}", r.breaks);

        // Each entry after the first names its predecessor's hash - the
        // property the whole thing rests on.
        let raw = std::fs::read_to_string(log.path()).unwrap();
        let entries: Vec<AuditEntry> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(entries[0].prev.is_none(), "the boundary has no predecessor");
        for w in entries.windows(2) {
            assert_eq!(w[1].prev, w[0].hash, "each entry names the one before");
        }
    }

    /// MIGRATION: pre-chain entries stay READABLE and are reported as their
    /// own count, not as breaks.
    ///
    /// An upgrade must not turn existing history into an error. The claim
    /// Termaxa can make is "continuity from the boundary onward", and the
    /// claim it cannot make is that it protected history it was not there
    /// for. The report states both rather than collapsing them.
    #[test]
    fn pre_chain_history_is_readable_and_reported_separately() {
        let env = TestEnv::new("chain-migrate");
        let log = AuditLog::new(env.root()).unwrap();

        // Two entries as an older version would have written them: no prev,
        // no hash.
        let mut old = entry("old one");
        old.prev = None;
        old.hash = None;
        let line = serde_json::to_string(&old).unwrap();
        std::fs::write(log.path(), format!("{line}\n{line}\n")).unwrap();

        // Then two from this version.
        log.append(&entry("new one")).unwrap();
        log.append(&entry("new two")).unwrap();

        let r = log.verify_chain().unwrap();
        assert_eq!(r.pre_chain, 2, "old entries are pre-chain, not broken");
        assert_eq!(r.verified, 2, "new entries verify");
        assert!(r.is_intact(), "a migration boundary is not a break");

        // And all four are still readable.
        assert_eq!(log.read_last(10).unwrap().len(), 4);
    }

    /// An edited entry is detected, and the entries around it stay readable.
    ///
    /// One corrupt line must not make the whole record unreadable: that would
    /// destroy more evidence than the corruption did.
    #[test]
    fn a_tampered_entry_is_named_and_the_rest_survives() {
        let env = TestEnv::new("chain-tamper");
        let log = AuditLog::new(env.root()).unwrap();
        for i in 0..4 {
            log.append(&entry(&format!("cmd {i}"))).unwrap();
        }

        // Rewrite entry 2's command, leaving its hash alone - the shape of an
        // edit that tries to hide what was run.
        let raw = std::fs::read_to_string(log.path()).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
        lines[1] = lines[1].replace("cmd 1", "innocent");
        std::fs::write(log.path(), lines.join("\n") + "\n").unwrap();

        let r = log.verify_chain().unwrap();
        assert!(!r.is_intact());
        assert!(
            r.breaks.contains(&2),
            "the edited entry is named: {:?}",
            r.breaks
        );
        // The record is still readable - reporting, not refusing.
        assert_eq!(log.read_last(10).unwrap().len(), 4);
    }

    /// Deleting an entry breaks the link that named it.
    #[test]
    fn a_removed_entry_leaves_a_gap_the_chain_reports() {
        let env = TestEnv::new("chain-delete");
        let log = AuditLog::new(env.root()).unwrap();
        for i in 0..4 {
            log.append(&entry(&format!("cmd {i}"))).unwrap();
        }
        let raw = std::fs::read_to_string(log.path()).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
        lines.remove(1); // the entry someone wanted gone
        std::fs::write(log.path(), lines.join("\n") + "\n").unwrap();

        let r = log.verify_chain().unwrap();
        assert!(
            !r.is_intact(),
            "a hole in the chain is visible even though every remaining line \
             is internally valid"
        );
    }

    use crate::testutil::TempTree;

    fn entry(command: &str) -> AuditEntry {
        let (ts_ms, ts) = now();
        AuditEntry {
            ts_ms,
            ts,
            source: "test".into(),
            actor: None,
            decided_by: None,
            command: command.into(),
            decision: "allow".into(),
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
            cwd: "/work".into(),
            prev: None,
            hash: None,
        }
    }

    fn log_in(tmp: &TempTree) -> AuditLog {
        AuditLog::new(&tmp.dir("state")).expect("the log directory must be creatable")
    }

    #[test]
    fn new_puts_the_log_under_the_state_dir_and_creates_it() {
        let tmp = TempTree::new("audit-new");
        let state = tmp.dir("state");
        let log = AuditLog::new(&state).expect("the log directory must be creatable");

        assert_eq!(log.path, state.join("logs").join("audit.jsonl"));
        assert!(
            state.join("logs").is_dir(),
            "the directory is created up front so appends never fail on a missing parent"
        );
    }

    #[test]
    fn read_last_on_a_log_that_was_never_written_is_empty() {
        let tmp = TempTree::new("audit-missing");
        let log = log_in(&tmp);

        let entries = log
            .read_last(10)
            .expect("no log yet is a fresh project, not a failure");
        assert!(entries.is_empty());
    }

    #[test]
    fn read_last_returns_exactly_the_tail_in_order() {
        let tmp = TempTree::new("audit-tail");
        let log = log_in(&tmp);
        for command in ["one", "two", "three", "four", "five"] {
            log.append(&entry(command)).expect("append must succeed");
        }

        let tail = log.read_last(2).expect("read must succeed");
        let commands: Vec<&str> = tail.iter().map(|e| e.command.as_str()).collect();
        // Exactly two, oldest first: reports read the tail as a timeline.
        assert_eq!(commands, ["four", "five"]);
    }

    #[test]
    fn read_last_asking_for_more_than_exists_returns_everything() {
        let tmp = TempTree::new("audit-short");
        let log = log_in(&tmp);
        for command in ["one", "two", "three"] {
            log.append(&entry(command)).expect("append must succeed");
        }

        // The boundary: asking for exactly the number held, and for more.
        let all = log.read_last(3).expect("read must succeed");
        assert_eq!(
            all.iter().map(|e| e.command.as_str()).collect::<Vec<_>>(),
            ["one", "two", "three"]
        );
        let more = log.read_last(99).expect("read must succeed");
        assert_eq!(more.len(), 3, "asking for more cannot invent entries");
    }

    #[test]
    fn read_last_skips_a_line_it_cannot_parse() {
        let tmp = TempTree::new("audit-corrupt");
        let log = log_in(&tmp);
        log.append(&entry("first")).expect("append must succeed");
        // A truncated write (a killed process mid-append) must not make the
        // whole history unreadable.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log.path)
            .expect("log must be open-able");
        writeln!(f, "{{\"ts_ms\": 1, oh no").expect("write must succeed");
        drop(f);
        log.append(&entry("second")).expect("append must succeed");

        let entries = log.read_last(10).expect("read must succeed");
        assert_eq!(
            entries
                .iter()
                .map(|e| e.command.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn now_reports_the_same_instant_in_both_forms() {
        let (ms, ts) = now();

        // A stubbed clock (0, or 1) would sit in 1970.
        assert!(
            ms > 1_735_689_600_000,
            "epoch milliseconds should be recent, got {}",
            ms
        );
        let parsed = chrono::DateTime::parse_from_rfc3339(&ts)
            .unwrap_or_else(|e| panic!("`{}` must be RFC3339 UTC: {}", ts, e));
        let skew = (ms as i64 - parsed.timestamp_millis()).abs();
        assert!(
            skew < 2_000,
            "the two halves must describe one instant, {} ms apart",
            skew
        );
    }
}
