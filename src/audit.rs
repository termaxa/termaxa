use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
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

    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("cannot open {}", self.path.display()))?;
        let line = serde_json::to_string(entry)?;
        writeln!(f, "{}", line)?;
        Ok(())
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
