//! The witness: one line the hook writes before it judges anything.
//!
//! A transcript command with no record line can mean two different things,
//! with different fixes (Tim Schipper, Sep 2026): the hook never fired (the
//! wiring was bypassed, or was never there), or it fired and failed to
//! record (the gate crashed, timed out, or could not write). The transcript
//! alone cannot tell them apart, so the hook leaves this marker first, as
//! the very first thing it does after reading its input, before the policy
//! loads, before any preview runs, before insurance. `termaxa replay
//! --against-record` then reads: a witness with a record line is a judged
//! call; a witness with no record line is "fired, unrecorded"; neither is
//! "never fired".

use std::path::Path;

/// Append the witness for this payload, if it is a gate call for a project
/// this machine knows. Never fails the hook: a witness that cannot be
/// written is a witness that is not there, which replay reports honestly.
pub fn leave(raw_payload: &str) {
    let Some(p) = crate::hook::parse_input(raw_payload) else {
        return;
    };
    if p.is_post || p.command.trim().is_empty() {
        return;
    }
    // The doctor's probe writes nothing anywhere (probe_inertness.rs), and
    // a witness for it would be a call that never happened.
    let is_probe = std::env::var("TERMAXA_HOOK_PROBE").as_deref() == Ok("1")
        || p.session.as_deref() == Some(crate::hook::PROBE_SESSION);
    if is_probe {
        return;
    }
    let Ok(paths) = crate::paths::resolve_from(Path::new(&p.cwd)) else {
        return;
    };
    let (ts_ms, ts) = crate::audit::now();
    let line = serde_json::json!({
        "ts_ms": ts_ms,
        "ts": ts,
        "session": p.session,
        "call_id": p.call_id,
        "command": p.command.chars().take(200).collect::<String>(),
        "dialect": format!("{:?}", p.dialect).to_lowercase(),
    });
    let path = paths.state_dir.join("logs").join("seen.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write as _;
        let _ = writeln!(f, "{line}");
    }
}
