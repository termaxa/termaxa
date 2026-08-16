//! Talking to a supervisor that does not exist yet.
//!
//! v0.16 groundwork for v0.17. This module carries the wire types, the socket
//! path convention, and mode detection — everything the hook needs to compile
//! against and to fail correctly when the supervisor is absent. The daemon
//! itself is v0.17; a loopback stub in test support stands in for it so
//! deny-on-unreachable and version-skew are testable before it exists.
//!
//! WHY THE PROTOCOL SHIPS BEFORE THE DAEMON. The hook's behaviour when it
//! cannot reach a supervisor is the part that has to be right, and it is
//! testable now. Writing it after the daemon would mean writing it when the
//! happy path already works, which is when a failure path gets the least
//! attention — and this particular failure path is the permanent answer to
//! Cursor 3.11, four releases of silent fail-open.
//!
//! THE TRUST MODEL, because it determines what these types may carry. In
//! supervised mode the hook runs inside the AGENT's trust domain: the agent's
//! UID spawns it, so anything the hook concludes is the agent's own account of
//! itself. The hook therefore forwards the RAW PAYLOAD and forwards nothing
//! else — no verdict, no parse, no classification. The supervisor re-derives
//! everything from bytes it received itself. A record built from hook-reported
//! decisions would be the agent's account wearing a uniform.

// The wire types below have no caller until the daemon exists (v0.17). Live
// already, and NOT covered by this allow: `detect`, `Mode` and
// `SuperviseError::Unreachable`, which the hook consults on every invocation
// to fail closed when supervision is configured but absent.
//
// Scoped to this module rather than crate-wide, and narrated rather than
// silent, because "dead code" here means "the other end is not written yet"
// and that distinction is exactly what a future reader needs. It comes off in
// v0.17 with the daemon.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Wire protocol version.
///
/// The hook binary and the daemon binary WILL skew during an upgrade — they
/// are the same executable, but not the same running process, and nothing
/// restarts a daemon because a package manager replaced a file. A version
/// mismatch must be a refusal with a message, never undefined behaviour, so
/// this is checked before a request is honoured rather than hoped about.
pub const PROTOCOL_VERSION: u32 = 1;

/// The socket's name inside the operator-owned state directory.
///
/// Directory `0755` (the agent user can traverse and connect), socket
/// connectable by the agent user, everything else inside owned by the
/// operator and unreadable to the agent. The path convention lives here
/// rather than at each caller so basic mode and supervised mode cannot come
/// to disagree about where to look (#37).
pub const SOCKET_NAME: &str = "supervise.sock";

/// Where the supervisor's socket lives for a given Termaxa home.
pub fn socket_path(termaxa_home: &Path) -> PathBuf {
    termaxa_home.join(SOCKET_NAME)
}

/// What the hook sends: the payload as it arrived, and nothing it concluded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub version: u32,
    /// The raw hook payload, byte for byte as the harness sent it. The
    /// supervisor parses this itself.
    pub payload: String,
    /// The dialect the hook detected. ADVISORY ONLY — the supervisor
    /// re-detects from the payload. It travels because it is useful in a log
    /// line when detection disagrees, which is a fact worth having; it is not
    /// input to a decision, because a value the agent's domain produced
    /// cannot be.
    pub dialect_hint: Option<String>,
    /// The directory the hook was invoked in, for the same advisory reason.
    pub cwd: String,
}

/// What the supervisor sends back: a rendered answer and the code to exit with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub version: u32,
    /// The response body, already rendered in the harness's dialect. The hook
    /// prints this and exits; it does not decide how to say it, because
    /// deciding how to say a verdict is close enough to deciding the verdict.
    pub rendered: String,
    pub exit_code: i32,
    /// The audit sequence number this decision was recorded under, so the
    /// hook can reference an entry it did not write.
    pub audit_seq: Option<u64>,
}

/// Why a request could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuperviseError {
    /// No socket at the expected path: the supervisor is not running.
    Unreachable,
    /// Connected, but the peer speaks a different protocol version.
    VersionSkew { ours: u32, theirs: u32 },
    /// Connected and then did not answer within the deadline.
    Timeout,
    /// Answered with something that is not a `Response`.
    Malformed,
}

impl SuperviseError {
    /// The line a human reads when the gate refuses because it lost its brain.
    /// Each names the actual condition: "supervisor unreachable" and "version
    /// mismatch" want different fixes, and a single message for both would
    /// send someone to the wrong one.
    pub fn reason(&self) -> String {
        match self {
            SuperviseError::Unreachable => {
                "supervised mode is configured but the supervisor is not answering — \
                 refusing rather than deciding without it"
                    .into()
            }
            SuperviseError::VersionSkew { ours, theirs } => format!(
                "supervisor speaks protocol v{theirs}, this hook speaks v{ours} — \
                 refusing rather than guessing at the difference (restart the supervisor \
                 after upgrading)"
            ),
            SuperviseError::Timeout => {
                "the supervisor did not answer in time — refusing rather than \
                 deciding without it"
                    .into()
            }
            SuperviseError::Malformed => {
                "the supervisor's answer could not be read — refusing rather than \
                 acting on it"
                    .into()
            }
        }
    }
}

/// Which topology is this hook running in?
///
/// Detected from the filesystem rather than from configuration, so a
/// half-finished setup cannot claim supervision it does not have: the socket
/// is either there or it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The default, and every Windows install. Everything runs as the user;
    /// protection is cooperative.
    Basic,
    /// A supervisor socket is present. The hook is a pipe and the authority
    /// is elsewhere.
    Supervised,
}

/// Detect the mode for a Termaxa home.
///
/// FAILING CLOSED IS NOT THE SAME AS DETECTING SUPERVISION. This answers only
/// "is a supervisor configured here" — the socket exists. Whether it ANSWERS
/// is a separate question, and the separation is deliberate: a hook that
/// treated an unreachable supervisor as "basic mode, carry on" would fail
/// OPEN at exactly the moment the operator most expects it not to. Detect,
/// then require an answer, and refuse if there is none.
pub fn detect(termaxa_home: &Path) -> Mode {
    if socket_path(termaxa_home).exists() {
        Mode::Supervised
    } else {
        Mode::Basic
    }
}

/// Validate a response against what we sent.
///
/// Version is checked on the way IN as well as on the way out: a daemon older
/// than the hook will happily answer a request it half-understood, and the
/// mismatch is only visible here.
pub fn check_response(raw: &str) -> Result<Response, SuperviseError> {
    let resp: Response = serde_json::from_str(raw).map_err(|_| SuperviseError::Malformed)?;
    if resp.version != PROTOCOL_VERSION {
        return Err(SuperviseError::VersionSkew {
            ours: PROTOCOL_VERSION,
            theirs: resp.version,
        });
    }
    Ok(resp)
}

/// Build the request for a payload the hook just received.
pub fn request_for(payload: &str, dialect_hint: Option<&str>, cwd: &str) -> Request {
    Request {
        version: PROTOCOL_VERSION,
        payload: payload.to_string(),
        dialect_hint: dialect_hint.map(|s| s.to_string()),
        cwd: cwd.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempTree;

    #[test]
    fn mode_is_read_from_the_filesystem_not_from_configuration() {
        let t = TempTree::new("mode-detect");
        let home = t.path();
        assert_eq!(
            detect(home),
            Mode::Basic,
            "no socket means basic - a config file claiming otherwise would be a claim, \
             not a fact"
        );

        std::fs::write(socket_path(home), b"").unwrap();
        assert_eq!(detect(home), Mode::Supervised);
    }

    /// The hook forwards the payload and nothing it concluded. Pinned because
    /// the temptation to send a parsed verdict is real and would quietly make
    /// the record the agent's own account.
    #[test]
    fn a_request_carries_the_raw_payload_and_no_conclusions() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let req = request_for(raw, Some("claude-code"), "/tmp/proj");
        assert_eq!(req.payload, raw, "byte for byte");
        assert_eq!(req.version, PROTOCOL_VERSION);

        // The dialect travels as a HINT. If this ever becomes authoritative,
        // a value produced inside the agent's trust domain is deciding
        // something, which is the thing supervised mode exists to prevent.
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("dialect_hint"),
            "advisory by its name: {json}"
        );
        assert!(
            !json.contains("decision") && !json.contains("verdict"),
            "the hook must not send a conclusion: {json}"
        );
    }

    #[test]
    fn a_version_mismatch_is_a_refusal_with_a_message_not_undefined_behaviour() {
        let newer = serde_json::to_string(&Response {
            version: PROTOCOL_VERSION + 1,
            rendered: "{}".into(),
            exit_code: 0,
            audit_seq: None,
        })
        .unwrap();

        match check_response(&newer) {
            Err(SuperviseError::VersionSkew { ours, theirs }) => {
                assert_eq!(ours, PROTOCOL_VERSION);
                assert_eq!(theirs, PROTOCOL_VERSION + 1);
            }
            other => panic!("a skewed version must be named as such, got {other:?}"),
        }

        // And the message says which fix applies - "restart the supervisor"
        // is different advice from "start it".
        let msg = SuperviseError::VersionSkew { ours: 1, theirs: 2 }.reason();
        assert!(msg.contains("restart"), "{msg}");
        assert!(
            !SuperviseError::Unreachable.reason().contains("restart"),
            "an absent supervisor needs starting, not restarting"
        );
    }

    #[test]
    fn a_malformed_answer_is_refused_rather_than_interpreted() {
        assert_eq!(
            check_response("not json at all"),
            Err(SuperviseError::Malformed)
        );
        assert_eq!(
            check_response(r#"{"version":1}"#),
            Err(SuperviseError::Malformed),
            "a partial response is not a response"
        );
    }

    /// Every failure reason says what to do about it. A refusal a human
    /// cannot act on is a gate that gets uninstalled (#48).
    #[test]
    fn every_failure_names_its_own_condition() {
        for e in [
            SuperviseError::Unreachable,
            SuperviseError::VersionSkew { ours: 1, theirs: 2 },
            SuperviseError::Timeout,
            SuperviseError::Malformed,
        ] {
            let r = e.reason();
            assert!(!r.is_empty());
            assert!(
                r.contains("refus"),
                "each reason states that it refused, and why: {r}"
            );
        }
    }
}
