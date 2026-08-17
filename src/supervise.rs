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

/// The socket's name, inside its own directory beside the state directory.
pub const SOCKET_NAME: &str = "supervise.sock";

/// Where the supervisor listens, and how a hook finds it.
///
/// THE ENDPOINT IS NOT STATE, and discovering it like state was the bug the
/// first proving run found. Every automated test ran the hook and the
/// supervisor as the same user, so `$HOME`-relative discovery worked. The
/// first time a real agent ran under a real second account, its hook resolved
/// `$TERMAXA_HOME` from ITS OWN home, found no socket there, concluded basic
/// mode, and decided on its own authority - writing an audit log the agent
/// owned. The walls held; the door led nowhere.
///
/// So the two are separated:
///
///   operator state   `$TERMAXA_HOME` or `~/.termaxa` — the operator's, and
///                    the agent has no path into it. Unchanged.
///   IPC endpoint     a socket path the agent is TOLD, in a runtime directory
///                    that holds nothing else.
///
/// `$HOME` belongs to the process making the request, which in supervised mode
/// is deliberately the agent. Pointing the agent's state home at the
/// operator's would reverse the ownership model, and would establish a
/// convention where an environment variable hands an agent a path to
/// privileged state. The endpoint is the only thing the agent needs, so the
/// endpoint is the only thing it gets.
///
/// Resolution order, most explicit first:
///
///   1. `$TERMAXA_SOCKET`         set by `wrap`, or by an operator by hand
///   2. `$XDG_RUNTIME_DIR/termaxa/supervise.sock`   per-user runtime dir
///   3. `<state>/run/supervise.sock`                the operator's own default
///
/// A hook running as the agent finds it via (1), because `wrap` exports it.
/// The supervisor binds via (3) unless told otherwise, and prints what it
/// bound so the operator can see it.
pub const SOCKET_ENV: &str = "TERMAXA_SOCKET";
/// The directory holding only the socket, under a given state directory.
///
/// `0755`, containing nothing but the socket; the state directory above it is
/// `0711` (traverse, not enumerate). Both numbers came from running the
/// boundary rig - `0700` makes the socket unreachable and denies everything,
/// `0755` on the state dir hands over the audit log.
pub fn socket_dir(termaxa_home: &Path) -> PathBuf {
    termaxa_home.join("run")
}

/// Where the supervisor should BIND, given its own state directory.
pub fn bind_path(termaxa_home: &Path) -> PathBuf {
    if let Some(p) = explicit_socket() {
        return p;
    }
    socket_dir(termaxa_home).join(SOCKET_NAME)
}

/// Where a hook should LOOK. Deliberately not `$HOME`-relative.
///
/// Returns `None` when no endpoint is configured anywhere, which is the
/// ordinary basic-mode answer: no supervisor, decide locally.
pub fn endpoint() -> Option<PathBuf> {
    if let Some(p) = explicit_socket() {
        return Some(p);
    }
    if let Some(p) = runtime_socket() {
        if p.exists() {
            return Some(p);
        }
    }
    // The operator's own default, which is what a hook run BY the operator
    // finds. An agent under `wrap` gets (1) instead.
    let state = crate::paths::home_base().ok()?;
    let p = socket_dir(&state).join(SOCKET_NAME);
    p.exists().then_some(p)
}

fn explicit_socket() -> Option<PathBuf> {
    std::env::var(SOCKET_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
}

/// `$XDG_RUNTIME_DIR/termaxa/supervise.sock`. Per-user, cleaned up by the OS,
/// and the conventional home for a socket rather than for state.
fn runtime_socket() -> Option<PathBuf> {
    std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|d| PathBuf::from(d).join("termaxa").join(SOCKET_NAME))
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

/// Is a supervisor configured for THIS process?
///
/// Answered from the endpoint, not from a state directory. A hook running as
/// the agent has no path into the operator's state and must not need one - it
/// needs the socket it was told about, and nothing else.
///
/// FAILING CLOSED IS NOT THE SAME AS DETECTING SUPERVISION. This answers only
/// "is an endpoint configured and present". Whether it ANSWERS is a separate
/// question, deliberately: a hook that treated an unreachable supervisor as
/// "basic mode, carry on" would fail OPEN exactly where the operator most
/// expects otherwise.
pub fn detect() -> Mode {
    match endpoint() {
        Some(_) => Mode::Supervised,
        None => Mode::Basic,
    }
}

/// Ask the supervisor to decide, from inside the agent's domain.
///
/// The hook sends the RAW PAYLOAD and prints what comes back. It does not
/// parse, evaluate, insure, or audit on its own authority here - anything it
/// concluded would be the agent's own account of itself, and the record's
/// whole value in this mode is that it is not.
///
/// Two seconds, matching the doctor probe's discipline: an agent is blocked
/// on this answer, and a supervisor that has wedged must produce a refusal
/// rather than a hang. Every failure below denies.
#[cfg(unix)]
pub fn ask(
    sock: &Path,
    payload: &str,
    dialect_hint: Option<&str>,
    cwd: &str,
) -> Result<Response, SuperviseError> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock).map_err(|_| SuperviseError::Unreachable)?;
    let timeout = std::time::Duration::from_secs(2);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = request_for(payload, dialect_hint, cwd);
    let line = serde_json::to_string(&req).map_err(|_| SuperviseError::Malformed)?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|_| SuperviseError::Unreachable)?;
    stream.flush().map_err(|_| SuperviseError::Unreachable)?;

    let mut resp = String::new();
    let read = BufReader::new(stream).read_line(&mut resp);
    match read {
        Ok(0) => Err(SuperviseError::Timeout),
        Ok(_) => check_response(&resp),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(SuperviseError::Timeout),
        Err(_) => Err(SuperviseError::Unreachable),
    }
}

#[cfg(not(unix))]
pub fn ask(
    _sock: &Path,
    _payload: &str,
    _dialect_hint: Option<&str>,
    _cwd: &str,
) -> Result<Response, SuperviseError> {
    Err(SuperviseError::Unreachable)
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

// ---------------------------------------------------------------------------
// the daemon (v0.17)
// ---------------------------------------------------------------------------

/// Serve until killed. One connection, one payload, one response.
///
/// Runs under the OPERATOR's UID. The agent's UID may connect and may write a
/// request; it may not read the policy, edit the log, or delete a backup,
/// because those live in a directory it cannot enter. That is the whole point
/// of the release: the boundary is the filesystem's, not the code's.
///
/// Single-threaded on purpose. Requests are short (parse, evaluate, insure,
/// append) and an agent issues them serially anyway; a thread per connection
/// would buy nothing and add a way for two requests to interleave inside the
/// audit append. If a proving run shows contention, that measurement is the
/// argument for changing it.
#[cfg(unix)]
pub fn serve(termaxa_home: &Path) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    std::fs::create_dir_all(termaxa_home)?;
    // The socket's own directory, traversable by the agent. The state
    // directory above it stays private; see `socket_dir`.
    let dir = socket_dir(termaxa_home);
    std::fs::create_dir_all(&dir)?;
    let mut dp = std::fs::metadata(&dir)?.permissions();
    dp.set_mode(0o755);
    std::fs::set_permissions(&dir, dp)?;

    // 0711 on the state directory: traversable, not listable. See `socket_dir`
    // for why this exact mode and not 0700 or 0755.
    let mut hp = std::fs::metadata(termaxa_home)?.permissions();
    hp.set_mode(0o711);
    std::fs::set_permissions(termaxa_home, hp)?;

    // 0711 gives TRAVERSAL, so everything private must be private in its own
    // right rather than by hiding behind the parent. The rig proved the
    // difference: with only the parent locked down, the agent could not LIST
    // the state directory and could still `cat` the audit log and a backup by
    // full path - paths it can guess, since they are documented.
    //
    // Belt and braces on every launch rather than once at init: a directory
    // created later, or loosened by hand, is re-tightened by the process that
    // owns the boundary.
    for private in ["projects", "backups", "logs"] {
        let p = termaxa_home.join(private);
        if p.exists() {
            harden(&p)?;
        }
    }

    let sock = bind_path(termaxa_home);

    // A stale socket file from a killed supervisor would make `bind` fail, and
    // worse, mode detection already reports Supervised for it - so every hook
    // denies while nothing is listening. Removing it here is safe because we
    // are about to bind the same path; if another supervisor is genuinely
    // live, the bind below fails and says so.
    if sock.exists() {
        std::fs::remove_file(&sock)?;
    }

    let listener =
        UnixListener::bind(&sock).with_context(|| format!("cannot bind {}", sock.display()))?;

    // 0666 on the socket: the agent user must connect. That is NOT a hole -
    // connecting lets it ask, not decide. The directory above is what keeps
    // the policy, the log and the backups out of its reach.
    let mut p = std::fs::metadata(&sock)?.permissions();
    p.set_mode(0o666);
    std::fs::set_permissions(&sock, p)?;

    eprintln!("termaxa: supervising on {}", sock.display());
    eprintln!("termaxa: hooks in this home now decide through this process");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("termaxa: accept failed: {e}");
                continue;
            }
        };

        // Who asked. SO_PEERCRED is the kernel's answer, not the caller's
        // claim - the one identity in this system the agent cannot forge.
        let peer_uid = peer_uid(&stream);

        let mut line = String::new();
        if BufReader::new(stream.try_clone()?)
            .read_line(&mut line)
            .is_err()
        {
            continue;
        }

        let reply = handle(&line, peer_uid);
        let _ = writeln!(stream, "{reply}");
        let _ = stream.flush();
    }
    Ok(())
}

/// Make a directory and everything under it operator-only.
///
/// Recursive because the state directory nests: `projects/<hash>/logs/` holds
/// the audit log, and a permissive directory anywhere on that path is a way in.
#[cfg(unix)]
fn harden(dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut p = std::fs::metadata(dir)?.permissions();
    p.set_mode(0o700);
    std::fs::set_permissions(dir, p)?;
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            harden(&path)?;
        } else {
            let mut fp = std::fs::metadata(&path)?.permissions();
            fp.set_mode(0o600);
            std::fs::set_permissions(&path, fp)?;
        }
    }
    Ok(())
}

/// Answer one request. Separated from the socket loop so it is testable
/// without a socket, and so a panic in decision logic cannot be confused with
/// a transport failure.
#[cfg(unix)]
fn handle(line: &str, peer_uid: Option<u32>) -> String {
    let err = |msg: &str| {
        serde_json::to_string(&Response {
            version: PROTOCOL_VERSION,
            rendered: msg.to_string(),
            exit_code: 2,
            audit_seq: None,
        })
        .unwrap_or_default()
    };

    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(_) => return err("[termaxa] the supervisor could not read that request"),
    };

    // Version checked on the way IN as well as out: a hook older than this
    // daemon will send a request this daemon half-understands, and answering
    // it anyway is the garbled decision the protocol exists to prevent.
    if req.version != PROTOCOL_VERSION {
        return err(&format!(
            "[termaxa] hook speaks protocol v{}, supervisor speaks v{} — \
             refusing rather than guessing at the difference",
            req.version, PROTOCOL_VERSION
        ));
    }

    // The supervisor re-derives everything from the payload it received. The
    // dialect hint travels for the log line, never for the decision.
    // The daemon decides on its OWN authority, so its call into the hook path
    // must not detect supervised mode and forward back to itself. One process,
    // one socket, single-threaded: that would deadlock on the first request.
    std::env::set_var("TERMAXA_SUPERVISOR", "1");
    let outcome = match crate::hook::decide(&req.payload) {
        Ok(o) => o,
        Err(e) => return err(&format!("[termaxa] the supervisor failed to decide: {e}")),
    };

    if let Some(uid) = peer_uid {
        eprintln!(
            "termaxa: uid={} hint={} exit={}",
            uid,
            req.dialect_hint.as_deref().unwrap_or("-"),
            outcome.exit_code
        );
    }

    serde_json::to_string(&Response {
        version: PROTOCOL_VERSION,
        rendered: outcome.rendered.unwrap_or_default(),
        exit_code: outcome.exit_code,
        audit_seq: outcome.audit_seq,
    })
    .unwrap_or_default()
}

/// The connecting process's UID, from the kernel.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.uid)
    } else {
        None
    }
}

/// macOS spells it `LOCAL_PEERCRED` with a different struct; until the
/// proving run happens on a Mac, this reports "unknown" rather than guessing
/// at an ABI nobody here has tested. An absent UID is recorded as absent.
#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(_stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    None
}

#[cfg(not(unix))]
pub fn serve(_termaxa_home: &Path) -> anyhow::Result<()> {
    anyhow::bail!(
        "termaxa supervise requires Unix domain sockets and a second user account. \
         Windows has neither in the form this depends on; basic mode is the Windows \
         answer and is fully supported."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon answers a well-formed request with a decision it made
    /// itself. Exercised without a socket, so a failure here is decision
    /// logic rather than transport.
    #[cfg(unix)]
    #[test]
    fn the_supervisor_decides_and_answers() {
        // A real project, because the supervisor decides against a real
        // policy - the first draft of this test pointed at /tmp and failed
        // with "no policy found", which was the test being wrong and the
        // daemon being right.
        let env = crate::testutil::TestEnv::new("sup-decide");
        let proj = env.root().join("proj");
        std::fs::create_dir_all(proj.join(".termaxa")).unwrap();
        std::fs::write(
            proj.join(".termaxa/policy.yaml"),
            "version: 1\ndefault: ask\nrules:\n  - match: \"*rm -rf*\"\n    action: deny\n    reason: \"blocked\"\n",
        )
        .unwrap();
        let cwd = proj.display().to_string();
        let payload = format!(
            r#"{{"tool_name":"Bash","tool_input":{{"command":"rm -rf /"}},"cwd":"{}"}}"#,
            cwd.replace('\\', "/")
        );
        let req = serde_json::to_string(&request_for(&payload, Some("claude-code"), &cwd)).unwrap();

        let raw = handle(&req, Some(1000));
        let resp: Response = serde_json::from_str(&raw).expect("a well-formed response");
        assert_eq!(resp.version, PROTOCOL_VERSION);
        assert_eq!(resp.exit_code, 2, "rm -rf / is denied: {}", resp.rendered);
        assert!(resp.rendered.contains("deny"), "{}", resp.rendered);
    }

    /// A request from a hook speaking a different protocol version is refused
    /// with a message, not answered with a decision the two ends would read
    /// differently.
    #[cfg(unix)]
    #[test]
    fn a_skewed_request_is_refused_rather_than_half_understood() {
        let mut req = request_for("{}", None, "/tmp");
        req.version = PROTOCOL_VERSION + 1;
        let raw = handle(&serde_json::to_string(&req).unwrap(), None);
        let resp: Response = serde_json::from_str(&raw).unwrap();
        assert_eq!(resp.exit_code, 2);
        assert!(
            resp.rendered.contains("protocol"),
            "the refusal names the cause: {}",
            resp.rendered
        );
    }

    /// Garbage on the socket is refused, not interpreted. The supervisor is
    /// reachable by the agent's UID by design, so it will be sent garbage.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_request_is_refused_not_guessed_at() {
        let resp: Response = serde_json::from_str(&handle("not json", None)).unwrap();
        assert_eq!(resp.exit_code, 2);
        assert!(
            resp.rendered.contains("could not read"),
            "{}",
            resp.rendered
        );
    }

    /// The endpoint is discovered from the ENDPOINT, not from a state
    /// directory, and the distinction is the whole of the routing fix.
    ///
    /// The first proving run found a hook running as the agent resolving
    /// `$HOME` to the agent's home, finding no socket there, concluding basic
    /// mode, and deciding on its own authority while the supervisor sat idle
    /// with nothing to do. Discovering an IPC endpoint the way state is
    /// discovered only works while both live under one user.
    #[test]
    fn the_endpoint_is_told_not_inferred_from_home() {
        // TestEnv, not TempTree: this reads and writes process-global
        // environment, and every other reader of it holds this lock. #63 is
        // the entry about what happens when one test does not.
        let env = crate::testutil::TestEnv::new("endpoint");
        let home = env.root().to_path_buf();

        let prev_sock = std::env::var(SOCKET_ENV).ok();
        let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var(SOCKET_ENV);
        std::env::remove_var("XDG_RUNTIME_DIR");

        // No endpoint anywhere: basic mode, the ordinary answer.
        assert_eq!(detect(), Mode::Basic);

        // An explicit endpoint is honoured wherever it points - including a
        // path with no relationship to this process's home, which is exactly
        // the agent's situation under `wrap`.
        let sock = home.join("elsewhere.sock");
        std::fs::write(&sock, b"").unwrap();
        std::env::set_var(SOCKET_ENV, &sock);
        assert_eq!(detect(), Mode::Supervised);
        assert_eq!(endpoint().unwrap(), sock);

        match prev_sock {
            Some(v) => std::env::set_var(SOCKET_ENV, v),
            None => std::env::remove_var(SOCKET_ENV),
        }
        if let Some(v) = prev_xdg {
            std::env::set_var("XDG_RUNTIME_DIR", v);
        }
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
