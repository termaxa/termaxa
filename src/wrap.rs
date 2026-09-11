//! `termaxa wrap -- <agent>` — every shell command the agent runs goes
//! through the gate, hook or no hook.
//!
//! v0.16 groundwork. The mechanism is deliberately boring: create a shim
//! directory, put `sh`/`bash`/`zsh` in it that forward to `termaxa run`,
//! prepend it to `PATH`, point `SHELL` at it, and launch the agent. A command
//! the agent runs through a shell then arrives at the existing runner —
//! "gate one command, insure, execute, record" — which already exists and is
//! already tested.
//!
//! WHAT THIS DOES NOT DO, stated the way the grades table states it. This is
//! not process interception. There is no `ptrace`, no `seccomp`, no
//! `LD_PRELOAD`. Commands reach the gate because they resolve a shell **by
//! name** through `PATH` or read `$SHELL`; a caller that execs `/bin/sh`
//! **by absolute path**, or that `execve`s a binary directly without a shell
//! at all, does not pass through anything. That residue is real and belongs
//! in the same table that sells the rung.
//!
//! NO HARNESS IS CLAIMED AS COVERED UNTIL WATCHED (#20, #45). Whether a
//! given agent's shell tool resolves `sh` through `PATH` or hardcodes
//! `/bin/sh` is an empirical question about that agent. One has been watched
//! (Sep 10, 2026, `strace -f -e trace=execve` on a wrapped headless session):
//! Claude Code looks for zsh on `PATH` and at four absolute paths, and with
//! none found runs `/bin/bash` by absolute path — nothing on `PATH` sees it.
//! It honours `CLAUDE_CODE_SHELL`, so `run` sets that to the `bash` shim and
//! the same session then went through the shim on every call. A harness that
//! hardcodes its shell and offers no such setting is outside this mechanism,
//! and `doctor` reports what is wired, not what an unobserved harness will
//! do. Measured, then written — not the reverse.
//!
//! WHY THE SHIM DIR IS OPERATOR-OWNED FROM THE START (#51). A directory on
//! `PATH` whose contents get executed is an execution primitive: anything that
//! can write there chooses what `sh` means. In basic mode the agent's UID
//! could write to a shim dir it owns, which would make the wrapper a way to
//! run code rather than a way to gate it. So the ownership story is written
//! now — the dir lives under the operator's Termaxa home, not in the project,
//! and supervised mode inherits it rather than retrofitting it.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Shells the shim answers to. Only names a caller would resolve through
/// `PATH`; adding one is a claim that agents invoke it, so the list stays
/// short and observed rather than aspirational.
const SHIMMED_SHELLS: [&str; 3] = ["sh", "bash", "zsh"];

/// Where the shims live: under the Termaxa home, never in the project.
///
/// Under the project it would be agent-writable in every mode, which is the
/// execution primitive above. Under the Termaxa home it is operator-owned in
/// supervised mode by the same `chmod` that protects the rest of the state
/// directory.
pub fn shim_dir(termaxa_home: &Path) -> PathBuf {
    termaxa_home.join("shims")
}

/// Write the shim scripts, returning the directory to prepend to `PATH`.
///
/// The shim is one line of `exec`, so it adds no shell of its own between the
/// agent and the gate: `exec termaxa run -- "$@"` replaces the shim process
/// rather than nesting under it.
#[cfg(unix)]
pub fn install_shims(termaxa_home: &Path, termaxa_bin: &Path) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    install_shims_on(termaxa_home, termaxa_bin, &path)
}

/// [`install_shims`] with the search path given rather than read from the
/// process. The tests use this: environment variables are process-global,
/// the test binary's `isolating_path` guard rewrites `PATH` to a directory
/// holding only the test binary while it runs, and a wrap test walking
/// `PATH` for `sh` on another thread at that moment found nothing (CI run
/// 191, macOS, Sep 12, 2026). A search path that arrives as an argument
/// cannot be rewritten under the test.
#[cfg(unix)]
pub fn install_shims_on(
    termaxa_home: &Path,
    termaxa_bin: &Path,
    path: &std::ffi::OsStr,
) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let dir = shim_dir(termaxa_home);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("cannot create shim directory {}", dir.display()))?;

    // 0755: the agent user must traverse and execute, and must not write.
    let mut perm = std::fs::metadata(&dir)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&dir, perm)?;

    for shell in SHIMMED_SHELLS {
        // Only a shell that exists gets a shim. A shim for an absent shell
        // makes the harness believe it has one: Claude Code preferred `zsh`
        // in a container with no zsh installed, because the shim directory
        // offered it (Sep 10, 2026).
        let Some(real) = real_shell_on(shell, &dir, path) else {
            // A shim left behind by an earlier install still advertises
            // the shell; take it down with the same reasoning.
            let _ = std::fs::remove_file(dir.join(shell));
            continue;
        };
        let path = dir.join(shell);
        // A `-c` string is how a shell is asked to run one command, and it is
        // the form we forward. It may sit in a cluster - `bash -lc` is how
        // Codex spells it - or after other options (`sh -e -c`), so the shim
        // scans the options the way `split_segments_deep` does and forwards
        // the whole argument list, options intact, so `-l` and `-e` still
        // reach the shell that finally runs it (#69). An interactive shell
        // (no `-c`) or a script file is a human or a file at a terminal and
        // is passed through untouched, because gating a person's own login
        // shell is not what this is for.
        let script = format!(
            r#"#!/bin/sh
# termaxa shim - generated, do not edit.
# A `-c` string, alone or in a cluster such as `-lc` or `-ec`, is routed
# through the gate with the shell's other options intact; anything else
# (a script file, an interactive shell) is handed to the real shell unchanged.
expect_string=""
skip_next=""
for a in "$@"; do
  if [ -n "$skip_next" ]; then
    skip_next=""
    continue
  fi
  if [ -n "$expect_string" ]; then
    # Options may follow -c (`zsh -c -l "..."` is Claude Code's spelling);
    # the string is the first operand after them.
    case "$a" in
      --) break ;;
      -o) skip_next=1 ;;
      -*) ;;
      "") break ;;
      *) exec {bin} run -- {shell} "$@" ;;
    esac
    continue
  fi
  case "$a" in
    --) break ;;
    -) break ;;
    --*) ;;
    -o) skip_next=1 ;;
    -*c*) expect_string=1 ;;
    -*) ;;
    *) break ;;
  esac
done
exec {real} "$@"
"#,
            bin = termaxa_bin.display(),
            shell = shell,
            real = real.display(),
        );
        std::fs::write(&path, script)
            .with_context(|| format!("cannot write shim {}", path.display()))?;
        let mut p = std::fs::metadata(&path)?.permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&path, p)?;
    }
    Ok(dir)
}

/// The real binary a shim stands in front of, found on the given search path
/// outside the shim directory, or `None` when the shell is not installed at
/// all.
#[cfg(unix)]
fn real_shell_on(
    shell: &str,
    shim_dir: &std::path::Path,
    path: &std::ffi::OsStr,
) -> Option<std::path::PathBuf> {
    for d in std::env::split_paths(path) {
        if d == shim_dir {
            continue;
        }
        let candidate = d.join(shell);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Windows has no `$SHELL` convention and its shim story is different enough
/// that guessing at it would be worse than saying so.
///
/// v0.16 proves the model on one platform (the scope doc's words). Windows
/// gets its own residue analysis in v0.17 or an explicit "never" — either
/// way stated rather than left to a user to discover.
#[cfg(not(unix))]
pub fn install_shims(termaxa_home: &Path, _termaxa_bin: &Path) -> Result<PathBuf> {
    // Named rather than hand-waved: the message says where shims WOULD go and
    // which shells they would cover, so the refusal describes the missing
    // work instead of just declining.
    anyhow::bail!(
        "termaxa wrap is Unix-only in v0.16. Windows has no $SHELL convention, so \
         shims for {shells} under {dir} would not be consulted the way they are on \
         Unix, and guessing at an equivalent is worse than saying so. Use hook mode, \
         which is fully supported on Windows.",
        shells = SHIMMED_SHELLS.join("/"),
        dir = shim_dir(termaxa_home).display(),
    )
}

/// The program and `PATH` an approved command runs with: the shim directory
/// taken out of `PATH`, and a bare program name resolved through what is
/// left, so it is the real shell and not the shim again.
///
/// #65. The shim forwards `sh -c "<cmd>"` to `termaxa run -- sh "$@"`.
/// The runner then executed `sh` by name, through the same `PATH` the
/// wrapper had set up, and got the shim: an allowed command recursed
/// without end (`wrap -- sh -c 'echo hi'` hung), an asked one asked twice
/// and then found no stdin. Nothing ever reached `/bin/sh`. Measured on
/// 2026-09-03; the residue test had pinned a deny and a bypass, never an
/// execution.
///
/// The command's own children run with the same stripped `PATH`, which is
/// the intent: what was approved was the command and what it spawns. A
/// program given with a path separator is left alone; a bare name that
/// resolves nowhere is left bare, for the OS to report as before.
pub fn outside_shims(
    program: &str,
    path: Option<&std::ffi::OsStr>,
    termaxa_home: &Path,
) -> (std::ffi::OsString, std::ffi::OsString) {
    let shims = shim_dir(termaxa_home);
    let same_dir = |entry: &str| -> bool {
        let e = Path::new(entry);
        e == shims
            || match (e.canonicalize(), shims.canonicalize()) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
    };
    let kept: Vec<String> = path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
        .split(path_separator())
        .filter(|entry| !entry.is_empty() && !same_dir(entry))
        .map(str::to_string)
        .collect();
    let stripped: std::ffi::OsString = kept.join(path_separator()).into();
    let bare = !program.contains('/') && !program.contains('\\');
    let resolved = if bare {
        kept.iter()
            .map(|dir| Path::new(dir).join(program))
            .find(|candidate| is_executable_file(candidate))
            .map(|p| p.into_os_string())
            .unwrap_or_else(|| program.into())
    } else {
        program.into()
    };
    (resolved, stripped)
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// The shell the agent is told to use: the shim for the shell it would have
/// chosen on its own. Claude Code looks for zsh first and bash second
/// (measured Sep 10, 2026), and on a Mac the user's PATH and aliases live in
/// `~/.zshrc`; v0.18.5 handed every such machine the `bash` shim and moved
/// the agent to `bash -l` (measured Sep 11: zsh installed, not one zsh probe,
/// five bash spawns). So: the `zsh` shim when a real zsh exists - the shim
/// is only written when one does - else the `bash` shim, else the `sh` shim.
/// The agent keeps its environment; only the gate is inserted. Claude Code
/// accepts only a bash or zsh path in `CLAUDE_CODE_SHELL` and `$SHELL`;
/// other harnesses that read `$SHELL` get a shim either way.
pub(crate) fn agent_shell(shim_dir: &Path) -> PathBuf {
    for name in ["zsh", "bash"] {
        let shim = shim_dir.join(name);
        if shim.is_file() {
            return shim;
        }
    }
    shim_dir.join("sh")
}

/// The shell to hand the agent, given what the operator set. A
/// `CLAUDE_CODE_SHELL` that already names one of the shims is the operator
/// choosing a shell inside the gate, and is kept as is. Anything else -
/// unset, or a path outside the shim directory - becomes [`agent_shell`],
/// and the override is returned so `run` can say so: a wrapper that silently
/// routes nothing is the failure this repairs.
pub(crate) fn chosen_shell(shim_dir: &Path, operator: Option<&Path>) -> (PathBuf, Option<PathBuf>) {
    if let Some(op) = operator {
        if op.parent() == Some(shim_dir) && op.is_file() {
            return (op.to_path_buf(), None);
        }
        return (agent_shell(shim_dir), Some(op.to_path_buf()));
    }
    (agent_shell(shim_dir), None)
}

/// Launch `argv` with the shims in front of it.
pub fn run(argv: &[String], termaxa_home: &Path) -> Result<i32> {
    if argv.is_empty() {
        anyhow::bail!("nothing to wrap: termaxa wrap -- <command>");
    }
    let bin = std::env::current_exe().context("cannot locate the termaxa binary")?;
    let dir = install_shims(termaxa_home, &bin)?;

    let existing = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}{}{}", dir.display(), path_separator(), existing);

    // Claude Code never resolves bash through PATH. Measured Sep 10, 2026
    // under strace: it probes zsh at four absolute paths and then runs
    // `/bin/bash` by absolute path for its snapshot and every Bash tool
    // call, so on a box without zsh the shim saw nothing and `rm -rf
    // ./scratch` ran with no audit entry, three times. It does honour
    // `CLAUDE_CODE_SHELL` (documented: a path to a bash or zsh binary, taken
    // over its own detection), and reads `$SHELL` only when that names bash
    // or zsh - the `sh` shim it was handed is neither. So both point at the
    // shim for the shell it would have chosen itself (`agent_shell`), and the
    // same run then went through the shim five times out of five. An
    // operator value naming one of the shims is kept; one pointing outside
    // the shim directory is overridden and said so.
    let operator = std::env::var_os("CLAUDE_CODE_SHELL").map(PathBuf::from);
    let (shell, overridden) = chosen_shell(&dir, operator.as_deref());
    if let Some(prev) = overridden {
        eprintln!(
            "termaxa wrap: CLAUDE_CODE_SHELL was {}; set to {} so Claude Code's shell is the gate",
            prev.display(),
            shell.display()
        );
    }

    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env("PATH", path)
        .env("SHELL", &shell)
        .env("CLAUDE_CODE_SHELL", &shell)
        // A marker the gate can see, so a shimmed command is distinguishable
        // in the record from one that arrived by hook. Not a security
        // control - anything in the child can unset it - which is why it is
        // provenance rather than policy input.
        .env("TERMAXA_WRAPPED", "1");

    // THE ENDPOINT, and only the endpoint.
    //
    // The wrapped process runs as the agent, whose $HOME is deliberately not
    // the operator's - so it cannot discover the socket the way the operator
    // does, and must be TOLD. The first proving run found this the hard way:
    // an agent's hook looked in its own home, found nothing, and decided
    // locally while the supervisor sat idle.
    //
    // What travels is the socket path. NOT TERMAXA_HOME: pointing the agent's
    // state directory at the operator's would reverse the ownership model and
    // establish a convention where an environment variable hands an agent a
    // path to privileged state. The agent needs to ask; it does not need to
    // know where the answers are kept.
    if let Some(sock) = crate::supervise::endpoint() {
        cmd.env(crate::supervise::SOCKET_ENV, &sock);
    }

    let status = cmd
        .status()
        .with_context(|| format!("cannot launch {}", argv[0]))?;
    Ok(status.code().unwrap_or(1))
}

fn path_separator() -> &'static str {
    if cfg!(windows) {
        ";"
    } else {
        ":"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempTree;

    /// The search path the shell tests use, so a `PATH` rewritten by another
    /// test's guard on another thread cannot make `sh` vanish mid-test.
    #[cfg(unix)]
    const SEARCH: &str = "/usr/local/bin:/usr/bin:/bin";

    #[cfg(unix)]
    fn shims(home: &Path) -> PathBuf {
        install_shims_on(
            home,
            Path::new("/usr/bin/termaxa"),
            std::ffi::OsStr::new(SEARCH),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn real(shell: &str, dir: &Path) -> Option<PathBuf> {
        real_shell_on(shell, dir, std::ffi::OsStr::new(SEARCH))
    }

    /// The agent is told to use the shim for the shell it would have chosen
    /// itself: zsh when a real zsh exists (the shim is only written when one
    /// does), else bash, else sh. Pinned on a synthetic shim directory so it
    /// does not depend on what the test machine has installed, and once on
    /// the real one, where the answer is whichever of zsh and bash exists.
    #[cfg(unix)]
    #[test]
    fn the_agent_is_told_to_use_the_shim_for_the_shell_it_would_have_chosen() {
        let t = TempTree::new("wrap-agent-shell");
        let fake = t.path().join("fake-shims");
        std::fs::create_dir_all(&fake).unwrap();
        for name in ["sh", "bash", "zsh"] {
            std::fs::write(fake.join(name), "#!/bin/sh\n").unwrap();
        }
        assert_eq!(agent_shell(&fake), fake.join("zsh"));
        std::fs::remove_file(fake.join("zsh")).unwrap();
        assert_eq!(agent_shell(&fake), fake.join("bash"));
        std::fs::remove_file(fake.join("bash")).unwrap();
        assert_eq!(agent_shell(&fake), fake.join("sh"));

        let dir = shims(t.path());
        let want = if dir.join("zsh").is_file() {
            dir.join("zsh")
        } else {
            dir.join("bash")
        };
        assert_eq!(agent_shell(&dir), want);
    }

    /// An operator value that already names one of the shims is the operator
    /// choosing a shell inside the gate, and is kept. A value outside the
    /// shim directory - or naming a shim that does not exist - is replaced
    /// and reported. Unset is the default.
    #[cfg(unix)]
    #[test]
    fn an_operators_shim_is_kept_and_anything_else_is_overridden_and_said() {
        let t = TempTree::new("wrap-chosen-shell");
        let fake = t.path().join("fake-shims");
        std::fs::create_dir_all(&fake).unwrap();
        for name in ["sh", "bash", "zsh"] {
            std::fs::write(fake.join(name), "#!/bin/sh\n").unwrap();
        }
        assert_eq!(chosen_shell(&fake, None), (fake.join("zsh"), None));
        assert_eq!(
            chosen_shell(&fake, Some(&fake.join("bash"))),
            (fake.join("bash"), None),
            "the operator's own shim is kept"
        );
        assert_eq!(
            chosen_shell(&fake, Some(&fake.join("sh"))),
            (fake.join("sh"), None)
        );
        let outside = Path::new("/opt/homebrew/bin/bash");
        assert_eq!(
            chosen_shell(&fake, Some(outside)),
            (fake.join("zsh"), Some(outside.to_path_buf())),
            "outside the shim directory: replaced and reported"
        );
        let missing = fake.join("fish");
        assert_eq!(
            chosen_shell(&fake, Some(&missing)),
            (fake.join("zsh"), Some(missing.clone())),
            "a shim that does not exist is not a shim"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shims_are_written_executable_and_not_writable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempTree::new("wrap-shims");
        let home = t.path();
        let dir = shims(home);

        for shell in SHIMMED_SHELLS {
            let p = dir.join(shell);
            if real(shell, &dir).is_none() {
                assert!(
                    !p.exists(),
                    "no shim for a shell that is not installed: {shell}"
                );
                continue;
            }
            assert!(p.exists(), "{shell} shim exists");
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "{shell} is executable");
            assert_eq!(
                mode & 0o022,
                0,
                "{shell} must not be group- or world-writable: a writable file on \
                 PATH is a way to run code, not a way to gate it (#51)"
            );
        }
    }

    /// The shim forwards `-c` to the gate and everything else to the real
    /// shell. An interactive shell is a person at a terminal; gating that is
    /// not what this is for, and a shim that swallowed it would break login.
    #[cfg(unix)]
    #[test]
    fn the_shim_routes_dash_c_and_passes_everything_else_through() {
        let t = TempTree::new("wrap-script");
        let dir = shims(t.path());
        let script = std::fs::read_to_string(dir.join("sh")).unwrap();

        assert!(
            script.contains("/usr/bin/termaxa run --"),
            "a -c command goes through the runner: {script}"
        );
        let real = real("sh", &dir).expect("sh exists on any unix test machine");
        assert!(
            script.contains(&format!("exec {} \"$@\"", real.display())),
            "anything else reaches the real shell by its resolved path: {script}"
        );
        // Options after -c are stepped over; the first operand routes.
        assert!(
            script.contains("-o) skip_next=1 ;;")
                && script.contains("exec /usr/bin/termaxa run --"),
            "{script}"
        );
        assert!(
            script.contains("exec "),
            "exec rather than a nested shell, so the shim adds no process: {script}"
        );
    }

    /// THE RESIDUE, pinned so it is never quietly assumed away.
    ///
    /// A shim on PATH catches a shell resolved BY NAME. It does not catch
    /// `/bin/sh` by absolute path, and it cannot — nothing consults PATH for
    /// an absolute path. Measured inside a real wrapper:
    ///
    ///     wrap -- sh -c "rm -rf victim"        blocked by policy
    ///     wrap -- /bin/sh -c "rm -rf victim"   ran ungated
    ///
    /// This is the grades table's "escape via tools that execute without
    /// spawning through the wrapper", made concrete. A test that only proved
    /// the happy path would let someone read the wrapper as interception.
    /// #65: the runner's own `sh` must be the real one. The shim directory
    /// leaves `PATH`, a bare name resolves through what remains, a path
    /// is left alone, and a name that resolves nowhere stays bare.
    #[cfg(unix)]
    #[test]
    fn an_approved_command_runs_outside_the_shims() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempTree::new("wrap-outside");
        let dir = shims(t.path());
        let real = t.dir("realbin");
        std::fs::write(real.join("sh"), "#!/bin/sh\nexit 0\n").unwrap();
        let mut p = std::fs::metadata(real.join("sh")).unwrap().permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(real.join("sh"), p).unwrap();

        let path = format!("{}:{}:/nonexistent", dir.display(), real.display());
        let (program, stripped) = outside_shims("sh", Some(std::ffi::OsStr::new(&path)), t.path());
        assert_eq!(
            program,
            real.join("sh").into_os_string(),
            "the bare name resolves past the shim to the real shell"
        );
        let stripped = stripped.to_string_lossy().into_owned();
        assert!(
            !stripped.contains(&dir.display().to_string()),
            "the shim directory is out of the child's PATH: {stripped}"
        );
        assert!(
            stripped.starts_with(&real.display().to_string()),
            "{stripped}"
        );

        // A trailing slash is the same directory.
        let path = format!("{}/:{}", dir.display(), real.display());
        let (_, stripped) = outside_shims("sh", Some(std::ffi::OsStr::new(&path)), t.path());
        assert!(
            !stripped.to_string_lossy().contains("shims"),
            "{stripped:?}"
        );

        // A program given as a path is left alone; a name that resolves
        // nowhere stays a name.
        let (program, _) = outside_shims("/bin/sh", Some(std::ffi::OsStr::new(&path)), t.path());
        assert_eq!(program, std::ffi::OsString::from("/bin/sh"));
        let (program, _) = outside_shims(
            "no-such-program-tmx",
            Some(std::ffi::OsStr::new(&path)),
            t.path(),
        );
        assert_eq!(program, std::ffi::OsString::from("no-such-program-tmx"));

        // No shims on PATH at all: nothing changes but the resolution.
        let (_, same) = outside_shims("sh", Some(std::ffi::OsStr::new("/usr/bin:/bin")), t.path());
        assert_eq!(same, std::ffi::OsString::from("/usr/bin:/bin"));
    }

    #[cfg(unix)]
    #[test]
    fn an_absolute_path_shell_is_outside_what_a_path_shim_can_reach() {
        let t = TempTree::new("wrap-residue");
        let dir = shims(t.path());

        // The shim answers to the NAME. That is the whole mechanism.
        assert!(dir.join("sh").exists());

        // And nothing here, or anywhere, puts a file at /bin/sh - so a caller
        // naming that path reaches the system shell directly. Asserted as a
        // property of the design rather than by touching /bin.
        assert!(
            !dir.join("bin").exists(),
            "the shim dir shadows names on PATH, not absolute paths"
        );
    }

    /// The shim directory lives under the Termaxa home, never in the project.
    /// In the project it would be agent-writable in every mode, which turns a
    /// gate into an execution primitive (#51).
    #[test]
    fn the_shim_directory_is_outside_the_project() {
        let t = TempTree::new("wrap-location");
        let home = t.path();
        let dir = shim_dir(home);
        assert!(dir.starts_with(home), "{}", dir.display());
        assert!(
            !dir.to_string_lossy().contains(".termaxa/policy"),
            "not beside the policy the agent may read"
        );
    }
}
