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
//! NO HARNESS IS CLAIMED AS COVERED (#20, #45). Whether a given agent's shell
//! tool resolves `sh` through `PATH` or hardcodes `/bin/sh` is an empirical
//! question about that agent, and nobody here has watched one do it. `doctor`
//! reports what is wired; it does not promise what an unobserved harness will
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
    use std::os::unix::fs::PermissionsExt;

    let dir = shim_dir(termaxa_home);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("cannot create shim directory {}", dir.display()))?;

    // 0755: the agent user must traverse and execute, and must not write.
    let mut perm = std::fs::metadata(&dir)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&dir, perm)?;

    for shell in SHIMMED_SHELLS {
        let path = dir.join(shell);
        // `-c "cmd"` is how a shell is asked to run one command, and it is
        // the only form we forward: the agent's shell tool uses it. An
        // interactive shell (no `-c`) is a human at a terminal and is passed
        // through untouched, because gating a person's own login shell is not
        // what this is for.
        let script = format!(
            "#!/bin/sh\n\
             # termaxa shim — generated, do not edit.\n\
             # `sh -c \"<command>\"` is routed through the gate; anything else\n\
             # is handed to the real shell unchanged.\n\
             if [ \"$1\" = \"-c\" ] && [ -n \"$2\" ]; then\n\
             \x20 exec {bin} run -- {shell} -c \"$2\"\n\
             fi\n\
             exec /bin/{shell} \"$@\"\n",
            bin = termaxa_bin.display(),
            shell = shell,
        );
        std::fs::write(&path, script)
            .with_context(|| format!("cannot write shim {}", path.display()))?;
        let mut p = std::fs::metadata(&path)?.permissions();
        p.set_mode(0o755);
        std::fs::set_permissions(&path, p)?;
    }
    Ok(dir)
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

/// Launch `argv` with the shims in front of it.
pub fn run(argv: &[String], termaxa_home: &Path) -> Result<i32> {
    if argv.is_empty() {
        anyhow::bail!("nothing to wrap: termaxa wrap -- <command>");
    }
    let bin = std::env::current_exe().context("cannot locate the termaxa binary")?;
    let dir = install_shims(termaxa_home, &bin)?;

    let existing = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}{}{}", dir.display(), path_separator(), existing);

    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env("PATH", path)
        .env("SHELL", dir.join("sh"))
        // A marker the gate can see, so a shimmed command is distinguishable
        // in the record from one that arrived by hook. Not a security
        // control - anything in the child can unset it - which is why it is
        // provenance rather than policy input.
        .env("TERMAXA_WRAPPED", "1");

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

    #[cfg(unix)]
    #[test]
    fn shims_are_written_executable_and_not_writable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempTree::new("wrap-shims");
        let home = t.path();
        let dir = install_shims(home, Path::new("/usr/bin/termaxa")).unwrap();

        for shell in SHIMMED_SHELLS {
            let p = dir.join(shell);
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
        let dir = install_shims(t.path(), Path::new("/usr/bin/termaxa")).unwrap();
        let script = std::fs::read_to_string(dir.join("sh")).unwrap();

        assert!(
            script.contains("/usr/bin/termaxa run --"),
            "a -c command goes through the runner: {script}"
        );
        assert!(
            script.contains("exec /bin/sh \"$@\""),
            "anything else reaches the real shell: {script}"
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
    #[cfg(unix)]
    #[test]
    fn an_absolute_path_shell_is_outside_what_a_path_shim_can_reach() {
        let t = TempTree::new("wrap-residue");
        let dir = install_shims(t.path(), Path::new("/usr/bin/termaxa")).unwrap();

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
