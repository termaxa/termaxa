//! `termaxa demo`: the gate on a throwaway project, in twenty seconds.
//!
//! Builds a scratch project in the system temp directory - twelve files in
//! `scratch/`, a `.env`, the starter policy - and runs the real `check` and
//! `log` subcommands in it through the current executable, with one line of
//! narration before each. Nothing here is a mock: the previews, verdicts
//! and audit lines are the ones a user gets, on a tree that exists. The
//! project is removed afterwards; the audit log stays under the state
//! directory like any other project's.
//!
//! Until v0.21.8 the project sat under the demo state directory,
//! `~/.termaxa/demo/project-<ts>`, and from v0.21.3, when the gate's own
//! files became a path rule on the floor (`*/.termaxa/*`), every check in it
//! was denied by that rule: the demo promised a blast radius, a `.env` rule
//! and an ask, and printed "Termaxa's own config is off limits" three times
//! (found Nov 2, 2026, writing a reviewer's quickstart). The test ran with a
//! `TERMAXA_HOME` whose name was not `.termaxa`, so it never saw it.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// The commands the demo checks, with what each one shows.
const STEPS: &[(&str, &str)] = &[
    (
        "A recursive delete: the blast radius is counted before anything runs, and the starter denies it.",
        "rm -rf ./scratch",
    ),
    (
        "A write to .env: a path rule fires whatever the command is spelled like.",
        "echo TOKEN=abc > .env",
    ),
    (
        "A single-file delete: an ask, with the file named and insurance planned before it would run.",
        "rm scratch/f1.txt",
    ),
];

pub fn run() -> Result<i32> {
    let exe = std::env::current_exe().context("cannot find the termaxa binary")?;
    let root = std::env::temp_dir().join(format!("termaxa-demo-{}", crate::audit::now().0));
    build_project(&root)?;
    let result = play(&exe, &root);
    let _ = std::fs::remove_dir_all(&root);
    result
}

fn build_project(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("scratch"))?;
    for i in 1..=12 {
        std::fs::write(
            root.join("scratch").join(format!("f{i}.txt")),
            format!("line {i}\n"),
        )?;
    }
    std::fs::write(root.join(".env"), "API_KEY=not-a-real-key\n")?;
    std::fs::create_dir_all(root.join(".termaxa"))?;
    std::fs::write(
        root.join(".termaxa").join("policy.yaml"),
        crate::init::STARTER_POLICY,
    )?;
    Ok(())
}

fn play(exe: &Path, root: &Path) -> Result<i32> {
    println!();
    println!(
        "{}",
        crate::ui::dim(&format!(
            "termaxa demo — a scratch project at {} (12 files in scratch/, a .env, the starter policy). Removed when this ends.",
            root.display()
        ))
    );
    for (what, command) in STEPS {
        println!();
        println!("{}", crate::ui::dim(&format!("▸ {what}")));
        println!(
            "{}",
            crate::ui::dim(&format!("$ termaxa check \"{command}\""))
        );
        let status = Command::new(exe)
            .args(["check", command])
            .current_dir(root)
            .status()
            .with_context(|| format!("cannot run {} check", exe.display()))?;
        let _ = status;
    }
    println!();
    println!(
        "{}",
        crate::ui::dim("▸ Every verdict is in the record, which the agent cannot rewrite.")
    );
    println!("{}", crate::ui::dim("$ termaxa log"));
    Command::new(exe)
        .arg("log")
        .current_dir(root)
        .status()
        .context("cannot run termaxa log")?;
    println!();
    println!(
        "{}",
        crate::ui::dim(
            "Next: `termaxa init` in a project of yours wires the hook for the agent it finds."
        )
    );
    Ok(0)
}
