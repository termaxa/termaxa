//! A stand-in for a program the tests spawn, built for every platform (#59).
//!
//! Not an example of using termaxa. Cargo builds every file in `examples/`
//! during a plain `cargo test` and never installs one, which is what a test
//! fixture needs. A test copies this binary into a scratch directory under
//! the name of the program it stands in for (`psql`, `psql.exe`) and writes
//! its script beside the copy, with the extension `stub`: what to print on
//! stdout and on stderr, the exit code, and optionally a file to write its
//! arguments to, one per line (`testutil::stub_program`). A `#!/bin/sh`
//! file did this before, and ran nowhere but unix.

use std::io::Write as _;

fn main() {
    let exe = std::env::current_exe().expect("a running program has a path");
    let script_path = exe.with_extension("stub");
    let script = match std::fs::read_to_string(&script_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("test_stub: cannot read {}: {e}", script_path.display());
            std::process::exit(97);
        }
    };
    let script: serde_json::Value = match serde_json::from_str(&script) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("test_stub: {} is not JSON: {e}", script_path.display());
            std::process::exit(98);
        }
    };
    if let Some(to) = script["argv_to"].as_str() {
        let mut argv = String::new();
        for arg in std::env::args_os().skip(1) {
            argv.push_str(&arg.to_string_lossy());
            argv.push('\n');
        }
        if let Err(e) = std::fs::write(to, argv) {
            eprintln!("test_stub: cannot write {to}: {e}");
            std::process::exit(99);
        }
    }
    let text = |key: &str| script[key].as_str().unwrap_or_default().to_string();
    // Each followed by a newline, as `printf '%s\n'` printed them.
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", text("stdout"));
    let _ = out.flush();
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{}", text("stderr"));
    let _ = err.flush();
    let code = script["code"].as_i64().unwrap_or(0);
    std::process::exit(i32::try_from(code).unwrap_or(1));
}
