//! Terminal presentation helpers.
//!
//! Deliberately dependency-free: raw ANSI escapes behind a colour gate, not a
//! crate. Termaxa ships as a small single binary and the dependency tree is
//! part of the product (a security tool people audit), so a colour library
//! isn't worth a supply-chain edge.
//!
//! Colour is suppressed when output isn't a terminal (piped/redirected), when
//! `NO_COLOR` is set (https://no-color.org), or when `TERMAXA_NO_COLOR` is set.
//! That means `termaxa check ... > out.txt` and CI logs stay clean.

use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Whether ANSI colour should be emitted. Computed once per process.
pub fn colour_enabled() -> bool {
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("TERMAXA_NO_COLOR").is_some()
        {
            return false;
        }
        // CLICOLOR_FORCE=1 wins over TTY detection (used by CI that wants colour).
        if std::env::var("CLICOLOR_FORCE")
            .map(|v| v != "0")
            .unwrap_or(false)
        {
            return true;
        }
        is_tty()
    })
}

#[cfg(unix)]
fn is_tty() -> bool {
    // SAFETY: isatty on a constant fd is a pure query with no side effects.
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

#[cfg(windows)]
fn is_tty() -> bool {
    // `GetConsoleMode` succeeds only for a real console handle: for a file or
    // a pipe it fails. That is exactly the question "is stdout a terminal?",
    // and it costs two FFI declarations rather than a dependency.
    //
    // Found by live testing: the previous version returned `true`
    // unconditionally, so `termaxa doctor > out.txt` wrote escape sequences
    // into the file.
    type Handle = *mut core::ffi::c_void;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> Handle;
        fn GetConsoleMode(h_console_handle: Handle, lp_mode: *mut u32) -> i32;
    }
    // SAFETY: both calls are pure queries on a process-owned standard handle.
    // GetConsoleMode writes only into `mode`, and returns 0 on failure
    // (redirected output), which is the answer we want.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;
        GetConsoleMode(handle, &mut mode) != 0
    }
}

#[cfg(not(any(unix, windows)))]
fn is_tty() -> bool {
    // Unknown platform: assume not a terminal. Plain text is always readable;
    // escape sequences in a log file are not.
    false
}

fn wrap(code: &str, s: &str) -> String {
    if colour_enabled() {
        format!("\x1b[{}m{}\x1b[0m", code, s)
    } else {
        s.to_string()
    }
}

pub fn green(s: &str) -> String {
    wrap("32", s)
}
pub fn amber(s: &str) -> String {
    wrap("33", s)
}
pub fn red(s: &str) -> String {
    wrap("31", s)
}
pub fn dim(s: &str) -> String {
    wrap("2", s)
}
pub fn bold(s: &str) -> String {
    wrap("1", s)
}
pub fn cyan(s: &str) -> String {
    wrap("36", s)
}

/// Colourise a decision word by severity. The single place that maps
/// allow/ask/deny to colour, so every surface agrees.
pub fn decision(action: &str) -> String {
    match action {
        "allow" => green(action),
        "ask" => amber(action),
        "deny" => red(&bold(action)),
        other => other.to_string(),
    }
}

/// The mark for a decision, colourised. Mirrors `report::mark_for` semantics:
/// a post-execution receipt is a success, not a denial.
pub fn mark(action: &str, source: &str) -> String {
    match (action, source) {
        (_, "post") => green("✓"),
        ("resumed", _) => green("▶"),
        ("tripped", _) => red("⚡"),
        ("allow", _) => green("✓"),
        ("ask", _) => amber("?"),
        ("deny", _) => red("✗"),
        _ => dim("•"),
    }
}

/// A label/value line with aligned columns, e.g. "decision  deny".
///
/// The label is padded BEFORE it is colourised. Padding a string that already
/// contains ANSI escapes counts the escape bytes toward the width, so
/// `{:<10}` on a dimmed 7-letter word adds no padding at all and the columns
/// collapse. (Found by live testing: `commandrm -rf /`.)
pub fn field(label: &str, value: &str) -> String {
    format!("{}{}", dim(&format!("{:<10}", label)), value)
}

/// The welcome screen: what `termaxa` with no arguments prints.
///
/// Deliberately NOT clap's `--help`. A wall of flags teaches nothing; five
/// lines and one runnable command teach the whole product. The challenge
/// command works with zero setup (demo mode), so the next thing the reader
/// does is see a real verdict.
pub fn welcome(version: &str) {
    println!();
    println!("  {} {}", bold(&green("termaxa")), dim(version));
    println!();
    println!("  Predict what will happen.");
    println!("  Protect what matters.");
    println!("  Recover when you're wrong.");
    println!();
    println!("  {}", dim("Try this — no setup required:"));
    println!();
    println!("      {}", cyan("termaxa check \"rm -rf /\""));
    println!();
    println!("  {}", dim("Then, in a project you're working in:"));
    println!();
    println!(
        "      {}   {}",
        cyan("termaxa init --claude-code"),
        dim("(or --cursor)")
    );
    println!(
        "      {}                {}",
        cyan("termaxa doctor"),
        dim("check the wiring")
    );
    println!(
        "      {}                {}",
        cyan("termaxa report"),
        dim("what your agent did")
    );
    println!();
    println!("  {}", dim("termaxa --help for the full surface"));
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_words_are_unchanged_when_colour_is_off() {
        // Under `cargo test` stdout is captured, and NO_COLOR may or may not be
        // set — either way the *text* must survive intact, since scripts and
        // tests parse these words.
        for w in ["allow", "ask", "deny"] {
            assert!(decision(w).contains(w), "decision() dropped the word {w}");
        }
    }

    #[test]
    fn post_receipts_mark_as_success_not_denial() {
        // Same invariant report.rs pins: an executed command is a success.
        assert!(mark("ask", "post").contains('✓'));
        assert!(mark("deny", "post").contains('✓'));
        assert!(mark("deny", "hook").contains('✗'));
        assert!(mark("ask", "hook").contains('?'));
        assert!(mark("allow", "hook").contains('✓'));
    }

    #[test]
    fn field_pads_the_label_before_colouring_it() {
        // Regression: padding a colourised label counts escape bytes toward
        // the width, producing "commandrm -rf /" with no gap. The value must
        // always be separated from the label by whitespace.
        let line = field("command", "rm -rf /");
        assert!(line.contains("command"));
        assert!(line.contains("rm -rf /"));
        let plain: String = strip_ansi(&line);
        assert!(
            plain.starts_with("command   "),
            "label must be padded to a fixed column, got {plain:?}"
        );
        assert!(plain.ends_with("rm -rf /"));
        // Short and long labels land the value in the same column.
        assert_eq!(
            strip_ansi(&field("rule", "x")).find('x'),
            strip_ansi(&field("reason", "x")).find('x'),
            "all labels must align the value to the same column"
        );
    }

    #[test]
    fn every_colour_helper_keeps_the_text_it_wraps() {
        // The words are the product: a helper that dropped or replaced its
        // text would still "look coloured" to a passing eye.
        for (name, got) in [
            ("green", green("hello")),
            ("amber", amber("hello")),
            ("red", red("hello")),
            ("dim", dim("hello")),
            ("bold", bold("hello")),
            ("cyan", cyan("hello")),
        ] {
            assert!(got.contains("hello"), "{name}() dropped its text: {got:?}");
        }
    }

    #[test]
    fn every_colour_helper_answers_to_the_same_gate() {
        // Either all of them wrap or none does. A mixed answer means one
        // stopped consulting `colour_enabled` and hard-coded its own verdict.
        for (name, got) in [
            ("green", green("x")),
            ("amber", amber("x")),
            ("red", red("x")),
            ("dim", dim("x")),
            ("bold", bold("x")),
            ("cyan", cyan("x")),
        ] {
            assert_eq!(
                got != "x",
                colour_enabled(),
                "{name}() disagrees with the colour gate: {got:?}"
            );
        }
    }

    #[test]
    fn an_unrecognised_decision_word_passes_through_unchanged() {
        // `decision` is a presentation map, not a validator: a word it does
        // not know must still reach the reader.
        assert_eq!(decision("skipped"), "skipped");
        assert!(mark("skipped", "hook").contains('•'));
    }

    /// Test helper: drop ANSI escape sequences so assertions can look at the
    /// text a human would see.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }
}
