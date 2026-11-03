//! The shipped docs must be valid UTF-8.
//!
//! INCIDENT (2026-08-14, v0.15.0 prep): a `Get-Content | -replace |
//! Set-Content` one-liner on Windows PowerShell 5.1 — default encoding
//! ANSI — wrote the CHANGELOG's new heading with a CP-1252 em dash (0x97)
//! and clipped multibyte sequences in the section body. The file rendered
//! as mojibake and failed every tool that assumes UTF-8, and it was caught
//! minutes before an immutable tag. README.md itself warns that PS 5.1
//! mangles redirected Unicode; the warning now has an enforcer.
//! (examples/policy.yaml needs no line here: `include_str!` already makes
//! invalid UTF-8 a compile error.)

#[test]
fn the_shipped_docs_are_valid_utf8() {
    for name in [
        "CHANGELOG.md",
        "README.md",
        "README.ja.md",
        "SECURITY.md",
        "RELEASING.md",
    ] {
        let path = concat_root(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        if let Err(e) = std::str::from_utf8(&bytes) {
            let pos = e.valid_up_to();
            let ctx = String::from_utf8_lossy(&bytes[pos.saturating_sub(40)..pos]);
            panic!(
                "{name} is not valid UTF-8 at byte {pos} (0x{:02x}), just after: …{ctx}\n\
                 Likely a Windows shell edit without `-Encoding utf8`. Repair the \
                 stray CP-1252 bytes — do not blind-convert, most of the file is \
                 already correct UTF-8.",
                bytes[pos]
            );
        }
    }
}

fn concat_root(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name)
}
