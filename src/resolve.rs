//! What a command's targets actually point at.
//!
//! Roadmap 2.4, the spine of v0.16. Every engine used to answer "what does this
//! command touch?" from the SPELLING — `delete.rs` resolved for its preview,
//! `backup.rs` resolved again for its insurance, and `policy.rs` never resolved
//! at all, matching rule patterns against the raw string. So `> ./.env` and
//! `> .env` are the same file and different strings, and only the string
//! reached the gate (known-limitations 0.2, still pinned).
//!
//! This module resolves once, upstream, and hands every consumer the same
//! answer. It is Schipper's `protect.rs` approach — resolve against the payload
//! cwd, classify the real path, decide — generalised from the write path to
//! commands.
//!
//! TWO READINGS, ALWAYS BOTH. A target keeps `as_written` even when it resolves
//! cleanly, because the two answer different questions: `resolved` is what will
//! be destroyed, `as_written` is what the human typed and what a reason line
//! must quote back. Collapsing them would make the gate's explanation of itself
//! less legible than the command it is judging.
//!
//! RESOLUTION IS LEXICAL AND EXECUTES NOTHING. `.`, `..`, `~`, and the WSL and
//! Git Bash path spellings are handled by `delete::resolve_path_in`. Shell
//! variables are NOT expanded — expanding `$HOME` would mean reading the
//! environment the gate runs in, which is not necessarily the environment the
//! command will run in. `$(...)` is command substitution and stays fenced
//! upstream by `shell::has_substitution`; this module never sees it as a target.
//!
//! UNRESOLVED IS A STATE, NOT A VERDICT. A target carrying `$VAR` cannot be
//! resolved lexically, and that fact is carried in the value rather than
//! collapsed into a decision here. The policy layer decides what an unresolved
//! target with a given shape is worth; this module only reports what it found.
//! That ordering is deliberate: resolution that decides is resolution that
//! cannot be reused by a consumer wanting a different policy.

// This module lands one commit ahead of its consumers, deliberately: the
// representation is reviewable on its own, and wiring it into evaluation is a
// separate change with its own behaviour to argue about. Until that lands,
// every item here is dead by construction. The allow is scoped to this module
// and comes off in the commit that threads it through `policy::evaluate`.
#![allow(dead_code)]

use crate::delete;
use std::path::{Path, PathBuf};

/// A property of a target that makes an unresolved one worth failing closed on.
///
/// These are computed for EVERY target, resolved or not, because a caller
/// asking "is this sensitive?" should not have to ask "did it resolve?" first.
/// What the policy layer does with them differs by resolution state; what this
/// module reports does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveShape {
    /// `$VAR`, `${VAR}` or `%VAR%` — the target's real path depends on an
    /// environment this gate cannot read reliably. The most important shape:
    /// it is the only one that also makes the target unresolvable, so it is
    /// the case where the gate genuinely does not know what it is judging.
    UnexpandedVar,
    /// Resolves outside the project root. Not automatically wrong — plenty of
    /// legitimate work touches `~/.cache` — but it is the shape of the field
    /// report this project exists because of: `rm -rf "/c/Users/harih"` from
    /// inside a project directory.
    OutsideRoot,
    /// Resolves to a user profile, or a sibling of one. The 70,201-file case.
    UnderUserProfile,
    /// Names one of the gate's own assets: anything under `.termaxa/`, or an
    /// agent hook configuration. Reuses `protect::classify` rather than
    /// restating the list, so the write path and the command path cannot
    /// disagree about what is protected (#37).
    ProtectedName,
}

impl SensitiveShape {
    /// Short phrase for a reason line, written to read naturally after the
    /// target: "`$HOME/.ssh` — depends on an unexpanded variable".
    pub fn label(self) -> &'static str {
        match self {
            SensitiveShape::UnexpandedVar => "depends on an unexpanded variable",
            SensitiveShape::OutsideRoot => "resolves outside the project",
            SensitiveShape::UnderUserProfile => "resolves to a user profile",
            SensitiveShape::ProtectedName => "names the gate's own files",
        }
    }
}

/// One target of a command, in both readings.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedTarget {
    /// Exactly what appeared in the command, quotes stripped. Never empty.
    pub as_written: String,
    /// The lexically resolved path, or `None` when resolution could not be
    /// completed — today that means an unexpanded variable, the one thing
    /// lexical resolution genuinely cannot see through.
    pub resolved: Option<PathBuf>,
    /// Everything notable about this target, in a stable order.
    pub shapes: Vec<SensitiveShape>,
}

impl ResolvedTarget {
    /// Did resolution complete? `false` means the gate does not know what path
    /// this is, which is a different situation from knowing it is dangerous.
    pub fn is_unresolved(&self) -> bool {
        self.resolved.is_none()
    }

    pub fn has(&self, s: SensitiveShape) -> bool {
        self.shapes.contains(&s)
    }

    /// The reading a human should be shown. The resolved path when it differs
    /// meaningfully from what was typed, otherwise what was typed — the same
    /// judgement `delete.rs` makes when it decides whether to print an
    /// "as written" line.
    pub fn display(&self) -> String {
        match &self.resolved {
            Some(p) => p.display().to_string(),
            None => self.as_written.clone(),
        }
    }
}

/// Resolve one target against the command's cwd and the project root.
///
/// `root` is the project directory, used only to answer the outside-root
/// question. Pass `cwd` for both when there is no distinct root to speak of.
pub fn target(raw: &str, cwd: &Path, root: &Path) -> ResolvedTarget {
    let as_written = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    let mut shapes = Vec::new();

    if has_unexpanded_var(&as_written) {
        shapes.push(SensitiveShape::UnexpandedVar);
        // Resolution stops here deliberately. `delete::resolve_path_in` would
        // happily join `$HOME/.ssh` onto the cwd and produce a real-looking
        // path that points nowhere true. A confident wrong answer is worse
        // than an admitted unknown in a tool that reports blast radius.
        return ResolvedTarget {
            as_written,
            resolved: None,
            shapes,
        };
    }

    let resolved = delete::resolve_path_in(&as_written, cwd);

    if !delete::is_inside(&resolved, root) {
        shapes.push(SensitiveShape::OutsideRoot);
    }
    if delete::is_user_profile(&resolved) {
        shapes.push(SensitiveShape::UnderUserProfile);
    }
    if crate::protect::classify(&cwd.display().to_string(), &resolved.display().to_string())
        .is_some()
    {
        shapes.push(SensitiveShape::ProtectedName);
    }

    ResolvedTarget {
        as_written,
        resolved: Some(resolved),
        shapes,
    }
}

/// Does this target's path depend on a shell variable?
///
/// `$(` is deliberately NOT counted: that is command substitution, fenced
/// upstream by `shell::has_substitution`, and counting it here would report
/// the same fact twice under a name that does not fit it.
fn has_unexpanded_var(s: &str) -> bool {
    let b: Vec<char> = s.chars().collect();
    for i in 0..b.len() {
        if b[i] == '$' {
            match b.get(i + 1) {
                // `$(` is substitution, not a variable.
                Some('(') => continue,
                Some(c) if c.is_ascii_alphanumeric() || *c == '_' || *c == '{' => return true,
                _ => {}
            }
        }
        // `%VAR%` — Windows. Needs a closing `%` with at least one name
        // character between, so a lone `%` (legal in a filename) does not count.
        if b[i] == '%' {
            if let Some(rest) = b.get(i + 1..) {
                for (n, c) in rest.iter().enumerate() {
                    if *c == '%' && n > 0 {
                        return true;
                    }
                    if !(c.is_ascii_alphanumeric() || *c == '_') {
                        break;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempTree;

    #[test]
    fn a_plain_relative_target_resolves_against_the_given_cwd_and_is_ordinary() {
        let t = TempTree::new("resolve-plain");
        let root = t.path();
        let r = target("./dist", root, root);
        assert_eq!(r.as_written, "./dist");
        assert_eq!(r.resolved, Some(root.join("dist")));
        assert!(!r.is_unresolved());
        assert!(r.shapes.is_empty(), "ordinary work carries no shapes");
    }

    #[test]
    fn the_two_readings_are_both_kept() {
        let t = TempTree::new("resolve-readings");
        let root = t.path();
        let r = target("./sub/../dist", root, root);
        // as_written survives resolution: a reason line quotes what was typed.
        assert_eq!(r.as_written, "./sub/../dist");
        assert_eq!(r.resolved, Some(root.join("dist")));
    }

    #[test]
    fn an_unexpanded_variable_is_unresolved_rather_than_guessed() {
        let t = TempTree::new("resolve-var");
        let root = t.path();
        for raw in ["$HOME/.ssh", "${HOME}/.ssh", "%USERPROFILE%\\.ssh", "$X"] {
            let r = target(raw, root, root);
            assert!(r.is_unresolved(), "{raw} must not resolve");
            assert!(r.has(SensitiveShape::UnexpandedVar), "{raw}");
            // The gate admits it does not know, rather than inventing a path.
            assert_eq!(r.resolved, None);
            assert_eq!(r.display(), raw);
        }
    }

    #[test]
    fn a_dollar_that_is_not_a_variable_does_not_count() {
        let t = TempTree::new("resolve-dollar");
        let root = t.path();
        // Command substitution is fenced upstream; counting it here would
        // report the same fact twice under the wrong name.
        for raw in ["$(date).log", "cost$.txt", "100%", "50%-done"] {
            let r = target(raw, root, root);
            assert!(
                !r.has(SensitiveShape::UnexpandedVar),
                "{raw} is not a variable reference"
            );
        }
    }

    #[test]
    fn a_target_outside_the_project_carries_that_shape() {
        let t = TempTree::new("resolve-outside");
        let root = t.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        let r = target("../elsewhere", &root, &root);
        assert!(r.has(SensitiveShape::OutsideRoot));
        // Control leg: inside the project, the shape is absent.
        let inside = target("./src", &root, &root);
        assert!(!inside.has(SensitiveShape::OutsideRoot));
    }

    #[test]
    fn the_gates_own_files_are_recognised_through_protect() {
        let t = TempTree::new("resolve-protected");
        let root = t.path();
        let r = target(".termaxa/policy.yaml", root, root);
        assert!(
            r.has(SensitiveShape::ProtectedName),
            "the command path and the write path must agree on what is protected"
        );
        // Control leg: an ordinary project file is not protected.
        let ordinary = target("src/main.rs", root, root);
        assert!(!ordinary.has(SensitiveShape::ProtectedName));
    }

    #[test]
    fn shapes_accumulate_rather_than_shadowing_each_other() {
        let t = TempTree::new("resolve-multi");
        let root = t.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        // A .termaxa path outside the project is BOTH outside and protected;
        // reporting only the first found would lose half the reason.
        let r = target("../other/.termaxa/policy.yaml", &root, &root);
        assert!(r.has(SensitiveShape::OutsideRoot), "{:?}", r.shapes);
        assert!(r.has(SensitiveShape::ProtectedName), "{:?}", r.shapes);
    }

    #[test]
    fn every_shape_has_a_label_that_reads_after_a_target() {
        for s in [
            SensitiveShape::UnexpandedVar,
            SensitiveShape::OutsideRoot,
            SensitiveShape::UnderUserProfile,
            SensitiveShape::ProtectedName,
        ] {
            let l = s.label();
            assert!(!l.is_empty());
            assert!(
                l.chars().next().unwrap().is_lowercase(),
                "{l}: labels continue a sentence, they do not start one"
            );
        }
    }
}
