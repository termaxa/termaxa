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

use crate::delete;
use std::path::PathBuf;

/// Where a command runs, for the purpose of judging its targets.
///
/// Two values, both about the execution context, threaded together because
/// they travel together: passing them as separate arguments through every
/// evaluation call site invites transposing them, and a transposed cwd/root
/// pair fails silently - every target reads as outside the project.
///
/// DELIBERATELY SMALL. No policy state, no decision state, no speculative
/// fields. The resolver consumes this and returns facts; deciding what those
/// facts are worth stays with the policy layer. A context that grew a
/// `Decision` or a rule list would put the two on the same side of the line
/// this module exists to keep.
#[derive(Debug, Clone)]
pub struct EvalContext {
    /// The directory the command runs in - from the hook payload, never the
    /// process cwd (decision #59's sibling: a hook runs wherever the harness
    /// spawned it).
    pub cwd: PathBuf,
    /// The project root, used only to answer the outside-the-project question.
    pub root: PathBuf,
}

impl EvalContext {
    /// Context for a command running at `dir`, with no distinct project root -
    /// the directory is both. Used by surfaces that evaluate without a located
    /// project, and by tests.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        let d: PathBuf = dir.into();
        Self {
            cwd: d.clone(),
            root: d,
        }
    }

    /// Context derived from a located project. `Paths::project_dir` is the
    /// `.termaxa/` directory, so the project root is its parent - computed
    /// here once rather than at each call site, where getting it wrong would
    /// make every target read as outside the project.
    pub fn from_paths(cwd: impl Into<PathBuf>, paths: &crate::paths::Paths) -> Self {
        let root = paths
            .project_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| paths.project_dir.clone());
        Self {
            cwd: cwd.into(),
            root,
        }
    }
}

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

/// How a command uses a path.
///
/// Roadmap 2.1. The role is the extractor's whole job beyond finding the
/// path: `cp normal.txt .env` and `mv .env /tmp/foo` both name `.env`, and
/// only one of them destroys it. Collapsing them into an undifferentiated
/// "target" is what made the first `.env` rule fire on a command's SOURCE.
///
/// THREE roles, not two, because Source means different things across the
/// commands that have one. `cp`'s source is read and survives; `mv`'s source
/// is gone afterwards. A downstream layer reasoning by role alone must be
/// able to tell those apart without re-deriving which command produced them -
/// otherwise the command grammar leaks back into the policy layer, which is
/// what this extractor exists to absorb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetRole {
    /// Read, and still there afterwards. `cp SRC dst`, `dd if=SRC`.
    Source,
    /// Written to, and whatever was there may be gone. `cp src DST`,
    /// `tee DST`, `dd of=DST`, and every truncating redirect.
    Destination,
    /// Destroyed in place. `rm TARGET`, and `mv SRC dst` - a move is a delete
    /// of its source, which is the case that would go missing if `mv` only
    /// reported where the file lands.
    Removed,
}

impl TargetRole {
    /// Does this role mean something existing is at risk? `Source` is the
    /// only one that is not, which is why an extractor that reports every
    /// path-looking argument produces false positives on reads.
    pub fn is_destructive(self) -> bool {
        matches!(self, TargetRole::Destination | TargetRole::Removed)
    }
}

/// One target of a command, in both readings.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedTarget {
    /// How the command uses this path.
    pub role: TargetRole,
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

    /// Used by tests asserting on a specific shape. Production reads the
    /// whole list, because a reason line names every shape a target carries.
    #[cfg(test)]
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

/// Every path a segment touches, with the role the command gives it.
///
/// Roadmap 2.1. Four sources, each parsed by its own grammar rather than by
/// "anything that looks like a path":
///
///   redirects   destination   (the splitter already found them)
///   rm & co.    removed       (`delete::extract_targets`)
///   cp / mv     per grammar   (operands before the destination are sources;
///                              `mv`'s are REMOVED, `cp`'s survive)
///   tee / dd    destination   (every operand; `of=` respectively)
///
/// The grammar matters. `cp a b dir/` has three operands and one
/// destination, so a rule that took "the last path-looking argument and
/// called the rest targets" would report `b` as at risk when it is only
/// read. That is the same mistake as matching a path rule against a
/// command's source, which shipped once already.
pub fn command_targets(segment: &str, ctx: &EvalContext) -> Vec<ResolvedTarget> {
    let mut out: Vec<(String, TargetRole)> = Vec::new();

    // Redirects: the unified scanner already extracted them, with truncation
    // decided there. An append still names a destination - it does not
    // truncate, but the path is still one the command writes.
    for seg in crate::shell::split_segments(segment) {
        for o in &seg.redirects {
            out.push((o.target.clone(), TargetRole::Destination));
        }
    }

    // Deletes: destroyed in place, which is what Removed means.
    for t in crate::delete::extract_targets(segment) {
        out.push((t, TargetRole::Removed));
    }

    // Per-command grammars.
    for seg in crate::shell::split_segments(segment) {
        let tokens = crate::delete::tokenize_public(&seg);
        let Some((head, at)) = crate::delete::resolve_head(&tokens) else {
            continue;
        };
        let args = &tokens[at + 1..];
        match head.as_str() {
            "cp" | "copy" => out.extend(copy_move_targets(args, TargetRole::Source)),
            "mv" | "move" => out.extend(copy_move_targets(args, TargetRole::Removed)),
            "tee" => out.extend(tee_targets(args)),
            "dd" => out.extend(dd_targets(args)),
            _ => {}
        }
    }

    out.sort();
    out.dedup();
    out.into_iter()
        .map(|(raw, role)| target(&raw, role, ctx))
        .collect()
}

/// `cp`/`mv` grammar: operands are sources except the last, which is the
/// destination — unless `-t DIR` / `--target-directory=DIR` names the
/// destination explicitly, in which case EVERY operand is a source.
///
/// `source_role` is what this command does to its sources: `cp` reads them,
/// `mv` removes them. That single parameter is the whole difference between
/// the two grammars, which is why they share an implementation.
///
/// HAND-WALKED value-taking flags (#56). `-t`/`--target-directory` and
/// `-S`/`--suffix` consume the next token; everything else starting with `-`
/// is a boolean. Getting this wrong makes a flag's VALUE read as a path, so
/// the list is short and explicit rather than clever.
fn copy_move_targets(args: &[String], source_role: TargetRole) -> Vec<(String, TargetRole)> {
    let mut operands: Vec<String> = Vec::new();
    let mut explicit_dir: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--target-directory=") {
            explicit_dir = Some(rest.to_string());
        } else if a == "-t" || a == "--target-directory" {
            explicit_dir = args.get(i + 1).cloned();
            i += 1;
        } else if a == "-S" || a == "--suffix" {
            i += 1; // consumes its value, which is not a path
        } else if a.starts_with('-') && a.len() > 1 {
            // boolean flag
        } else {
            operands.push(a.clone());
        }
        i += 1;
    }

    let mut out = Vec::new();
    match explicit_dir {
        // -t DIR: the destination is named, so every operand is a source.
        Some(dir) => {
            out.push((dir, TargetRole::Destination));
            out.extend(operands.into_iter().map(|o| (o, source_role)));
        }
        None => {
            // Fewer than two operands names no destination: `cp x` is an
            // error, and reporting `x` as a destination would be a guess.
            if operands.len() >= 2 {
                let dest = operands.pop().expect("len >= 2");
                out.push((dest, TargetRole::Destination));
                out.extend(operands.into_iter().map(|o| (o, source_role)));
            }
        }
    }
    out
}

/// `tee` grammar: every operand is a file it writes. `-a` appends rather than
/// truncating, which changes how much is destroyed but not that the path is a
/// destination — the same call the redirect scanner makes for `>>`.
fn tee_targets(args: &[String]) -> Vec<(String, TargetRole)> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .map(|a| (a.clone(), TargetRole::Destination))
        .collect()
}

/// `dd` grammar: `key=value` operands, so the roles are named rather than
/// positional. `of=` is written, `if=` is read. Everything else (`bs=`,
/// `count=`, `status=`) is not a path.
fn dd_targets(args: &[String]) -> Vec<(String, TargetRole)> {
    let mut out = Vec::new();
    for a in args {
        if let Some(v) = a.strip_prefix("of=") {
            out.push((v.to_string(), TargetRole::Destination));
        } else if let Some(v) = a.strip_prefix("if=") {
            out.push((v.to_string(), TargetRole::Source));
        }
    }
    out
}

/// Resolve one target against the command's cwd and the project root.
///
/// `root` is the project directory, used only to answer the outside-root
/// question. Pass `cwd` for both when there is no distinct root to speak of.
pub fn target(raw: &str, role: TargetRole, ctx: &EvalContext) -> ResolvedTarget {
    let as_written = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    let mut shapes = Vec::new();

    if has_unexpanded_var(&as_written) {
        shapes.push(SensitiveShape::UnexpandedVar);
        // Resolution stops here deliberately. `delete::resolve_path_in` would
        // happily join `$HOME/.ssh` onto the cwd and produce a real-looking
        // path that points nowhere true. A confident wrong answer is worse
        // than an admitted unknown in a tool that reports blast radius.
        return ResolvedTarget {
            role,
            as_written,
            resolved: None,
            shapes,
        };
    }

    let resolved = delete::resolve_path_in(&as_written, &ctx.cwd);

    if !delete::is_inside(&resolved, &ctx.root) {
        shapes.push(SensitiveShape::OutsideRoot);
    }
    if delete::is_user_profile(&resolved) {
        shapes.push(SensitiveShape::UnderUserProfile);
    }
    if crate::protect::classify(
        &ctx.cwd.display().to_string(),
        &resolved.display().to_string(),
    )
    .is_some()
    {
        shapes.push(SensitiveShape::ProtectedName);
    }

    ResolvedTarget {
        role,
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

    fn roles(cmd: &str) -> Vec<(String, TargetRole)> {
        let ctx = EvalContext::at(std::path::Path::new("/tmp/proj"));
        let mut v: Vec<(String, TargetRole)> = command_targets(cmd, &ctx)
            .into_iter()
            .map(|t| (t.as_written, t.role))
            .collect();
        v.sort();
        v
    }

    /// Roadmap 2.1. The role is the point: `cp` reads its sources and `mv`
    /// destroys them, and a layer downstream must be able to tell those apart
    /// without knowing which command produced the list.
    #[test]
    fn cp_reads_its_sources_and_mv_removes_them() {
        assert_eq!(
            roles("cp normal.txt .env"),
            vec![
                (".env".into(), TargetRole::Destination),
                ("normal.txt".into(), TargetRole::Source),
            ],
            "a copy's source survives - it must not read as at-risk"
        );
        assert_eq!(
            roles("mv .env /tmp/foo"),
            vec![
                (".env".into(), TargetRole::Removed),
                ("/tmp/foo".into(), TargetRole::Destination),
            ],
            "a move destroys its source, which is the case that goes missing \
             if only the destination is reported"
        );
    }

    /// The grammar is parsed, not guessed. `cp a b c dir/` has three sources
    /// and one destination; taking "the last path-looking argument and
    /// calling the rest targets" would report `b` as at risk when it is only
    /// read - the same mistake as matching a path rule against a source.
    #[test]
    fn the_final_operand_is_the_destination_and_the_rest_are_not() {
        assert_eq!(
            roles("cp a b c dir/"),
            vec![
                ("a".into(), TargetRole::Source),
                ("b".into(), TargetRole::Source),
                ("c".into(), TargetRole::Source),
                ("dir/".into(), TargetRole::Destination),
            ]
        );
        assert_eq!(
            roles("mv a b c dir/"),
            vec![
                ("a".into(), TargetRole::Removed),
                ("b".into(), TargetRole::Removed),
                ("c".into(), TargetRole::Removed),
                ("dir/".into(), TargetRole::Destination),
            ]
        );
        // One operand names no destination. `cp x` is an error; reporting `x`
        // as a destination would be inventing a fact.
        assert!(roles("cp x").is_empty());
    }

    /// `-t DIR` names the destination, so EVERY operand is a source. Without
    /// this the last operand would be taken as the destination and the real
    /// one missed entirely - and with a single operand (`mv -t dir/ .env`)
    /// the whole command would report nothing.
    #[test]
    fn an_explicit_target_directory_inverts_the_grammar() {
        assert_eq!(
            roles("cp -t dir/ a b"),
            vec![
                ("a".into(), TargetRole::Source),
                ("b".into(), TargetRole::Source),
                ("dir/".into(), TargetRole::Destination),
            ]
        );
        assert_eq!(
            roles("cp --target-directory=dir/ a b"),
            vec![
                ("a".into(), TargetRole::Source),
                ("b".into(), TargetRole::Source),
                ("dir/".into(), TargetRole::Destination),
            ]
        );
        assert_eq!(
            roles("mv -t dir/ .env"),
            vec![
                (".env".into(), TargetRole::Removed),
                ("dir/".into(), TargetRole::Destination),
            ]
        );
        // A value-taking flag's VALUE is not a path.
        assert_eq!(
            roles("cp -S .bak a b"),
            vec![
                ("a".into(), TargetRole::Source),
                ("b".into(), TargetRole::Destination),
            ],
            "-S consumes .bak, which must not read as an operand"
        );
    }

    /// `tee` writes every operand; `dd` names its roles rather than
    /// positioning them.
    #[test]
    fn tee_writes_every_operand_and_dd_names_its_roles() {
        assert_eq!(
            roles("tee a.log b.log"),
            vec![
                ("a.log".into(), TargetRole::Destination),
                ("b.log".into(), TargetRole::Destination),
            ]
        );
        // -a appends rather than truncating, but the path is still written.
        assert_eq!(
            roles("tee -a log.txt"),
            vec![("log.txt".into(), TargetRole::Destination)]
        );
        assert_eq!(
            roles("dd if=/dev/zero of=.env"),
            vec![
                (".env".into(), TargetRole::Destination),
                ("/dev/zero".into(), TargetRole::Source),
            ]
        );
        // Non-path operands are not paths.
        assert_eq!(
            roles("dd of=x bs=1M count=10"),
            vec![("x".into(), TargetRole::Destination)]
        );
    }

    /// Redirects and deletes keep answering, and now answer in the same
    /// vocabulary: a delete REMOVES, a redirect writes a DESTINATION.
    #[test]
    fn redirects_and_deletes_speak_the_same_vocabulary() {
        assert_eq!(
            roles("cat /dev/null > out.txt"),
            vec![("out.txt".into(), TargetRole::Destination)]
        );
        assert_eq!(
            roles("rm -rf ./dist"),
            vec![("./dist".into(), TargetRole::Removed)]
        );
    }

    #[test]
    fn a_plain_relative_target_resolves_against_the_given_cwd_and_is_ordinary() {
        let t = TempTree::new("resolve-plain");
        let root = t.path();
        let r = target("./dist", TargetRole::Destination, &EvalContext::at(root));
        assert_eq!(r.as_written, "./dist");
        assert_eq!(r.resolved, Some(root.join("dist")));
        assert!(!r.is_unresolved());
        assert!(r.shapes.is_empty(), "ordinary work carries no shapes");
    }

    #[test]
    fn the_two_readings_are_both_kept() {
        let t = TempTree::new("resolve-readings");
        let root = t.path();
        let r = target(
            "./sub/../dist",
            TargetRole::Destination,
            &EvalContext::at(root),
        );
        // as_written survives resolution: a reason line quotes what was typed.
        assert_eq!(r.as_written, "./sub/../dist");
        assert_eq!(r.resolved, Some(root.join("dist")));
    }

    #[test]
    fn an_unexpanded_variable_is_unresolved_rather_than_guessed() {
        let t = TempTree::new("resolve-var");
        let root = t.path();
        for raw in ["$HOME/.ssh", "${HOME}/.ssh", "%USERPROFILE%\\.ssh", "$X"] {
            let r = target(raw, TargetRole::Destination, &EvalContext::at(root));
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
            let r = target(raw, TargetRole::Destination, &EvalContext::at(root));
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
        let r = target(
            "../elsewhere",
            TargetRole::Destination,
            &EvalContext::at(&root),
        );
        assert!(r.has(SensitiveShape::OutsideRoot));
        // Control leg: inside the project, the shape is absent.
        let inside = target("./src", TargetRole::Destination, &EvalContext::at(&root));
        assert!(!inside.has(SensitiveShape::OutsideRoot));
    }

    #[test]
    fn the_gates_own_files_are_recognised_through_protect() {
        let t = TempTree::new("resolve-protected");
        let root = t.path();
        let r = target(
            ".termaxa/policy.yaml",
            TargetRole::Destination,
            &EvalContext::at(root),
        );
        assert!(
            r.has(SensitiveShape::ProtectedName),
            "the command path and the write path must agree on what is protected"
        );
        // Control leg: an ordinary project file is not protected.
        let ordinary = target(
            "src/main.rs",
            TargetRole::Destination,
            &EvalContext::at(root),
        );
        assert!(!ordinary.has(SensitiveShape::ProtectedName));
    }

    #[test]
    fn shapes_accumulate_rather_than_shadowing_each_other() {
        let t = TempTree::new("resolve-multi");
        let root = t.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        // A .termaxa path outside the project is BOTH outside and protected;
        // reporting only the first found would lose half the reason.
        let r = target(
            "../other/.termaxa/policy.yaml",
            TargetRole::Destination,
            &EvalContext::at(&root),
        );
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
