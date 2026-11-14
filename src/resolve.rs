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
    /// False when `cwd` is only where the line started and a `cd` before
    /// this segment moved the shell somewhere the gate cannot read
    /// (`cd "$X"`, `cd -`): a relative target then resolves to nothing the
    /// gate can know, and is reported as such.
    pub cwd_known: bool,
    /// When `cwd_known` is false: what is known of the end of the
    /// directory, as path components. `cd "$(git rev-parse
    /// --show-toplevel)/.claude"` leaves the shell somewhere ending in
    /// `.claude`; `cd "$X"` somewhere nothing is known of (empty). A
    /// relative target after either has a known end, this and then its own
    /// path, which a path rule matching at any depth can name.
    pub cwd_end: Vec<String>,
}

impl EvalContext {
    /// Context from an explicit cwd and root, for callers that have both but
    /// no `Paths` - the preview layer receives them separately.
    pub fn new_for_preview(cwd: impl Into<PathBuf>, root: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            root: root.into(),
            cwd_known: true,
            cwd_end: Vec::new(),
        }
    }

    /// Context for a command running at `dir`, with no distinct project root -
    /// the directory is both. Used by surfaces that evaluate without a located
    /// project, and by tests.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        let d: PathBuf = dir.into();
        Self {
            cwd: d.clone(),
            root: d,
            cwd_known: true,
            cwd_end: Vec::new(),
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
            cwd_known: true,
            cwd_end: Vec::new(),
        }
    }

    /// This context moved to `dir`, or, when the directory is not known,
    /// marked unknown with whatever is known of its end (`end`; `None` when
    /// the segment's own reading had the directory known, which a `cd`
    /// that failed to resolve can still leave unknown).
    fn in_dir(&self, dir: Option<PathBuf>, end: Option<Vec<String>>) -> Self {
        match dir {
            Some(d) if self.cwd_known => Self {
                cwd: d,
                root: self.root.clone(),
                cwd_known: true,
                cwd_end: Vec::new(),
            },
            _ => Self {
                cwd: self.cwd.clone(),
                root: self.root.clone(),
                cwd_known: false,
                cwd_end: end.unwrap_or_default(),
            },
        }
    }

    /// The context one segment of a command line runs in: where every `cd`
    /// before it on the line left the shell (`Segment::run_dir`). A redirect
    /// target resolves here.
    pub fn for_segment(&self, seg: &crate::shell::Segment) -> Self {
        self.in_dir(seg.run_dir(&self.cwd), seg.run_dir_end(self.start_end()))
    }

    /// Where a segment's own operands resolve: `for_segment`, then git's
    /// `-C` for a git command (`delete::operand_base`).
    pub fn for_operands(&self, seg: &crate::shell::Segment) -> Self {
        self.in_dir(
            delete::operand_base(seg, &self.cwd),
            delete::operand_end(seg, self.start_end()),
        )
    }

    /// What `Segment::run_dir_end` wants to know of this context: `None`
    /// when the directory is known, otherwise what is known of its end.
    fn start_end(&self) -> Option<&[String]> {
        if self.cwd_known {
            None
        } else {
            Some(&self.cwd_end)
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
    /// A relative path after a `cd` the gate cannot follow (`cd "$X" &&
    /// rm -r build`). Like a variable, it makes the target unresolvable:
    /// the directory it is relative to is not known until the shell runs.
    UnknownDirectory,
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
            SensitiveShape::UnknownDirectory => {
                "is relative to a directory an earlier `cd` moved to, which the gate cannot read"
            }
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
    /// Put back as git has it committed, by a discard that names no file:
    /// `git reset --hard`, `git checkout -- .`. What the file held since its
    /// last commit is gone (`command_contents`).
    Reverted,
    /// Taken out of the tree into a stash: `git stash`, and with `-u` the
    /// untracked files too. A stash keeps what it takes, so this is not a
    /// loss, and a rule that guards a file's contents has nothing to say.
    /// What a stash cannot keep is the gate being hooked: the tree it leaves
    /// has the hook config as committed and no untracked policy. So only a
    /// rule on the floor is asked about a stashed file (`path_rule_for`).
    Stashed,
}

impl TargetRole {
    /// Does this role mean something existing is at risk? `Source` is the
    /// only one that is not, which is why an extractor that reports every
    /// path-looking argument produces false positives on reads.
    /// What this command does to the path, phrased to sit inside a reason
    /// line: "target `x` (removed) — ...". Only destructive roles ever reach
    /// a reason line, so Source has no natural phrasing here and says what it
    /// is rather than inventing one.
    pub fn effect(self) -> &'static str {
        match self {
            TargetRole::Source => "read",
            TargetRole::Destination => "written",
            TargetRole::Removed => "removed",
            TargetRole::Reverted => "put back as committed",
            TargetRole::Stashed => "taken into a stash",
        }
    }

    pub fn is_destructive(self) -> bool {
        matches!(
            self,
            TargetRole::Destination
                | TargetRole::Removed
                | TargetRole::Reverted
                | TargetRole::Stashed
        )
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
    /// When `resolved` is `None` because the directory is unknown: the end
    /// of the path, what is known of the directory's end
    /// (`EvalContext::cwd_end`) and then the target's own path.
    /// `settings.json` after `cd "$(git rev-parse --show-toplevel)/.claude"`
    /// ends in `.claude/settings.json`; `.claude/settings.json` after `cd
    /// "$X"` ends in the same; a path rule matching at any depth can name
    /// either. Empty only when `..` climbed out of everything known.
    pub end: Option<Vec<String>>,
    /// Everything notable about this target, in a stable order.
    pub shapes: Vec<SensitiveShape>,
    /// The command only ADDS to this file: a `>>`, or `tee -a`, and nothing
    /// else on the line writes it. It is still a destination, and a path
    /// rule still judges the write; but what the file holds stays, so there
    /// is nothing to lose, nothing to copy first and nothing for the preview
    /// to report. Until v0.21.10 the preview read an append as an overwrite
    /// with no way back ("loses 6 B of existing content", "NOT
    /// recoverable"), which made an ask on such a line a refusal and held
    /// `echo KEY=2 >> .env` in observe mode, where the truncating spelling
    /// runs after its copy (measured Nov 13, 2026).
    pub appends: bool,
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
        match (&self.resolved, &self.end) {
            (Some(p), _) => p.display().to_string(),
            // A variable in the target: what was typed says where it goes
            // better than its end does.
            (None, _) if self.shapes.contains(&SensitiveShape::UnexpandedVar) => {
                self.as_written.clone()
            }
            // The directory's start is not known; the path's end is, and
            // is what a rule named.
            (None, Some(end)) => format!("…/{}", end.join("/")),
            (None, None) => self.as_written.clone(),
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
    // Each segment resolves where it runs: a redirect where every `cd`
    // before it left the shell, the command's own operands there too, and
    // a git command's after its `-C`. Read against the line's first
    // directory, `cd .termaxa && echo x > policy.yaml` was a write to
    // `./policy.yaml` that no path rule named, and was allowed.
    // (as written, role, which segment, operand or redirect, only appended
    // to). Sorted on the first two as before, so a reason names the same
    // target it always did.
    let mut out: Vec<(String, TargetRole, usize, bool, bool)> = Vec::new();
    let mut contexts: Vec<(EvalContext, EvalContext)> = Vec::new();
    for seg in crate::shell::split_segments_deep(segment) {
        let k = contexts.len();
        contexts.push((ctx.for_segment(&seg), ctx.for_operands(&seg)));
        let mut add = |raw: String, role: TargetRole, operand: bool, appends: bool| {
            out.push((raw, role, k, operand, appends));
        };

        // Redirects: the unified scanner already extracted them, with
        // truncation decided there. An append still names a destination -
        // it does not truncate, but the path is still one the command
        // writes.
        for o in &seg.redirects {
            add(
                o.target.clone(),
                TargetRole::Destination,
                false,
                !o.truncates,
            );
        }

        // Deletes: destroyed in place, which is what Removed means.
        for t in crate::delete::segment_targets(&seg) {
            add(t.text, TargetRole::Removed, true, false);
        }

        // Per-command grammars, over the segment's own words: a redirect's
        // target is a Destination above, not an operand here (#61).
        let tokens = crate::delete::tokenize_public(seg.command());
        let Some((head, at)) = crate::delete::resolve_head(&tokens) else {
            continue;
        };
        let args = &tokens[at + 1..];
        let grammar: Vec<(String, TargetRole)> = match head.as_str() {
            "cp" | "copy" => copy_move_targets(&head, args, TargetRole::Source),
            "mv" | "move" => copy_move_targets(&head, args, TargetRole::Removed),
            "tee" => tee_targets(args),
            "dd" => dd_targets(args),
            _ => Vec::new(),
        };
        // `tee -a` adds to its files, as `>>` does.
        let adds = head == "tee" && tee_appends(args);
        for (raw, role) in grammar {
            add(raw, role, true, adds);
        }
        for p in option_write_targets(&head, args) {
            add(p, TargetRole::Destination, true, false);
        }
    }

    out.sort();
    out.dedup();
    // The same path named by two segments, or as an operand and a
    // redirect, is one target: the dedup above saw two keys. It is only
    // appended to if every write of it appends (`echo a >> f; echo b > f`
    // loses what `f` held).
    let mut resolved: Vec<ResolvedTarget> = Vec::new();
    for (raw, role, k, operand, appends) in out {
        let (shell, operands) = &contexts[k];
        let mut t = target(&raw, role, if operand { operands } else { shell });
        t.appends = appends;
        match resolved
            .iter_mut()
            .find(|m| m.role == t.role && m.as_written == t.as_written && m.resolved == t.resolved)
        {
            Some(m) => m.appends &= t.appends,
            None => resolved.push(t),
        }
    }
    resolved
}

/// What a command changes INSIDE a directory it names, as targets of their
/// own: the files a `cp` or a `mv` lands in a directory, and the files a
/// delete or a move takes with one.
///
/// A path rule names a file, and until v0.21.10 it saw that file only when
/// the command named it too. `cp x/settings.json .claude/` writes
/// `.claude/settings.json` and reported one destination, the directory; `rm
/// -rf .claude` removes it and reported one removal, the directory. So the
/// spelling that leaves the file name out was an ask where the spelling with
/// it is a deny, it ran in observe mode, where that rule is on the floor,
/// and the copy was allowed outright under a policy that allows `cp *`
/// (found Nov 14, 2026, reading the code for another change). A copied tree
/// is the same write many times over: `cp -r template/. .` lands the
/// template's `.claude/settings.json` on the project's.
///
/// Two readings, and they differ in how far they go:
///
/// - **A file into a directory** is exact: the name that lands is the
///   source's own, wherever the directory is. `cp a b dir/` lands `dir/a`
///   and `dir/b`; a glob is what it matches on disk; a name held in a
///   variable is not known and is left out.
/// - **A tree** is read off the disk (`delete::files_under`, under the
///   delete preview's budget), and only for what it changes in the project
///   and in the agent configuration under the user's home. A tree copied or
///   deleted anywhere else holds `.claude/settings.json` files too, every
///   checkout does, and those are not this session's: `cp -r . /tmp/backup`
///   and `rm -rf ../old-worktree` are judged as before.
///
/// And a third, for git, which changes files by asking git what it would
/// do (`undone_by_git`): the tracked files whose uncommitted changes a
/// discard or a stash puts back as committed, and the untracked files a
/// clean or a stash takes away. In the state `termaxa init` leaves, the hook
/// registration is an uncommitted change to `.claude/settings.json` and the
/// policy an untracked directory, so `git stash` unhooked the gate and `git
/// clean -fd` deleted its policy, each an ask that ran in observe mode
/// (found the same day, on the fixtures of the first measurement).
///
/// Not in `command_targets`: only the path rules read these, so the
/// preview, the copy aside and the classifier see the command as they did.
pub fn command_contents(segment: &str, ctx: &EvalContext) -> Vec<ResolvedTarget> {
    let mut out: Vec<ResolvedTarget> = Vec::new();
    let mut budget = delete::WalkBudget::new();
    for seg in crate::shell::split_segments_deep(segment) {
        let ctx = ctx.for_operands(&seg);
        for t in delete::segment_targets(&seg) {
            removed_with(&t.text, &ctx, &mut budget, &mut out);
        }
        let tokens = brace_expanded(delete::tokenize_public(seg.command()));
        let Some((head, at)) = delete::resolve_head(&tokens) else {
            continue;
        };
        // The commands that copy or move: `cp` and `mv` and their cmd
        // names, PowerShell's by their own parameter names (`cp` and `mv`
        // are its aliases too, and are read that way when a word of the
        // line is one of its parameters), a rename, and `git mv`, which is
        // a move.
        let rest = &tokens[at + 1..];
        let (source_role, args): (TargetRole, Vec<String>) = match head.as_str() {
            "rename-item" | "rni" | "ren" => {
                renamed(rest, &ctx, &mut budget, &mut out);
                continue;
            }
            "cp" | "copy" if says_powershell(rest) => {
                (TargetRole::Source, powershell_operands(rest))
            }
            "mv" | "move" if says_powershell(rest) => {
                (TargetRole::Removed, powershell_operands(rest))
            }
            "cp" | "copy" => (TargetRole::Source, rest.to_vec()),
            "mv" | "move" => (TargetRole::Removed, rest.to_vec()),
            "copy-item" | "cpi" => (TargetRole::Source, powershell_operands(rest)),
            "move-item" | "mi" => (TargetRole::Removed, powershell_operands(rest)),
            "git" => {
                let full = tokens[at..].to_vec();
                let g = delete::git_without_global_options(&full).unwrap_or(full);
                if g.get(1).is_some_and(|sub| sub.eq_ignore_ascii_case("mv")) {
                    (TargetRole::Removed, g[2..].to_vec())
                } else {
                    undone_by_git(&tokens[at..], &ctx, &mut budget, &mut out);
                    continue;
                }
            }
            _ => continue,
        };
        let head = match source_role {
            TargetRole::Removed => "mv",
            _ => "cp",
        };
        let args = &args[..];
        let grammar = copy_move_targets(head, args, source_role);
        let Some(dest) = grammar
            .iter()
            .find(|(_, role)| *role == TargetRole::Destination)
            .map(|(d, _)| unquoted(d))
        else {
            continue;
        };
        let sources: Vec<String> = grammar
            .iter()
            .filter(|(_, role)| *role != TargetRole::Destination)
            .map(|(s, _)| unquoted(s))
            .collect();
        if source_role == TargetRole::Removed {
            for s in &sources {
                removed_with(s, &ctx, &mut budget, &mut out);
            }
        }
        landed(
            args,
            source_role,
            &dest,
            &sources,
            &ctx,
            &mut budget,
            &mut out,
        );
    }
    out
}

fn unquoted(s: &str) -> String {
    s.trim().trim_matches('"').trim_matches('\'').to_string()
}

/// `mv .claude{,.bak}` is `mv .claude .claude.bak`: one brace list in a
/// word, the simple form, opened the way the shell opens it. A nested list,
/// a range (`{1..3}`) and a variable (`${X}`) are left as written, and a
/// name the reading cannot open is one it does not know.
fn brace_expanded(tokens: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(tokens.len());
    for t in tokens {
        match (t.find('{'), t.rfind('}')) {
            (Some(a), Some(b))
                if a < b
                    && t[a + 1..b].contains(',')
                    && !t[a + 1..b].contains('{')
                    && !t[..a].ends_with('$') =>
            {
                for part in t[a + 1..b].split(',') {
                    out.push(format!("{}{}{}", &t[..a], part, &t[b + 1..]));
                }
            }
            _ => out.push(t),
        }
    }
    out
}

/// A glob with a bracket in it, as one this reading can expand: each `[…]`
/// becomes `?`, which matches whatever the bracket would and more. `cp -r
/// template/.[!.]* .` is how dot-named entries are copied, and what it is
/// read as landing may be more than it lands, never less.
fn without_brackets(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(a) = rest.find('[') {
        match rest[a..].find(']') {
            Some(b) if b > 1 => {
                out.push_str(&rest[..a]);
                out.push('?');
                rest = &rest[a + b + 1..];
            }
            _ => break,
        }
    }
    out.push_str(rest);
    out
}

/// What a parameter of `Copy-Item`, `Move-Item` or `Rename-Item` is to this
/// reading.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PsParameter {
    /// `-Path`, `-LiteralPath`: what is copied, moved or renamed.
    Source,
    /// `-Destination`, and `-NewName` for a rename.
    Destination,
    /// `-Recurse`: a directory goes with what it holds.
    Recurse,
    /// Takes a value, and the value is not a path this reading uses.
    Value,
    /// Takes nothing.
    Switch,
}

/// The parameters of `Copy-Item`, `Move-Item` and `Rename-Item`, with the
/// common parameters every cmdlet takes.
///
/// HAND-WALKED (#56): the list sizes a decision. A parameter read as a
/// switch when it takes a value leaves that value standing as a path, and
/// `Copy-Item x .claude\ -ErrorAction SilentlyContinue` would be read as a
/// copy into `SilentlyContinue`. PowerShell accepts any prefix that names
/// one parameter (`-Dest`, `-Rec`), so the switches are listed as well: a
/// prefix is resolved against all of them, as PowerShell resolves it.
const POWERSHELL_PARAMETERS: [(&str, PsParameter); 29] = [
    ("path", PsParameter::Source),
    ("literalpath", PsParameter::Source),
    ("destination", PsParameter::Destination),
    ("newname", PsParameter::Destination),
    ("recurse", PsParameter::Recurse),
    ("filter", PsParameter::Value),
    ("include", PsParameter::Value),
    ("exclude", PsParameter::Value),
    ("credential", PsParameter::Value),
    ("fromsession", PsParameter::Value),
    ("tosession", PsParameter::Value),
    ("erroraction", PsParameter::Value),
    ("warningaction", PsParameter::Value),
    ("informationaction", PsParameter::Value),
    ("progressaction", PsParameter::Value),
    ("errorvariable", PsParameter::Value),
    ("warningvariable", PsParameter::Value),
    ("informationvariable", PsParameter::Value),
    ("outvariable", PsParameter::Value),
    ("outbuffer", PsParameter::Value),
    ("pipelinevariable", PsParameter::Value),
    ("container", PsParameter::Switch),
    ("force", PsParameter::Switch),
    ("passthru", PsParameter::Switch),
    ("whatif", PsParameter::Switch),
    ("confirm", PsParameter::Switch),
    ("verbose", PsParameter::Switch),
    ("debug", PsParameter::Switch),
    ("usetransaction", PsParameter::Switch),
];

/// The short names PowerShell gives some of them.
const POWERSHELL_ALIASES: [(&str, &str); 17] = [
    ("pspath", "literalpath"),
    ("lp", "literalpath"),
    ("ea", "erroraction"),
    ("wa", "warningaction"),
    ("infa", "informationaction"),
    ("proga", "progressaction"),
    ("ev", "errorvariable"),
    ("wv", "warningvariable"),
    ("iv", "informationvariable"),
    ("ov", "outvariable"),
    ("ob", "outbuffer"),
    ("pv", "pipelinevariable"),
    ("vb", "verbose"),
    ("db", "debug"),
    ("wi", "whatif"),
    ("cf", "confirm"),
    ("usetx", "usetransaction"),
];

/// Which parameter `-Word` names: its full name, an alias, or a prefix only
/// one parameter starts with. A prefix two parameters share names neither,
/// and PowerShell refuses the command.
fn powershell_parameter(word: &str) -> Option<PsParameter> {
    let name = word.strip_prefix('-')?.to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    let name = POWERSHELL_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .map_or(name.as_str(), |(_, full)| *full);
    if let Some((_, kind)) = POWERSHELL_PARAMETERS.iter().find(|(n, _)| *n == name) {
        return Some(*kind);
    }
    let mut starting = POWERSHELL_PARAMETERS
        .iter()
        .filter(|(n, _)| n.starts_with(name));
    match (starting.next(), starting.next()) {
        (Some((_, kind)), None) => Some(*kind),
        _ => None,
    }
}

/// Is a word of these arguments one of PowerShell's parameters, by its full
/// name? `cp` and `mv` are aliases there, and `cp x y -Recurse -Force` is
/// `Copy-Item`. A full name is never a cluster of `cp`'s own switches.
fn says_powershell(args: &[String]) -> bool {
    args.iter().any(|a| {
        let word = a.split(':').next().unwrap_or(a);
        word.len() > 3
            && word.starts_with('-')
            && POWERSHELL_PARAMETERS
                .iter()
                .any(|(n, _)| word[1..].eq_ignore_ascii_case(n))
    })
}

/// What a PowerShell copy, move or rename names: whether it recurses, its
/// sources, and its destination when the line gives one.
///
/// `-Destination X` (or `-Destination:X`) names the destination wherever it
/// stands; `-Path` and `-LiteralPath` name the sources; a comma makes a
/// list of them, with or without a space after it. Words with no parameter
/// in front bind in PowerShell's order: the sources first, unless they
/// were named, then the destination.
fn powershell_words(args: &[String]) -> (bool, Vec<String>, Option<String>) {
    let list = |v: &str| -> Vec<String> {
        v.split(',')
            .map(unquoted)
            .filter(|p| !p.is_empty())
            .collect()
    };
    let mut recurse = false;
    let mut named_sources: Option<Vec<String>> = None;
    let mut named_dest: Option<String> = None;
    // Each positional argument, a comma list being one argument.
    let mut positional: Vec<Vec<String>> = Vec::new();
    let mut list_open = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if !a.starts_with('-') || a.len() < 2 {
            let continues = list_open || a.starts_with(',');
            list_open = a.ends_with(',');
            match positional.last_mut() {
                Some(last) if continues => last.extend(list(a)),
                _ => positional.push(list(a)),
            }
            continue;
        }
        list_open = false;
        let (word, inline) = match a.split_once(':') {
            Some((w, v)) => (w, Some(v.to_string())),
            None => (a.as_str(), None),
        };
        let kind = powershell_parameter(word);
        let value = match kind {
            Some(PsParameter::Source | PsParameter::Destination | PsParameter::Value) => {
                inline.or_else(|| {
                    let mut v = args.get(i).cloned();
                    i += 1;
                    // A list after the parameter: `-Path a, b`.
                    while v.as_ref().is_some_and(|x| x.ends_with(','))
                        || args.get(i).is_some_and(|x| x.starts_with(','))
                    {
                        match (v.as_mut(), args.get(i)) {
                            (Some(x), Some(more)) => x.push_str(more),
                            _ => break,
                        }
                        i += 1;
                    }
                    v
                })
            }
            _ => None,
        };
        match kind {
            Some(PsParameter::Source) => {
                named_sources
                    .get_or_insert_with(Vec::new)
                    .extend(value.as_deref().map(list).unwrap_or_default());
            }
            Some(PsParameter::Destination) => {
                named_dest = value.as_deref().and_then(|v| list(v).into_iter().next());
            }
            Some(PsParameter::Recurse) => recurse = true,
            _ => {}
        }
    }
    let mut positional = positional.into_iter();
    let sources = named_sources.unwrap_or_else(|| positional.next().unwrap_or_default());
    let dest = named_dest.or_else(|| positional.next().and_then(|d| d.into_iter().next()));
    (recurse, sources, dest)
}

/// `Copy-Item` and `Move-Item`, as `cp` would be written: `-r` when it
/// recurses, the sources, then the destination. With no destination
/// PowerShell copies into the directory it is in.
fn powershell_operands(args: &[String]) -> Vec<String> {
    let (recurse, sources, dest) = powershell_words(args);
    let mut out: Vec<String> = Vec::new();
    if recurse {
        out.push("-r".to_string());
    }
    if sources.is_empty() {
        return out;
    }
    out.extend(sources);
    out.push(dest.unwrap_or_else(|| ".".to_string()));
    out
}

/// `Rename-Item a b` and `ren a b`: `a` is gone, with what it holds, and
/// `b` is there instead, beside where `a` was. The new name is a name and
/// not a path, in PowerShell and in cmd alike.
fn renamed(
    args: &[String],
    ctx: &EvalContext,
    budget: &mut delete::WalkBudget,
    out: &mut Vec<ResolvedTarget>,
) {
    let (_, sources, new_name) = powershell_words(args);
    let (Some(source), Some(new_name)) = (sources.first(), new_name) else {
        return;
    };
    let was = source.trim_end_matches(['/', '\\']);
    let beside = match was.rfind(['/', '\\']) {
        Some(0) => joined("/", &new_name),
        Some(i) => joined(&was[..i], &new_name),
        None => new_name,
    };
    removed_with(source, ctx, budget, out);
    // A renamed file is a write of its new name; a renamed directory puts
    // what it held under the new one.
    match on_disk(source, ctx).filter(|p| p.is_dir()) {
        Some(tree) => {
            if not_read(&tree, ctx) {
                return;
            }
            if let Some(place) = on_disk(&beside, ctx) {
                for p in guarded_files(&tree, &place, ctx, budget) {
                    out.push(inside(p, TargetRole::Destination));
                }
            }
        }
        None => out.push(target(&beside, TargetRole::Destination, ctx)),
    }
}

/// What a git command undoes or removes without naming it: the tracked
/// files whose uncommitted changes a discard puts back as committed
/// (`Reverted`), the untracked files a clean deletes (`Removed`), and both
/// kinds as a stash takes them (`Stashed`, which only a rule on the floor
/// is asked about: a stash keeps what it takes).
///
/// Asked of git, in the directory the command runs in: which files have
/// uncommitted changes is `backup::git_discard_losses`, the answer the
/// discard preview and the stash snapshot already take (#37), and which
/// untracked files would go is `git clean -n`, a dry run. Nothing is read
/// when the command points git somewhere else (`--git-dir`, `--work-tree`)
/// or is not in a repository.
///
/// When the directory is not known (`cd "$(git rev-parse --show-toplevel)"
/// && git stash`, how an agent goes to the top of a repository), a command
/// that names no path, or only `.`, is read in the project's own
/// repository, whole: wherever the `cd` went, that is most often where, and
/// a hold too many is the loud side (#44). One that names a path there is
/// not read; the path is relative to a directory nobody knows.
///
/// Which commands:
/// - `git reset --hard`, `git checkout [--] <paths>`, `git restore <paths>`,
///   `git checkout -f`, `git switch --discard-changes`: the scope
///   `backup::git_discard_target` reads.
/// - `git stash`, `git stash push`, `git stash save`: the same files, and
///   with `-u` or `-a` the untracked ones too. `list`, `show`, `pop`,
///   `apply`, `drop` and the rest put nothing back.
/// - `git clean` that is not a dry run: what it would remove.
///
/// Not read: what a command brings in from ANOTHER commit. A branch switch,
/// a merge, a pull, a rebase, a revert, `git reset --hard <commit>` and
/// `git checkout <commit> -- <paths>` write what the repository's history
/// holds, and are read only for the uncommitted changes they discard on the
/// way.
fn undone_by_git(
    tokens: &[String],
    ctx: &EvalContext,
    budget: &mut delete::WalkBudget,
    out: &mut Vec<ResolvedTarget>,
) {
    if tokens
        .iter()
        .any(|t| t.starts_with("--git-dir") || t.starts_with("--work-tree"))
    {
        return;
    }
    let cwd = if ctx.cwd_known {
        ctx.cwd.as_path()
    } else {
        ctx.root.as_path()
    };
    let plain = delete::git_without_global_options(tokens).unwrap_or_else(|| tokens.to_vec());
    let args = plain.get(2..).unwrap_or(&[]);
    let verb = plain.get(1).map(|s| s.to_ascii_lowercase());
    let (scope, untracked) = match verb.as_deref() {
        Some("stash") => match stash_takes(args) {
            Some(taken) => taken,
            None => return,
        },
        Some("clean") => (None, clean_takes(args)),
        _ => (crate::backup::git_discard_target(tokens, cwd), None),
    };
    let (scope, untracked) = if ctx.cwd_known {
        (scope, untracked)
    } else {
        let here = |paths: &[String]| paths.iter().all(|p| p == "." || p == "./");
        (
            match scope {
                Some(crate::backup::Discard::Paths(p)) => {
                    here(&p).then_some(crate::backup::Discard::WholeTree)
                }
                whole => whole,
            },
            untracked.filter(|u| here(&u.paths)).map(|u| Untracked {
                paths: Vec::new(),
                whole_tree: true,
                ..u
            }),
        )
    };
    let (put_back, taken) = if verb.as_deref() == Some("stash") {
        (TargetRole::Stashed, TargetRole::Stashed)
    } else {
        (TargetRole::Reverted, TargetRole::Removed)
    };
    if scope.is_none() && untracked.is_none() {
        return;
    }
    // Git names a tracked file from the top of the repository.
    let Some(top) = git_line(cwd, &["rev-parse", "--show-toplevel"]).map(PathBuf::from) else {
        return;
    };
    if let Some(scope) = &scope {
        for name in crate::backup::git_discard_losses(cwd, scope).unwrap_or_default() {
            out.push(inside(below(&top, &name), put_back));
        }
    }
    if let Some(untracked) = &untracked {
        // A clean works below the directory it runs in; a stash with no
        // paths takes the whole tree's.
        let from = if untracked.whole_tree { &top } else { cwd };
        for path in git_would_remove(from, untracked) {
            if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                out.push(inside(path, taken));
            } else if !not_read(&path, ctx) && !delete::is_checkout(&path) {
                for rel in delete::files_under(&path, budget) {
                    out.push(inside(below(&path, &rel), taken));
                }
            }
        }
    }
}

/// The untracked files a command would take away, as `git clean` is asked
/// for them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Untracked {
    /// `-d`: untracked directories too.
    dirs: bool,
    /// `-x`: ignored files as well.
    ignored_too: bool,
    /// `-X`: ignored files only.
    ignored_only: bool,
    /// `-e <pattern>`: left alone.
    except: Vec<String>,
    /// The paths the command names; none is the directory it runs in.
    paths: Vec<String>,
    /// From the top of the repository, wherever the command runs (a stash).
    whole_tree: bool,
}

/// What `git clean <args>` would remove, or `None` when it removes nothing:
/// a dry run, or `-i`, which asks at a terminal an agent does not have.
///
/// HAND-WALKED (#56): `-n`, `-i`, `-h`, `-d`, `-x`, `-X`, `-e` and their
/// long names, alone or in a cluster (`-fdx`); `-f` and `-q` change nothing
/// about what is removed. Every other word is a path.
fn clean_takes(args: &[String]) -> Option<Untracked> {
    let mut u = Untracked::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        match a {
            "--" => {
                u.paths.extend(args[i..].iter().cloned());
                break;
            }
            "--dry-run" | "--interactive" => return None,
            "--force" | "--quiet" => {}
            "--exclude" => {
                u.except.extend(args.get(i).cloned());
                i += 1;
            }
            _ if a.starts_with("--exclude=") => u.except.push(a["--exclude=".len()..].to_string()),
            _ if a.starts_with("--") => {}
            _ if a.starts_with('-') && a.len() > 1 => {
                for (at, c) in a.char_indices().skip(1) {
                    match c {
                        'n' | 'i' | 'h' => return None,
                        'd' => u.dirs = true,
                        'x' => u.ignored_too = true,
                        'X' => u.ignored_only = true,
                        'e' => {
                            // `-e<pattern>` or `-e <pattern>`.
                            let rest = &a[at + 1..];
                            if rest.is_empty() {
                                u.except.extend(args.get(i).cloned());
                                i += 1;
                            } else {
                                u.except.push(rest.to_string());
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
            _ => u.paths.push(a.to_string()),
        }
    }
    Some(u)
}

/// What `git stash <args>` takes out of the tree: the scope of the tracked
/// changes it puts back as committed and, with `-u` or `-a`, the untracked
/// files it removes. `None` for the stash commands that take nothing:
/// `list`, `show`, `pop`, `apply`, `drop`, `clear`, `branch`, `create`,
/// `store`.
///
/// HAND-WALKED (#56): a bare `git stash` is `push`; `-u` and
/// `--include-untracked`, `-a` and `--all`, alone or in a cluster; `-m`
/// takes the next word; after `push` every other word is a path; after
/// `save` every other word is the message.
fn stash_takes(args: &[String]) -> Option<(Option<crate::backup::Discard>, Option<Untracked>)> {
    let mut untracked = false;
    let mut ignored = false;
    let mut verb: Option<&str> = None;
    let mut words: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        match a {
            "--" => {
                words.extend(args[i..].iter().cloned());
                break;
            }
            "--include-untracked" => untracked = true,
            "--all" => {
                untracked = true;
                ignored = true;
            }
            "-m" | "--message" | "--pathspec-from-file" => i += 1,
            _ if a.starts_with("--") => {}
            _ if a.starts_with('-') && a.len() > 1 => {
                untracked |= a[1..].contains('u') || a[1..].contains('a');
                ignored |= a[1..].contains('a');
                // `-um wip`: the message follows the cluster.
                if a.ends_with('m') {
                    i += 1;
                }
            }
            _ if verb.is_none() && words.is_empty() => verb = Some(a),
            _ => words.push(a.to_string()),
        }
    }
    let paths = match verb {
        None | Some("push") => words,
        Some("save") => Vec::new(),
        // A bare `git stash` with options and no verb put its first word
        // here; anything else is a verb that takes nothing from the tree.
        Some(_) => return None,
    };
    let scope = if paths.is_empty() {
        crate::backup::Discard::WholeTree
    } else {
        crate::backup::Discard::Paths(paths.clone())
    };
    let taken = untracked.then(|| Untracked {
        dirs: true,
        ignored_too: ignored,
        whole_tree: paths.is_empty(),
        paths,
        ..Untracked::default()
    });
    Some((Some(scope), taken))
}

/// What a clean would remove, asked of git as a dry run in `dir`. The
/// command is built here from what was read of the agent's, never passed
/// through (#41): `-n` first, the switches this reading knows, each
/// exclusion behind its own `-e`, and the paths behind `--`, where git takes
/// no option.
fn git_would_remove(dir: &std::path::Path, what: &Untracked) -> Vec<PathBuf> {
    let mut args: Vec<String> = ["-c", "core.quotePath=false", "clean", "-n"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if what.dirs {
        args.push("-d".into());
    }
    if what.ignored_only {
        args.push("-X".into());
    } else if what.ignored_too {
        args.push("-x".into());
    }
    for pattern in &what.except {
        args.push("-e".into());
        args.push(pattern.clone());
    }
    if !what.paths.is_empty() {
        args.push("--".into());
        args.extend(what.paths.iter().cloned());
    }
    let Ok(done) = std::process::Command::new("git")
        .current_dir(dir)
        .args(&args)
        .output()
    else {
        return Vec::new();
    };
    if !done.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&done.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix("Would remove "))
        .map(|name| below(dir, name.trim_matches('"')))
        .collect()
}

/// One line of git's answer, run in `dir`: `None` when git is not there,
/// fails (not a repository) or says nothing.
fn git_line(dir: &std::path::Path, args: &[&str]) -> Option<String> {
    let done = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&done.stdout).trim().to_string();
    (done.status.success() && !line.is_empty()).then_some(line)
}

/// A path git names with `/`, below `base`: `../x` is beside it.
fn below(base: &std::path::Path, name: &str) -> PathBuf {
    let mut path = base.to_path_buf();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                path.pop();
            }
            _ => path.push(part),
        }
    }
    path
}

/// The last component of a path as written, trailing separators aside.
fn last_component(s: &str) -> &str {
    s.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
}

/// `a/b`, whichever separator `a` ends in.
fn joined(a: &str, b: &str) -> String {
    format!("{}/{}", a.trim_end_matches(['/', '\\']), b)
}

/// Where `raw` is on disk, when the gate can say: not through a variable,
/// and not relative to a directory it could not follow.
fn on_disk(raw: &str, ctx: &EvalContext) -> Option<PathBuf> {
    if has_unexpanded_var(raw) || (!ctx.cwd_known && !delete::is_dir_independent(raw)) {
        return None;
    }
    Some(delete::resolve_path_in(raw, &ctx.cwd))
}

/// A file read out of a tree: already a path, with nothing left to resolve.
fn inside(path: PathBuf, role: TargetRole) -> ResolvedTarget {
    ResolvedTarget {
        role,
        as_written: path.display().to_string(),
        resolved: Some(path),
        end: None,
        shapes: Vec::new(),
        appends: false,
    }
}

/// The files a tree puts at, or takes from, `place`, for the parts of
/// `place` a tree is read for: the project, and the agent configuration
/// under the user's home. `tree` is where the tree is on disk now: `place`
/// itself for a delete, the source for a copy or a move.
///
/// Only a tree that lands or lies INSIDE one of those. A delete of the
/// project or of something above it (`rm -rf ..`, `rm -rf ~`, `rm -rf /`)
/// takes the project with it and is judged as it always was, by the rules
/// that name it and by what can be copied first: the root rules explain
/// themselves better than the first protected file a walk happens to meet
/// (`removed_with`).
///
/// And not a checkout of its own that is not the project's: a worktree
/// under `.claude/worktrees`, a clone in `vendor/`, which hold a `.git` of
/// their own. Every checkout has a `.claude/settings.json` and, once the
/// policy is committed, a `.termaxa/policy.yaml`; they gate sessions that
/// run there, and `rm -rf .claude/worktrees/done` removes that checkout
/// whole. Only what lands ON the project, or on an agent's configuration,
/// is read (`cp -r ../other-checkout/. .`).
fn guarded_files(
    tree: &std::path::Path,
    place: &std::path::Path,
    ctx: &EvalContext,
    budget: &mut delete::WalkBudget,
) -> Vec<PathBuf> {
    let mut guarded = vec![ctx.root.clone()];
    guarded.extend(delete::user_config_dirs());
    let mut out = Vec::new();
    let another_checkout =
        delete::is_checkout(tree) && !guarded.iter().any(|g| delete::is_inside(g, place));
    if guarded.iter().any(|g| delete::is_inside(place, g))
        && !another_checkout
        && std::fs::symlink_metadata(tree).is_ok_and(|m| m.is_dir())
    {
        for rel in delete::files_under(tree, budget) {
            out.push(place.join(rel));
        }
    }
    out
}

/// Is this tree one the reading does not enter: a directory a build
/// rebuilds, inside the project, or git's own?
fn not_read(tree: &std::path::Path, ctx: &EvalContext) -> bool {
    tree.file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case(".git"))
        || delete::reproducible_within(tree, Some(&ctx.root)).is_some()
}

/// What a delete, or the source side of a move, takes with a directory. A
/// glob is what it matches: each file by its own name, each directory by
/// what it holds. A link is removed as a link, and what it points at stays.
fn removed_with(
    raw: &str,
    ctx: &EvalContext,
    budget: &mut delete::WalkBudget,
    out: &mut Vec<ResolvedTarget>,
) {
    let Some(path) = on_disk(&without_brackets(&unquoted(raw)), ctx) else {
        return;
    };
    let (roots, globbed) = match delete::expand_glob(&path) {
        Some(found) => (found, true),
        None => (vec![path], false),
    };
    for root in roots {
        let Ok(meta) = std::fs::symlink_metadata(&root) else {
            continue;
        };
        // The project itself, or something above it, goes with everything
        // in it: there is nothing left for its hook config to gate, and the
        // rules that name the delete judge it (`guarded_files`).
        if not_read(&root, ctx) || delete::is_inside(&ctx.root, &root) {
            continue;
        }
        if !meta.is_dir() {
            if globbed {
                out.push(inside(root, TargetRole::Removed));
            }
            continue;
        }
        for p in guarded_files(&root, &root, ctx, budget) {
            out.push(inside(p, TargetRole::Removed));
        }
    }
}

/// What a `cp` or a `mv` lands: `dest/<name>` for a file that goes INTO a
/// directory, and for a tree, its files where they will be.
///
/// The destination is a directory to copy into when the command says so
/// (`-t`, more than one source, a trailing separator, `.`), or when it is
/// one on disk. One the gate cannot look at (a variable, a directory it
/// could not follow) may be a directory and is read as one: a deny too many
/// is loud, and a write nobody judged is not (#44). `-T` makes the
/// destination the copy itself.
fn landed(
    args: &[String],
    source_role: TargetRole,
    dest: &str,
    sources: &[String],
    ctx: &EvalContext,
    budget: &mut delete::WalkBudget,
    out: &mut Vec<ResolvedTarget>,
) {
    let long = |name: &str| args.iter().any(|a| a == name);
    let short = |c: char| {
        args.iter().any(|a| {
            a.len() > 1 && a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c)
        })
    };
    let explicit = args
        .iter()
        .any(|a| a == "-t" || a == "--target-directory" || a.starts_with("--target-directory="));
    let as_itself = long("--no-target-directory") || short('T');
    // A move takes a directory whole; a copy only when asked to.
    let whole_trees = source_role == TargetRole::Removed
        || long("--recursive")
        || long("--archive")
        || short('r')
        || short('R')
        || short('a');
    let named_a_directory = explicit
        || sources.len() > 1
        || dest.ends_with('/')
        || dest.ends_with('\\')
        || matches!(last_component(dest), "." | ".." | "~");
    let into = !as_itself
        && (named_a_directory
            || match on_disk(dest, ctx) {
                Some(p) => p.is_dir(),
                None => true,
            });

    for s in sources {
        let name = last_component(s);
        // `tree/.` is the tree's contents; `..` and nothing name no file.
        let contents = name == ".";
        if name.is_empty() || name == ".." {
            continue;
        }
        // The names that land: a glob's are what it matches on disk, and a
        // name held in a variable or a brace list is not known.
        let items: Vec<(String, Option<PathBuf>)> = if name.contains(['*', '?', '[']) {
            on_disk(&without_brackets(s), ctx)
                .and_then(|p| delete::expand_glob(&p))
                .unwrap_or_default()
                .into_iter()
                .filter_map(|p| Some((p.file_name()?.to_string_lossy().to_string(), Some(p))))
                .collect()
        } else if has_unexpanded_var(name) || name.contains('{') {
            Vec::new()
        } else {
            vec![(name.to_string(), on_disk(s, ctx))]
        };
        for (name, src) in items {
            match src.filter(|p| p.is_dir()) {
                Some(tree) => {
                    // `cp dir dest` without `-r` copies nothing.
                    if !whole_trees || not_read(&tree, ctx) {
                        continue;
                    }
                    // Where the tree's root lands: inside the directory
                    // under its own name, unless it is the contents
                    // (`tree/.`) or the destination is the tree's new name.
                    let place = if into && !contents {
                        joined(dest, &name)
                    } else {
                        dest.to_string()
                    };
                    let Some(place) = on_disk(&place, ctx) else {
                        continue;
                    };
                    for p in guarded_files(&tree, &place, ctx, budget) {
                        out.push(inside(p, TargetRole::Destination));
                    }
                }
                None => {
                    if into && !contents {
                        let t = target(&joined(dest, &name), TargetRole::Destination, ctx);
                        if !out.contains(&t) {
                            out.push(t);
                        }
                    }
                }
            }
        }
    }
}

/// Files a command writes through its own options rather than through a
/// redirect. Reported by Tim Schipper (Sep 27, 2026): `command_targets` had
/// no extractor for any of these, so neither the overwrite preview nor the
/// backup saw the file a `find -fprint`, `git diff --output`, `sed -n -i` or
/// `psql -o` was about to truncate. `args` are the words after the command.
/// Devices (`/dev/stdout`) are not files anyone loses.
pub fn option_write_targets(head: &str, args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match head {
        "find" | "gfind" => {
            let mut i = 0;
            while i < args.len() {
                if matches!(
                    args[i].as_str(),
                    "-fprint" | "-fprint0" | "-fprintf" | "-fls"
                ) {
                    if let Some(f) = args.get(i + 1) {
                        out.push(f.clone());
                    }
                    i += 1;
                }
                i += 1;
            }
        }
        "sed" | "gsed" => {
            let inv = crate::sed::parse_args(args);
            if inv.in_place {
                out.extend(inv.files.iter().filter(|f| f.as_str() != "-").cloned());
            }
            if !inv.sandbox {
                for s in &inv.scripts {
                    out.extend(crate::sed::effects(s).writes);
                }
            }
        }
        "git" => {
            let mut full = vec!["git".to_string()];
            full.extend(args.iter().cloned());
            let g = crate::delete::git_without_global_options(&full).unwrap_or(full);
            let mut i = 2;
            while i < g.len() {
                if let Some(v) = g[i].strip_prefix("--output=") {
                    out.push(v.to_string());
                } else if g[i] == "--output" {
                    if let Some(v) = g.get(i + 1) {
                        out.push(v.clone());
                    }
                    i += 1;
                }
                i += 1;
            }
        }
        "psql" => {
            let mut i = 0;
            while i < args.len() {
                let a = args[i].as_str();
                if a == "-o" || a == "--output" {
                    if let Some(v) = args.get(i + 1) {
                        out.push(v.clone());
                    }
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--output=") {
                    out.push(v.to_string());
                } else if a.len() > 2 && a.starts_with("-o") && !a.starts_with("--") {
                    out.push(a[2..].to_string());
                }
                i += 1;
            }
        }
        _ => {}
    }
    out.retain(|p| !p.is_empty() && !p.starts_with("/dev/"));
    out
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
fn copy_move_targets(
    head: &str,
    args: &[String],
    source_role: TargetRole,
) -> Vec<(String, TargetRole)> {
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
        } else if crate::delete::is_flag(head, a) && a.len() > 1 {
            // A boolean switch in this command's own syntax: `-r` for cp,
            // `/Y` for copy. Asked of `delete::is_flag` rather than answered
            // here, so the two modules cannot come to disagree about what a
            // switch looks like (#37).
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

/// Does this `tee` add to its files rather than replace them: `-a`,
/// `--append`, or the letter in a cluster of short flags (`-ia`)?
fn tee_appends(args: &[String]) -> bool {
    args.iter().any(|a| {
        a == "--append"
            || (a.len() > 1 && a.starts_with('-') && !a.starts_with("--") && a[1..].contains('a'))
    })
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
        // What follows the variable is literal, though: `$PWD/.env` is a
        // `.env` wherever `$PWD` is, and a path rule matching at any depth
        // names that end. `$X/policy.yaml` ends in a name no rule has, and
        // stays the documented limit.
        let end = delete::readable_end_of(&as_written).filter(|e| !e.is_empty());
        return ResolvedTarget {
            role,
            as_written,
            resolved: None,
            end,
            shapes,
            appends: false,
        };
    }

    if !ctx.cwd_known && !delete::is_dir_independent(&as_written) {
        shapes.push(SensitiveShape::UnknownDirectory);
        // What is known of the directory's end, then the target: the
        // path's end, wherever the directory is. `~other/x` is in another
        // user's home, not in the directory, and ends in what follows the
        // `~other`.
        let end = if as_written.starts_with('~') {
            delete::readable_end_of(&as_written)
        } else {
            Some(delete::join_end(&ctx.cwd_end, &as_written))
        }
        .filter(|e| !e.is_empty());
        return ResolvedTarget {
            role,
            as_written,
            resolved: None,
            end,
            shapes,
            appends: false,
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
        end: None,
        shapes,
        appends: false,
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
    #[test]
    fn the_files_an_option_writes_are_named() {
        let w = |head: &str, args: &[&str]| {
            option_write_targets(
                head,
                &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            w("find", &[".", "-type", "f", "-fprint", "out.txt"]),
            vec!["out.txt"]
        );
        assert_eq!(
            w("find", &[".", "-fprintf", "out.txt", "%p\\n"]),
            vec!["out.txt"]
        );
        assert_eq!(
            w("git", &["-C", "/x", "diff", "--output=o.txt"]),
            vec!["o.txt"]
        );
        assert_eq!(
            w("git", &["show", "--output", "o.txt", "HEAD"]),
            vec!["o.txt"]
        );
        assert_eq!(
            w("sed", &["-n", "-i", "s/a/b/", "f1", "f2"]),
            vec!["f1", "f2"]
        );
        assert_eq!(w("sed", &["-n", "w out.log", "in.txt"]), vec!["out.log"]);
        assert_eq!(
            w("psql", &["-d", "app", "-o", "q.txt", "-c", "select 1"]),
            vec!["q.txt"]
        );
        assert_eq!(w("psql", &["--output=q.txt"]), vec!["q.txt"]);
        // Reading forms name nothing, and a device is not a file anyone loses.
        assert!(w("find", &[".", "-name", "*.rs", "-print"]).is_empty());
        assert!(w("git", &["diff", "--stat"]).is_empty());
        assert!(w("sed", &["-n", "1,5p", "f"]).is_empty());
        assert!(w("sed", &["-n", "w /dev/stdout", "f"]).is_empty());
    }

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

    /// A redirection is a Destination the splitter reports, never an
    /// operand of the command it is attached to (#61). Before this, `>` and
    /// `log` were read as `mv`'s operands and `log` became the move's
    /// destination while `b`, the real one, became a source.
    #[test]
    fn a_redirection_is_not_an_operand() {
        assert_eq!(
            roles("mv a b > log 2>&1"),
            vec![
                ("a".into(), TargetRole::Removed),
                ("b".into(), TargetRole::Destination),
                ("log".into(), TargetRole::Destination),
            ]
        );
        assert_eq!(
            roles("cp a b 2>/dev/null"),
            vec![
                ("a".into(), TargetRole::Source),
                ("b".into(), TargetRole::Destination),
            ],
            "a sink is not a destination and not an operand"
        );
        assert_eq!(
            roles("rm -rf ./cache > /dev/null 2>&1"),
            vec![("./cache".into(), TargetRole::Removed)]
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

    /// cmd.exe switches are switches, not files. Measured before the fix:
    /// `copy /Y backup.txt .env` reported `/Y` as a Source, and worse,
    /// `copy /Y .env` reported `.env` as the DESTINATION - `/Y` filled the
    /// source slot, so a command that only copies FROM .env would have
    /// denied as if it wrote to it.
    ///
    /// Answered by `delete::is_flag`, which already decides this per command
    /// and per shell, rather than by a second rule here (#37).
    #[test]
    fn a_cmd_switch_is_not_an_operand() {
        assert_eq!(
            roles("copy /Y backup.txt .env"),
            vec![
                (".env".into(), TargetRole::Destination),
                ("backup.txt".into(), TargetRole::Source),
            ]
        );
        assert_eq!(
            roles("move /Y a b"),
            vec![
                ("a".into(), TargetRole::Removed),
                ("b".into(), TargetRole::Destination),
            ]
        );
        // One real operand names no destination, switches notwithstanding.
        assert!(
            roles("copy /Y .env").is_empty(),
            "a switch must not fill the source slot and promote .env"
        );
        assert_eq!(
            roles("copy /Y /Z a b"),
            vec![
                ("a".into(), TargetRole::Source),
                ("b".into(), TargetRole::Destination),
            ]
        );

        // CONTROL LEG, and the reason the rule matches SHAPE rather than a
        // leading slash: on Unix an absolute path starts with one too, and
        // losing it would be a silent under-report on the platform where
        // `/etc` matters most.
        assert_eq!(
            roles("cp /etc/hosts backup"),
            vec![
                ("/etc/hosts".into(), TargetRole::Source),
                ("backup".into(), TargetRole::Destination),
            ],
            "an absolute path is not a switch"
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

    /// #50, one layer down from where it was found. The policy layer reads
    /// its delete targets through `delete::extract_targets`, so the lexer
    /// that named the wrong file named it here too: a `match_path` rule
    /// written against the real filename missed, and the reason line quoted
    /// a path nothing on disk had. The resolved reading is the file bash
    /// deletes.
    #[test]
    fn an_escaped_quote_resolves_to_the_file_the_shell_deletes() {
        assert_eq!(
            roles(r#"rm -rf "a\"b""#),
            vec![("a\"b".to_string(), TargetRole::Removed)]
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

    /// After a `cd` the gate could read only the end of, a relative target
    /// has a known end and no resolved path (found Oct 14, 2026: `cd "$(git
    /// rev-parse --show-toplevel)/.claude" && echo {} > settings.json` was
    /// allowed by `echo *` through v0.21.5, the direct spelling a floor
    /// deny).
    #[test]
    fn a_target_in_a_directory_known_only_at_its_end_has_a_known_end() {
        let t = TempTree::new("resolve-end");
        let start = EvalContext::at(t.path());
        let ending = EvalContext {
            cwd_known: false,
            cwd_end: vec![".claude".to_string()],
            ..start.clone()
        };
        let r = target("settings.json", TargetRole::Destination, &ending);
        assert!(r.is_unresolved());
        assert!(r.has(SensitiveShape::UnknownDirectory), "{:?}", r.shapes);
        assert_eq!(
            r.end.as_deref(),
            Some(&[".claude".to_string(), "settings.json".to_string()][..])
        );
        assert_eq!(r.display(), "…/.claude/settings.json");
        // `..` climbs the known end, then into what is unknown.
        let r = target("../x", TargetRole::Destination, &ending);
        assert_eq!(r.end.as_deref(), Some(&["x".to_string()][..]));
        let r = target("../../x", TargetRole::Destination, &ending);
        assert_eq!(r.end.as_deref(), Some(&["x".to_string()][..]));
        // Climbing out of the end entirely leaves nothing known: no end.
        let r = target("..", TargetRole::Destination, &ending);
        assert_eq!(r.end, None);
        // An absolute target is the same file wherever the shell is.
        let r = target("/tmp/x", TargetRole::Destination, &ending);
        assert!(r.resolved.is_some());
        assert_eq!(r.end, None);
        // Another user's home is not under the directory: its end is what
        // follows the `~other`, not `.claude/…`.
        let r = target("~other/.claude/x", TargetRole::Destination, &ending);
        assert!(r.is_unresolved());
        assert_eq!(
            r.end.as_deref(),
            Some(&[".claude".to_string(), "x".to_string()][..])
        );
        let r = target("~other/x", TargetRole::Destination, &ending);
        assert_eq!(r.end.as_deref(), Some(&["x".to_string()][..]));
        // A variable in the target is unresolved for its own reason, and
        // ends in what follows the variable, not in the directory's end:
        // `$X` may be absolute.
        let r = target("$X/policy.yaml", TargetRole::Destination, &ending);
        assert!(r.has(SensitiveShape::UnexpandedVar));
        assert_eq!(r.end.as_deref(), Some(&["policy.yaml".to_string()][..]));
        let r = target("$PWD/.env", TargetRole::Destination, &start);
        assert!(r.has(SensitiveShape::UnexpandedVar));
        assert_eq!(r.end.as_deref(), Some(&[".env".to_string()][..]));
        assert_eq!(r.display(), "$PWD/.env");
        let r = target("$X", TargetRole::Destination, &start);
        assert_eq!(r.end, None);
        assert_eq!(r.display(), "$X");
        // With nothing known of the directory, the target's own path is
        // the end: wherever the shell is, this write lands on a
        // `.claude/settings.json`.
        let unknown = EvalContext {
            cwd_known: false,
            cwd_end: Vec::new(),
            ..start.clone()
        };
        let r = target(".claude/settings.json", TargetRole::Destination, &unknown);
        assert_eq!(
            r.end.as_deref(),
            Some(&[".claude".to_string(), "settings.json".to_string()][..])
        );
        assert_eq!(r.display(), "…/.claude/settings.json");
        let r = target("../x", TargetRole::Destination, &unknown);
        assert_eq!(r.end.as_deref(), Some(&["x".to_string()][..]));
        let r = target("..", TargetRole::Destination, &unknown);
        assert_eq!(r.end, None);
        assert_eq!(r.display(), "..");
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

#[cfg(test)]
mod contents_tests {
    use super::*;
    use crate::testutil::TempTree;

    fn landed_as(line: &str, ctx: &EvalContext) -> Vec<String> {
        command_contents(line, ctx)
            .into_iter()
            .map(|t| t.as_written)
            .collect()
    }

    /// A file that goes INTO a directory lands under its own name, and that
    /// is read off the command alone: the directory need not exist.
    #[test]
    fn a_file_copied_into_a_directory_lands_under_its_own_name() {
        let tmp = TempTree::new("contents-file");
        tmp.dir("isdir");
        tmp.file("isfile", "x");
        let ctx = EvalContext::at(tmp.path());
        assert_eq!(landed_as("cp a b dir/", &ctx), vec!["dir/a", "dir/b"]);
        assert_eq!(landed_as("mv a dir/", &ctx), vec!["dir/a"]);
        assert_eq!(landed_as("cp sub/a .", &ctx), vec!["./a"]);
        assert_eq!(landed_as("cp -t dir a", &ctx), vec!["dir/a"]);
        assert_eq!(
            landed_as("cp --target-directory=dir a b", &ctx),
            vec!["dir/a", "dir/b"]
        );
        // A directory on disk is one without the trailing separator.
        assert_eq!(landed_as("cp a isdir", &ctx), vec!["isdir/a"]);
        // A file, and a name nothing has yet, are the copy itself.
        assert!(landed_as("cp a isfile", &ctx).is_empty());
        assert!(landed_as("cp a newname", &ctx).is_empty());
        assert!(landed_as("cp -T a isdir", &ctx).is_empty());
        // A destination the gate cannot look at may be a directory.
        assert_eq!(landed_as("cp a \"$D\"", &ctx), vec!["$D/a"]);
        // The name that lands is the source's last word, whatever comes
        // before it; one held in a variable is not known.
        assert_eq!(
            landed_as("cp \"$T/settings.json\" dir/", &ctx),
            vec!["dir/settings.json"]
        );
        assert!(landed_as("cp \"$F\" dir/", &ctx).is_empty());
        // Neither a copy nor a move: nothing lands.
        assert!(landed_as("cat a dir/", &ctx).is_empty());
        // The same grammar under its other names.
        assert_eq!(landed_as("git mv a dir/", &ctx), vec!["dir/a"]);
        assert_eq!(landed_as("Copy-Item a dir\\", &ctx), vec!["dir/a"]);
        assert_eq!(
            landed_as("Copy-Item -Destination isdir -Path a,b -Force", &ctx),
            vec!["isdir/a", "isdir/b"]
        );
        assert_eq!(
            landed_as("Move-Item -Path a -Destination dir/", &ctx),
            vec!["dir/a"]
        );
        assert!(landed_as("Copy-Item a newname", &ctx).is_empty());
        // PowerShell's parameters, hand-walked (#56): one that takes a
        // value takes it; a prefix names the one parameter it starts; a
        // colon joins a value; a comma makes a list, spaced or not; `cp`
        // is `Copy-Item` when the line speaks PowerShell; and with no
        // destination the copy lands where the command runs.
        for (line, lands) in [
            (
                "Copy-Item a dir\\ -ErrorAction SilentlyContinue",
                vec!["dir/a"],
            ),
            ("Copy-Item a -ea 0 dir/", vec!["dir/a"]),
            ("Copy-Item -Filter *.json a dir/", vec!["dir/a"]),
            ("Copy-Item a -Dest isdir", vec!["isdir/a"]),
            ("Copy-Item -Destination:isdir a", vec!["isdir/a"]),
            (
                "Copy-Item -LiteralPath a -Destination isdir",
                vec!["isdir/a"],
            ),
            ("Copy-Item a, b isdir", vec!["isdir/a", "isdir/b"]),
            (
                "Copy-Item -Path a, b -Destination isdir",
                vec!["isdir/a", "isdir/b"],
            ),
            ("cpi a isdir", vec!["isdir/a"]),
            ("mi a isdir", vec!["isdir/a"]),
            ("cp a isdir -Force -PassThru", vec!["isdir/a"]),
            ("mv -Path a -Destination isdir", vec!["isdir/a"]),
            ("Copy-Item sub/a", vec!["./a"]),
        ] {
            assert_eq!(landed_as(line, &ctx), lands, "{line}");
        }
        for (word, kind) in [
            ("-Destination", Some(PsParameter::Destination)),
            ("-des", Some(PsParameter::Destination)),
            ("-NewName", Some(PsParameter::Destination)),
            ("-Path", Some(PsParameter::Source)),
            ("-pat", Some(PsParameter::Source)),
            ("-PSPath", Some(PsParameter::Source)),
            ("-l", Some(PsParameter::Source)),
            ("-Recurse", Some(PsParameter::Recurse)),
            ("-r", Some(PsParameter::Recurse)),
            ("-ErrorAction", Some(PsParameter::Value)),
            ("-ea", Some(PsParameter::Value)),
            ("-Filter", Some(PsParameter::Value)),
            ("-Force", Some(PsParameter::Switch)),
            ("-WhatIf", Some(PsParameter::Switch)),
            // `-p`, `-de`, `-f` and `-c` each start more than one.
            ("-p", None),
            ("-de", None),
            ("-f", None),
            ("-c", None),
            ("-nosuch", None),
        ] {
            assert_eq!(powershell_parameter(word), kind, "{word}");
        }
        // A rename: the new name stands beside the old one.
        assert_eq!(landed_as("Rename-Item a b", &ctx), vec!["b"]);
        assert_eq!(landed_as("ren sub\\a b", &ctx), vec!["sub/b"]);
        assert_eq!(
            landed_as("Rename-Item -NewName b -Path sub/a", &ctx),
            vec!["sub/b"]
        );
        assert!(landed_as("Rename-Item a", &ctx).is_empty());
        // A brace list is the words it opens into.
        assert_eq!(landed_as("cp x/{a,b} dir/", &ctx), vec!["dir/a", "dir/b"]);
        assert!(landed_as("cp a{,.bak}", &ctx).is_empty());
        assert_eq!(without_brackets(".[!.]*"), ".?*");
        assert_eq!(without_brackets("a[0-9]b[xy]"), "a?b?");
        assert_eq!(without_brackets("plain"), "plain");
    }

    /// What a stash and a clean take out of the tree, read off their words
    /// (hand-walked, #56).
    #[test]
    fn a_stash_and_a_clean_are_read_for_what_they_take() {
        use crate::backup::Discard;
        let w = |s: &str| -> Vec<String> { s.split_whitespace().map(String::from).collect() };
        let paths = |p: &[&str]| Discard::Paths(p.iter().map(|s| s.to_string()).collect());
        let everything = || Untracked {
            dirs: true,
            whole_tree: true,
            ..Untracked::default()
        };
        // A stash: bare is `push`; `save` takes a message, `push` paths.
        for line in [
            "",
            "push",
            "save wip on the form",
            "-m wip",
            "push -m wip",
            "-k",
        ] {
            assert_eq!(
                stash_takes(&w(line)),
                Some((Some(Discard::WholeTree), None)),
                "git stash {line}"
            );
        }
        for line in ["push src docs", "push -m wip -- src docs", "-- src docs"] {
            assert_eq!(
                stash_takes(&w(line)),
                Some((Some(paths(&["src", "docs"])), None)),
                "git stash {line}"
            );
        }
        for line in ["-u", "--include-untracked", "push -u", "-ku", "-um wip"] {
            assert_eq!(
                stash_takes(&w(line)),
                Some((Some(Discard::WholeTree), Some(everything()))),
                "git stash {line}"
            );
        }
        for line in ["-a", "--all", "push --all"] {
            assert_eq!(
                stash_takes(&w(line)),
                Some((
                    Some(Discard::WholeTree),
                    Some(Untracked {
                        ignored_too: true,
                        ..everything()
                    })
                )),
                "git stash {line}"
            );
        }
        assert_eq!(
            stash_takes(&w("push -u -- src")),
            Some((
                Some(paths(&["src"])),
                Some(Untracked {
                    dirs: true,
                    paths: vec!["src".to_string()],
                    ..Untracked::default()
                })
            ))
        );
        // The verbs that put nothing back.
        for verb in [
            "list", "show", "pop", "apply", "drop", "clear", "branch b", "create", "store x",
        ] {
            assert_eq!(stash_takes(&w(verb)), None, "git stash {verb}");
        }

        // A clean: what `-d`, `-x`, `-X`, `-e` and the paths say.
        assert_eq!(clean_takes(&w("-f")), Some(Untracked::default()));
        for line in ["-fd", "-f -d", "-df", "--force -d", "-ffd", "-qfd"] {
            assert_eq!(
                clean_takes(&w(line)),
                Some(Untracked {
                    dirs: true,
                    ..Untracked::default()
                }),
                "git clean {line}"
            );
        }
        assert_eq!(
            clean_takes(&w("-fdx")),
            Some(Untracked {
                dirs: true,
                ignored_too: true,
                ..Untracked::default()
            })
        );
        assert_eq!(
            clean_takes(&w("-fX")),
            Some(Untracked {
                ignored_only: true,
                ..Untracked::default()
            })
        );
        for line in [
            "-fd -e .termaxa -e *.log",
            "-fd --exclude=.termaxa --exclude *.log",
            "-fde.termaxa -e*.log",
        ] {
            assert_eq!(
                clean_takes(&w(line)),
                Some(Untracked {
                    dirs: true,
                    except: vec![".termaxa".to_string(), "*.log".to_string()],
                    ..Untracked::default()
                }),
                "git clean {line}"
            );
        }
        for line in ["-fd build out", "-fd -- build out"] {
            assert_eq!(
                clean_takes(&w(line)),
                Some(Untracked {
                    dirs: true,
                    paths: vec!["build".to_string(), "out".to_string()],
                    ..Untracked::default()
                }),
                "git clean {line}"
            );
        }
        // A dry run, a prompt and the help remove nothing.
        for line in [
            "-n",
            "-fdn",
            "-n -fd",
            "--dry-run -fd",
            "-i",
            "--interactive",
            "-h",
        ] {
            assert_eq!(clean_takes(&w(line)), None, "git clean {line}");
        }
        // Git names a path with `/`, from where it was asked.
        let base = std::path::Path::new("/repo/sub");
        assert_eq!(
            below(base, ".termaxa/"),
            PathBuf::from("/repo/sub/.termaxa")
        );
        assert_eq!(below(base, "../.env"), PathBuf::from("/repo/.env"));
        assert_eq!(below(base, "./a/b.txt"), PathBuf::from("/repo/sub/a/b.txt"));
    }

    /// A tree is read off the disk, for the project only: its files where
    /// they will be, or where they were.
    #[test]
    fn a_tree_is_read_for_what_it_changes_in_the_project() {
        let tmp = TempTree::new("contents-tree");
        tmp.file("proj/.claude/settings.json", "{}");
        tmp.file("proj/src/a.ts", "a");
        tmp.file("tpl/.claude/settings.json", "{}");
        tmp.file("tpl/README.md", "t");
        let proj = tmp.path().join("proj");
        let ctx = EvalContext::at(&proj);
        let paths = |line: &str| -> Vec<(TargetRole, PathBuf)> {
            command_contents(line, &ctx)
                .into_iter()
                .filter_map(|t| Some((t.role, t.resolved?)))
                .collect()
        };
        // The template's files, where they land in the project.
        let landed = paths("cp -r ../tpl/. .");
        assert!(
            landed.contains(&(TargetRole::Destination, proj.join(".claude/settings.json")))
                && landed.contains(&(TargetRole::Destination, proj.join("README.md"))),
            "{landed:?}"
        );
        // Under its own name when it is the directory that is copied.
        let landed = paths("cp -r ../tpl .");
        assert!(
            landed.contains(&(
                TargetRole::Destination,
                proj.join("tpl/.claude/settings.json")
            )),
            "{landed:?}"
        );
        // Without `-r` a directory is not copied at all.
        assert!(paths("cp ../tpl .").is_empty());
        // What a delete and a move take with a directory.
        assert_eq!(
            paths("rm -rf .claude"),
            vec![(TargetRole::Removed, proj.join(".claude/settings.json"))]
        );
        assert_eq!(
            paths("mv .claude ../gone"),
            vec![(TargetRole::Removed, proj.join(".claude/settings.json"))]
        );
        // The project copied or a tree deleted somewhere else: not read.
        assert!(paths("cp -r . ../backup").is_empty());
        assert!(paths("rm -rf ../tpl").is_empty());
    }
}
