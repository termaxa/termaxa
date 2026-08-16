use std::process::Command;

/// An execution preview: what will actually happen if this command runs.
///
/// This module is the seed of the plugin system. `generate` inspects the
/// command and returns a preview if some plugin knows how to produce one.
/// Previews are strictly best-effort: any failure (not a repo, no remote,
/// tool missing) yields `None` and enforcement proceeds exactly as before.
/// A preview must never block or break a decision.
#[derive(Debug)]
pub struct Preview {
    pub title: String,
    /// Full preview lines, shown in `run` and `check`.
    pub lines: Vec<String>,
    /// One-line summary, embedded in the hook reason for Claude Code prompts.
    pub summary: String,
    /// True when this command destroys something the backup engine cannot
    /// copy aside first - either no backup covers the command, or the target
    /// exceeds the copy budget.
    ///
    /// Roadmap 2.5. The preview has computed this since v0.13 and printed it
    /// ("NOT recoverable"), but nothing could ACT on it: the strongest
    /// unused signal in the product. Carried as a fact here so the decision
    /// layer can amplify with it, without the preview deciding anything.
    pub uninsurable: bool,
}

/// Generate a preview, optionally with knowledge of the project root.
///
/// The root lets the delete preview answer "is this target outside the
/// project?" — its single most useful signal, and one the process cwd cannot
/// supply: in hook mode the agent may spawn us from anywhere (see the Cursor
/// cwd bug). Callers that know the root pass it; callers that don't pass None
/// and the signal is omitted rather than guessed.
/// Build the consequence preview for a command.
///
/// `live` controls whether the preview may execute anything. When false, only
/// static analysis runs: parsing the command, resolving paths, scanning the
/// filesystem. No subprocess is spawned.
///
/// SECURITY (v0.14.2). `hook::run` generates the preview before returning a
/// decision, so a DENIED command still reached this function. v0.14.1 fixed
/// what the Postgres preview did with the arguments it was handed; it left
/// standing the structure that let a denied command reach a subprocess at all.
/// Confirmed with a stub `terraform` on PATH: a denied `terraform destroy`
/// caused `terraform plan -destroy` to run in the agent's working directory,
/// which initializes providers and evaluates `external` data sources.
///
/// The fix is not to skip the preview on deny — the denial message is more
/// useful with it ("DROP TABLE is blocked | DROP users"), and the delete
/// preview never spawns anything. It is to make "may this execute?" an
/// argument, so the caller that already knows the verdict decides.
/// Reported by Tim Schipper.
pub fn generate(
    command: &str,
    root: Option<&std::path::Path>,
    cwd: &std::path::Path,
    live: bool,
) -> Option<Preview> {
    // Deletes are checked across the whole command first: a compound like
    // `mkdir x && rm -rf /` must not have its delete masked by an earlier
    // segment producing a preview.
    if let Some(p) = crate::delete::preview_for(command, root, cwd) {
        return Some(p);
    }
    // Compound commands: preview the first segment that has one.
    let segments = crate::shell::split_segments(command);
    if segments.len() > 1 {
        if let Some(p) = segments.iter().find_map(|s| generate_one(s, cwd, live)) {
            return Some(p);
        }
        // No per-command preview, but a segment may still overwrite something.
        return overwrite_preview(command, root, cwd);
    }
    generate_one(command, cwd, live).or_else(|| overwrite_preview(command, root, cwd))
}

/// What a command is about to write over.
///
/// Roadmap 2.2. Deletes have had a blast-radius preview since v0.13; writes
/// had nothing. `cat /dev/null > config.json` destroys a file just as
/// thoroughly as `rm config.json`, and the human approving it saw a bare
/// verdict with no title, no lines, and no word about insurance.
///
/// Reports only what an existing file loses. A write that CREATES a file
/// destroys nothing, and a preview that announced it would be noise on
/// ordinary work - the same judgement `backup` makes when it declines to
/// insure a path that is not there yet (#48).
///
/// Uses the roles from 2.1, so a command's SOURCES are not reported as at
/// risk: `cp .env backup.txt` reads `.env` and writes `backup.txt`, and only
/// the second is losing anything.
fn overwrite_preview(
    command: &str,
    root: Option<&std::path::Path>,
    cwd: &std::path::Path,
) -> Option<Preview> {
    let ctx = match root {
        Some(r) => crate::resolve::EvalContext::new_for_preview(cwd, r),
        None => crate::resolve::EvalContext::at(cwd),
    };

    let mut lines = Vec::new();
    let mut summary_parts = Vec::new();
    let mut uninsurable = false;

    for t in crate::resolve::command_targets(command, &ctx) {
        if t.role != crate::resolve::TargetRole::Destination {
            continue;
        }
        let Some(path) = &t.resolved else {
            // An unresolved destination is already reported by the shape
            // machinery in policy; repeating it here would say the same thing
            // twice in one prompt.
            continue;
        };
        let Ok(meta) = std::fs::metadata(path) else {
            continue; // creating, not overwriting
        };
        if meta.is_dir() {
            continue; // a directory destination is where files land, not what is lost
        }

        let bytes = meta.len();
        lines.push(format!("  target      : {}", path.display()));
        lines.push(format!(
            "  loses       : {} of existing content",
            fmt_bytes(bytes)
        ));
        for s in &t.shapes {
            lines.push(format!("  ⚠ {}", s.label()));
        }

        match crate::backup::plan(command, cwd) {
            Some(plan) => lines.push(format!("  insurance   : {} (automatic on run/hook)", plan)),
            None => {
                lines
                    .push("  ✗ insurance : no backup covers this command — NOT recoverable".into());
                uninsurable = true;
            }
        }
        summary_parts.push(format!(
            "{} loses {}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string()),
            fmt_bytes(bytes)
        ));
    }

    if lines.is_empty() {
        return None;
    }
    Some(Preview {
        title: "overwrite impact".into(),
        lines,
        summary: summary_parts.join("; "),
        uninsurable,
    })
}

/// Bytes in the shape a human reads at a glance. Deliberately coarse: the
/// decision is "is this a lot", not "exactly how much".
fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

fn generate_one(command: &str, cwd: &std::path::Path, live: bool) -> Option<Preview> {
    let cmd = crate::policy::normalize(command);
    if cmd.starts_with("git push") {
        // Entirely subprocess-derived: `git rev-parse`, `git log`. Nothing
        // static to fall back on, so a non-live preview has no answer.
        return if live { git_push_preview(&cmd) } else { None };
    }
    if cmd.starts_with("psql") || cmd.contains(" psql ") {
        return crate::pg::preview_for(command, cwd, live);
    }
    for bin in ["terraform", "tofu"] {
        if cmd.starts_with(&format!("{} apply", bin))
            || cmd.starts_with(&format!("{} destroy", bin))
        {
            // `terraform plan` is the confirmed case: it initializes
            // providers and evaluates `external` data sources, which execute
            // arbitrary programs.
            return if live {
                terraform_preview(bin, cmd.starts_with(&format!("{} destroy", bin)))
            } else {
                None
            };
        }
    }
    None
}

/// What would `git push` actually send?
///
/// The core question is "compared to what?" — three cases:
///   1. branch has an upstream        -> @{u}..HEAD
///   2. no upstream, origin/<b> exists -> origin/<b>..HEAD
///   3. brand-new branch               -> everything is new
fn git_push_preview(command: &str) -> Option<Preview> {
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?;
    let force = command.contains("--force") || command.contains(" -f ");

    let (range, baseline) = if git(&["rev-parse", "--abbrev-ref", "@{u}"]).is_some() {
        ("@{u}..HEAD".to_string(), "upstream".to_string())
    } else {
        let remote_branch = format!("origin/{}", branch);
        if git(&["rev-parse", "--verify", "--quiet", &remote_branch]).is_some() {
            (format!("{}..HEAD", remote_branch), remote_branch)
        } else {
            // Case 3: nothing on the remote to compare against.
            let count = git(&["rev-list", "--count", "HEAD"])?;
            return Some(Preview {
                // A push is insured by pinning the remote ref before it runs
                // (`backup::plan` covers forced pushes), and a brand-new
                // branch destroys nothing on the remote in any case.
                uninsurable: false,
                title: format!("push preview ({} -> new remote branch)", branch),
                lines: vec![format!(
                    "entire branch is new to the remote: {} commit(s)",
                    count
                )],
                summary: format!("new branch, {} commit(s)", count),
            });
        }
    };

    let count: u32 = git(&["rev-list", "--count", &range])?.parse().ok()?;

    // A force push's damage is what the remote LOSES — the reverse range.
    // Discovered live in v0.6.0: the preview said "nothing to push" while a
    // force push destroyed a commit. Gain and loss are different directions.
    let loss_range = range.replace("..HEAD", "").replace("HEAD", "");
    let mut loss_lines: Vec<String> = Vec::new();
    let mut loss_count: u32 = 0;
    if force && !loss_range.is_empty() {
        let reverse = format!("HEAD..{}", loss_range);
        if let Some(n) = git(&["rev-list", "--count", &reverse]).and_then(|s| s.parse().ok()) {
            loss_count = n;
            if n > 0 {
                loss_lines.push(format!("  ⚠ remote will LOSE {} commit(s):", n));
                if let Some(log) = git(&["log", "--oneline", "--no-decorate", &reverse]) {
                    for l in log.lines().take(5) {
                        loss_lines.push(format!("    ✗ {}", l));
                    }
                }
            }
        }
    }

    if count == 0 && loss_count == 0 {
        return Some(Preview {
            // Nothing to push destroys nothing.
            uninsurable: false,
            title: format!("push preview ({} -> {})", branch, baseline),
            lines: vec!["nothing to push — remote is up to date".to_string()],
            summary: "nothing to push".to_string(),
        });
    }

    let mut lines = loss_lines;

    // The commits that would be sent (cap at 5 to keep the prompt readable).
    if let Some(log) = git(&["log", "--oneline", "--no-decorate", &range]) {
        for (i, l) in log.lines().enumerate() {
            if i == 5 {
                lines.push(format!("  ... and {} more", count as usize - 5));
                break;
            }
            lines.push(format!("  {}", l));
        }
    }

    // File-level impact: last line of --stat is the totals summary.
    let mut files_changed = String::from("? files changed");
    if let Some(stat) = git(&["diff", "--stat", &range]) {
        if let Some(total) = stat.lines().last() {
            files_changed = total.trim().to_string();
        }
        let file_lines: Vec<&str> = stat.lines().collect();
        if file_lines.len() > 1 {
            lines.push(String::new());
            for l in file_lines.iter().take(file_lines.len() - 1).take(8) {
                lines.push(format!("  {}", l.trim()));
            }
            if file_lines.len() - 1 > 8 {
                lines.push(format!("  ... and {} more files", file_lines.len() - 1 - 8));
            }
        }
    }

    let mut summary = format!("{} commit(s); {}", count, files_changed);
    if loss_count > 0 {
        summary = format!("remote LOSES {} commit(s); {}", loss_count, summary);
    }
    Some(Preview {
        // Forced pushes are insured by pinning the remote ref before the
        // push, which `backup::plan` does. The commits the remote would lose
        // are recoverable from that pin.
        uninsurable: false,
        title: format!("push preview ({} -> {})", branch, baseline),
        lines,
        summary,
    })
}

/// Run a git command, returning trimmed stdout on success, None on any failure.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ---------------------------------------------------------------------------
// terraform / tofu: what would `apply` actually do?
// ---------------------------------------------------------------------------

/// Run `plan` and surface add/change/destroy counts before an apply.
/// -input=false and -lock=false are load-bearing: a preview must never hang
/// the hook waiting for interactive input or a state lock.
fn terraform_preview(bin: &str, destroy: bool) -> Option<Preview> {
    let mut args = vec!["plan", "-no-color", "-input=false", "-lock=false"];
    if destroy {
        args.push("-destroy");
    }
    let out = std::process::Command::new(bin).args(&args).output().ok()?;
    if !out.status.success() {
        return None; // uninitialized dir, bad config — best effort, stay silent
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (add, change, del, resources) = parse_tf_plan(&text)?;

    let mut lines = Vec::new();
    if del > 0 {
        lines.push(format!("  ⚠ {} resource(s) will be DESTROYED", del));
    }
    for r in resources.iter().take(6) {
        lines.push(format!("  {}", r));
    }
    lines.push(format!(
        "  plan: {} to add, {} to change, {} to destroy",
        add, change, del
    ));

    Some(Preview {
        // Roadmap 2.5. `backup::plan` pins local terraform state, so a
        // rollback can restore the STATE FILE - it cannot restore a destroyed
        // cloud resource. When the plan destroys nothing there is nothing to
        // insure; when it destroys something, insurance does not reach it and
        // saying otherwise would be the most expensive lie the tool could
        // tell.
        uninsurable: del > 0,
        title: format!("{} plan preview", bin),
        lines,
        summary: format!("plan: +{} ~{} -{}", add, change, del),
    })
}

/// Pure parser: extract counts + resource action lines from plan output.
pub fn parse_tf_plan(text: &str) -> Option<(u32, u32, u32, Vec<String>)> {
    let mut resources = Vec::new();
    let mut counts = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("# ") && t.contains(" will be ") {
            resources.push(t.trim_start_matches("# ").to_string());
        }
        if let Some(rest) = t.strip_prefix("Plan: ") {
            // "3 to add, 1 to change, 2 to destroy."
            let nums: Vec<u32> = rest
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() >= 3 {
                counts = Some((nums[0], nums[1], nums[2]));
            }
        }
        if t.starts_with("Destroy complete") || t.starts_with("No changes.") {
            counts = counts.or(Some((0, 0, 0)));
        }
    }
    counts.map(|(a, c, d)| (a, c, d, resources))
}

#[cfg(test)]
mod tf_tests {
    use super::*;

    #[test]
    fn parses_plan_summary_and_resources() {
        let out = r#"
Terraform will perform the following actions:

  # terraform_data.web[0] will be created
  # terraform_data.web[1] will be created
  # aws_instance.old will be destroyed

Plan: 2 to add, 0 to change, 1 to destroy.
"#;
        let (a, c, d, res) = parse_tf_plan(out).unwrap();
        assert_eq!((a, c, d), (2, 0, 1));
        assert_eq!(res.len(), 3);
        assert!(res[2].contains("will be destroyed"));
    }

    #[test]
    fn a_resource_line_needs_both_halves_of_its_shape() {
        // Plan output is full of `#` comments, and prose elsewhere says "will
        // be" constantly. A resource line is the intersection, not either one.
        let out = "\
  # this is a note about the plan
  Terraform will be reading state
  # aws_instance.old will be destroyed

Plan: 0 to add, 0 to change, 1 to destroy.
";
        let (_, _, _, resources) = parse_tf_plan(out).unwrap();
        assert_eq!(resources, ["aws_instance.old will be destroyed"]);
    }

    #[test]
    fn no_changes_is_zeroes() {
        let (a, c, d, _) = parse_tf_plan("No changes. Your infrastructure matches.").unwrap();
        assert_eq!((a, c, d), (0, 0, 0));
    }
}

/// The live push preview, against real repositories.
///
/// `git()` runs wherever the PROCESS is, so every test here moves into a
/// purpose-built repo — which is also why they take `TestEnv` and its lock
/// rather than a bare scratch tree.
#[cfg(test)]
mod push_preview_tests {
    use super::*;

    use crate::testutil::TestEnv;
    use std::path::{Path, PathBuf};

    fn git_run(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "user.email=tests@termaxa.invalid",
                "-c",
                "user.name=termaxa tests",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .expect("git must be available: the preview under test is git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn commit_files(dir: &Path, names: &[String], message: &str) {
        for name in names {
            std::fs::write(dir.join(name), format!("{message}\n")).expect("file must be writable");
        }
        git_run(dir, &["add", "-A"]);
        git_run(dir, &["commit", "-q", "-m", message]);
    }

    fn commit_one(dir: &Path, name: &str, message: &str) {
        commit_files(dir, &[name.to_string()], message);
    }

    /// A working copy with `origin` beside it, one commit pushed and upstream
    /// tracking set — case 1 of the three the preview distinguishes.
    fn repo_with_remote(env: &mut TestEnv) -> PathBuf {
        let root = env.root().to_path_buf();
        let remote = root.join("remote.git");
        git_run(
            &root,
            &["init", "--bare", "-q", remote.to_str().expect("utf-8 path")],
        );

        let work = root.join("work");
        std::fs::create_dir_all(&work).expect("work dir must be creatable");
        git_run(&work, &["init", "-q"]);
        // Name the unborn branch rather than checking one out: `checkout -B`
        // has no commit to stand on yet.
        git_run(&work, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        git_run(
            &work,
            &[
                "remote",
                "add",
                "origin",
                remote.to_str().expect("utf-8 path"),
            ],
        );
        commit_one(&work, "seed.txt", "seed");
        git_run(&work, &["push", "-q", "-u", "origin", "main"]);
        // A bare repo's HEAD still names whatever `init` defaulted to, so a
        // clone of it would land on an unborn branch of that name instead of
        // the one branch that exists.
        git_run(&remote, &["symbolic-ref", "HEAD", "refs/heads/main"]);

        env.chdir(&work);
        work
    }

    /// Put a commit on the remote that the local branch does not have, so a
    /// force push would destroy it.
    fn advance_the_remote(root: &Path, remote: &Path) {
        let other = root.join("other");
        git_run(
            root,
            &[
                "clone",
                "-q",
                remote.to_str().expect("utf-8 path"),
                other.to_str().expect("utf-8 path"),
            ],
        );
        commit_one(&other, "remote-only.txt", "only on the remote");
        git_run(&other, &["push", "-q", "origin", "main"]);
    }

    fn preview_of(command: &str) -> Preview {
        generate(command, None, std::path::Path::new("."), true)
            .expect("a live push preview should exist in a repo")
    }

    #[test]
    fn a_branch_the_remote_has_never_seen_is_entirely_new() {
        let mut env = TestEnv::new("preview-new-branch");
        let work = repo_with_remote(&mut env);
        git_run(&work, &["checkout", "-q", "-b", "feature/widgets"]);
        commit_one(&work, "widget.txt", "widget");

        let p = preview_of("git push origin feature/widgets");
        assert_eq!(
            p.summary, "new branch, 2 commit(s)",
            "with no upstream and no origin/<branch>, everything is new"
        );
        assert!(p.title.contains("new remote branch"), "{}", p.title);
    }

    #[test]
    fn nothing_to_push_is_said_plainly() {
        let mut env = TestEnv::new("preview-current");
        repo_with_remote(&mut env);

        let p = preview_of("git push origin main");
        assert_eq!(p.summary, "nothing to push");
    }

    #[test]
    fn the_commit_list_is_capped_and_says_how_many_it_hid() {
        let mut env = TestEnv::new("preview-ahead");
        let work = repo_with_remote(&mut env);
        for i in 0..7 {
            commit_one(&work, &format!("f{i}.txt"), &format!("commit {i}"));
        }

        let p = preview_of("git push origin main");
        assert!(
            p.summary.starts_with("7 commit(s);"),
            "the count leads the summary: {}",
            p.summary
        );
        let listed = p.lines.iter().filter(|l| l.contains("commit ")).count();
        assert_eq!(
            listed, 5,
            "five commits are listed, then a tally: {:?}",
            p.lines
        );
        assert!(
            p.lines.iter().any(|l| l.contains("... and 2 more")),
            "the hidden ones are counted, not dropped: {:?}",
            p.lines
        );
        assert!(
            !p.summary.contains("LOSES"),
            "an ordinary push loses nothing: {}",
            p.summary
        );
        assert!(
            !p.lines.iter().any(|l| l.contains("LOSE")),
            "and says nothing about loss: {:?}",
            p.lines
        );
    }

    #[test]
    fn a_forced_push_that_destroys_nothing_claims_no_losses() {
        // The boundary the `> 0` guards sit on: forced, with a range to
        // examine, but nothing on the remote to lose.
        let mut env = TestEnv::new("preview-force-clean");
        let work = repo_with_remote(&mut env);
        commit_one(&work, "ahead.txt", "ahead");

        let p = preview_of("git push -f origin main");
        assert!(
            !p.summary.contains("LOSES"),
            "nothing is lost, so nothing is claimed: {}",
            p.summary
        );
        assert!(!p.lines.iter().any(|l| l.contains("LOSE")), "{:?}", p.lines);
    }

    #[test]
    fn a_forced_push_reports_what_the_remote_would_lose() {
        // The v0.6.0 incident: the preview said "nothing to push" while a
        // force push destroyed a commit. Gain and loss are different
        // directions, and only the loss direction is the damage.
        let mut env = TestEnv::new("preview-force-loss");
        let work = repo_with_remote(&mut env);
        let remote = env.root().join("remote.git");
        advance_the_remote(env.root(), &remote);
        git_run(&work, &["fetch", "-q", "origin"]);

        // `-f` alone, not `--force`: both spellings must count as force.
        let forced = preview_of("git push -f origin main");
        assert!(
            forced.summary.starts_with("remote LOSES 1 commit(s);"),
            "the loss leads the summary: {}",
            forced.summary
        );
        assert!(
            forced
                .lines
                .iter()
                .any(|l| l.contains("remote will LOSE 1 commit(s)")),
            "and is spelled out in the body: {:?}",
            forced.lines
        );

        // The same state without the force flag destroys nothing, so the
        // preview must not borrow the forced reading.
        let plain = preview_of("git push origin main");
        assert_eq!(plain.summary, "nothing to push");
    }

    #[test]
    fn the_file_list_is_capped_and_excludes_the_totals_line() {
        let mut env = TestEnv::new("preview-files-many");
        let work = repo_with_remote(&mut env);
        let names: Vec<String> = (0..10).map(|i| format!("file{i:02}.txt")).collect();
        commit_files(&work, &names, "ten files");

        let p = preview_of("git push origin main");
        assert!(
            p.lines.iter().any(|l| l.contains("... and 2 more files")),
            "ten files, eight shown: {:?}",
            p.lines
        );
        // The last --stat line is the totals; it belongs in the summary, and
        // listing it among the files would double-count it.
        assert!(
            !p.lines.iter().any(|l| l.contains("files changed")),
            "the totals line is not a file: {:?}",
            p.lines
        );
        assert!(
            p.summary.contains("files changed"),
            "the summary is where the totals go: {}",
            p.summary
        );
    }

    #[test]
    fn a_short_file_list_still_stops_before_the_totals_line() {
        // Under the cap of eight, the ONLY thing keeping the --stat totals
        // line out of the file list is dropping the last entry. With ten
        // files the cap hides that, and a list that ran one line too far
        // would look correct.
        let mut env = TestEnv::new("preview-files-few");
        let work = repo_with_remote(&mut env);
        let names: Vec<String> = (0..3).map(|i| format!("file{i}.txt")).collect();
        commit_files(&work, &names, "three files");

        let p = preview_of("git push origin main");
        assert!(
            !p.lines.iter().any(|l| l.contains("files changed")),
            "the totals line is not one of the files: {:?}",
            p.lines
        );
        let listed = p
            .lines
            .iter()
            .filter(|l| l.contains(".txt") && l.contains('|'))
            .count();
        assert_eq!(listed, 3, "three files, three lines: {:?}", p.lines);
    }

    #[test]
    fn exactly_eight_files_are_all_shown_without_a_tally() {
        // The boundary: eight fit, so there is no "and N more" to add.
        let mut env = TestEnv::new("preview-files-eight");
        let work = repo_with_remote(&mut env);
        let names: Vec<String> = (0..8).map(|i| format!("file{i}.txt")).collect();
        commit_files(&work, &names, "eight files");

        let p = preview_of("git push origin main");
        assert!(
            !p.lines.iter().any(|l| l.contains("more files")),
            "nothing was hidden, so nothing is tallied: {:?}",
            p.lines
        );
        let listed = p.lines.iter().filter(|l| l.contains("file")).count();
        assert!(listed >= 8, "all eight are shown: {:?}", p.lines);
    }
}

/// The terraform planner, driven by a stub binary.
///
/// Neither terraform nor tofu is a reasonable test dependency, and the plan
/// output is the only thing this code reads — so a script that prints one is
/// a complete stand-in. It is also how the live-gate finding below was
/// originally confirmed.
#[cfg(all(test, unix))]
mod terraform_stub_tests {
    use super::*;

    use crate::testutil::{TempTree, TestEnv};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    const DESTROYS_ONE: &str = "  # aws_instance.old will be destroyed\n\
                                \x20 # terraform_data.web will be created\n\
                                Plan: 2 to add, 0 to change, 1 to destroy.";
    const DESTROYS_NOTHING: &str = "  # terraform_data.web will be created\n\
                                    Plan: 1 to add, 0 to change, 0 to destroy.";

    /// A fake planner that prints `plan` and exits with `code`.
    fn stub(dir: &Path, name: &str, plan: &str, code: i32) -> PathBuf {
        std::fs::create_dir_all(dir).expect("stub dir must be creatable");
        let path = dir.join(name);
        // printf rather than a heredoc through `cat`: `cat` is an external
        // command, so the stub would depend on PATH resolving it, and PATH is
        // exactly what the neighbouring test in this module rewrites while
        // this one may be running. printf is a builtin and needs nothing
        // found on disk.
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' \"{plan}\"\nexit {code}\n"),
        )
        .expect("stub must be writable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stub must be executable");
        path
    }

    #[test]
    fn a_plan_that_destroys_something_leads_with_the_destruction() {
        let tmp = TempTree::new("tf-destroys");
        let bin = stub(tmp.path(), "faketf", DESTROYS_ONE, 0);

        let p = terraform_preview(bin.to_str().expect("utf-8 path"), true)
            .expect("a successful plan is a preview");
        assert_eq!(p.summary, "plan: +2 ~0 -1");
        assert!(
            p.lines
                .iter()
                .any(|l| l.contains("1 resource(s) will be DESTROYED")),
            "{:?}",
            p.lines
        );
    }

    #[test]
    fn a_plan_that_destroys_nothing_says_nothing_about_destruction() {
        let tmp = TempTree::new("tf-safe");
        let bin = stub(tmp.path(), "faketf", DESTROYS_NOTHING, 0);

        let p = terraform_preview(bin.to_str().expect("utf-8 path"), false)
            .expect("a successful plan is a preview");
        assert_eq!(p.summary, "plan: +1 ~0 -0");
        assert!(
            !p.lines.iter().any(|l| l.contains("DESTROYED")),
            "a warning about zero resources is noise: {:?}",
            p.lines
        );
    }

    #[test]
    fn a_plan_that_failed_is_not_read_at_all() {
        // Valid-looking output on a non-zero exit: an uninitialised directory
        // prints plenty. Best effort means staying silent, not guessing.
        let tmp = TempTree::new("tf-failed");
        let bin = stub(tmp.path(), "faketf", DESTROYS_ONE, 1);

        assert!(terraform_preview(bin.to_str().expect("utf-8 path"), false).is_none());
    }

    #[test]
    fn both_apply_and_destroy_reach_the_planner() {
        // PATH is process-global, so this takes the environment lock. The
        // binary name is fixed in the source, which is why the stub has to be
        // found the way the real one would be.
        let env = TestEnv::new("tf-path");
        let bin_dir = env.root().join("bin");
        stub(&bin_dir, "terraform", DESTROYS_ONE, 0);

        let previous = std::env::var_os("PATH");
        let combined = match &previous {
            Some(p) => format!("{}:{}", bin_dir.display(), p.to_string_lossy()),
            None => bin_dir.display().to_string(),
        };
        std::env::set_var("PATH", combined);

        // Both verbs are gated the same way; capture before restoring so a
        // failing assertion cannot leave PATH rewritten for the whole process.
        let apply = generate(
            "terraform apply -auto-approve",
            None,
            std::path::Path::new("."),
            true,
        );
        let destroy = generate("terraform destroy", None, std::path::Path::new("."), true);

        match previous {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }

        assert!(apply.is_some(), "`terraform apply` must be previewed");
        assert!(destroy.is_some(), "`terraform destroy` must be previewed");
        // `env` is still alive here, holding the lock across the restore.
        drop(env);
    }
}

#[cfg(test)]
mod live_gate_tests {
    use super::*;

    /// Roadmap 2.2. Deletes have had a blast-radius preview since v0.13;
    /// writes had none. `cat /dev/null > config.json` destroys a file as
    /// thoroughly as `rm config.json` and showed the human a bare verdict.
    #[test]
    fn an_overwrite_reports_what_the_file_loses() {
        let t = crate::testutil::TempTree::new("ov-preview");
        let dir = t.path();
        std::fs::write(dir.join("config.json"), "some existing content\n").unwrap();

        let pv = generate("cat /dev/null > config.json", None, dir, false)
            .expect("an overwrite of an existing file has a preview");
        assert_eq!(pv.title, "overwrite impact");
        let body = pv.lines.join("\n");
        assert!(body.contains("config.json"), "{body}");
        assert!(body.contains("loses"), "{body}");
        // And the insurance line agrees with what `backup::take` will do -
        // `plan` had no overwrite branch, so every preview of a write used to
        // say "NOT recoverable" while the backup was in fact taken.
        assert!(
            body.contains("insurance   :"),
            "an insured overwrite must not read as uninsured: {body}"
        );
        assert!(!pv.uninsurable, "this write IS insured");
    }

    /// Creating a file destroys nothing. A preview announcing it would be
    /// noise on ordinary work, which is how a gate gets ignored (#48).
    #[test]
    fn creating_a_file_has_nothing_to_preview() {
        let t = crate::testutil::TempTree::new("ov-create");
        let dir = t.path();
        assert!(
            generate("echo hi > brand-new.txt", None, dir, false).is_none(),
            "a write that creates has no blast radius"
        );
    }

    /// The roles from 2.1 carry through: a command's SOURCE is not losing
    /// anything, and reporting it would be the same false positive the path
    /// rules had (PR #27).
    #[test]
    fn a_source_is_not_reported_as_losing_content() {
        let t = crate::testutil::TempTree::new("ov-roles");
        let dir = t.path();
        std::fs::write(dir.join("src.txt"), "source content\n").unwrap();
        std::fs::write(dir.join("dst.txt"), "destination content\n").unwrap();

        let pv = generate("cp src.txt dst.txt", None, dir, false).expect("a preview");
        let body = pv.lines.join("\n");
        assert!(body.contains("dst.txt"), "the destination loses: {body}");
        assert!(
            !body.contains("src.txt"),
            "the source is only read and must not appear as at risk: {body}"
        );
    }

    /// Schipper review, finding 4, confirmed with a stub `terraform` on PATH:
    /// a DENIED `terraform destroy` still caused `terraform plan -destroy` to
    /// run in the agent's working directory. `hook::run` generates the preview
    /// before returning the decision, so denying is what made it worse — the
    /// more correctly the gate behaved, the more confidently it ran the plan.
    #[test]
    fn a_non_live_preview_spawns_nothing_for_terraform() {
        assert!(generate(
            "terraform destroy -auto-approve",
            None,
            std::path::Path::new("."),
            false
        )
        .is_none());
        assert!(generate("tofu destroy", None, std::path::Path::new("."), false).is_none());
    }

    /// Same structure, the other two subprocess previews.
    #[test]
    fn a_non_live_preview_spawns_nothing_for_git_push() {
        assert!(generate(
            "git push --force origin main",
            None,
            std::path::Path::new("."),
            false
        )
        .is_none());
    }

    /// The reason NOT to simply skip the preview on deny: static analysis is
    /// where the useful part of the denial message comes from. A denied
    /// `DROP TABLE` should still say which table, without connecting to the
    /// database it was just blocked from.
    #[test]
    fn a_non_live_preview_keeps_the_static_sql_analysis() {
        let p = generate(
            r#"psql -d shop -c "DROP TABLE users""#,
            None,
            std::path::Path::new("."),
            false,
        )
        .expect("static SQL analysis must still produce a preview");
        assert!(
            p.summary.contains("users"),
            "denial reason lost its detail: {}",
            p.summary
        );
    }

    /// A compound command is previewed by the first segment that has an
    /// answer, not by the whole string: `echo hi;psql -c "DROP TABLE users"`
    /// is not a psql command, but half of it is.
    #[test]
    fn a_compound_command_is_previewed_by_its_first_meaningful_segment() {
        let p = generate(
            r#"echo hi;psql -d shop -c "DROP TABLE users""#,
            None,
            std::path::Path::new("."),
            false,
        )
        .expect("the segment carrying a preview must be found");
        assert!(
            p.summary.contains("users"),
            "the segment's own analysis is what surfaces: {}",
            p.summary
        );
    }

    /// Deletes never spawned anything, so they are unaffected either way —
    /// asserted so a future refactor can't quietly gate them too.
    #[test]
    fn deletes_preview_identically_whether_live_or_not() {
        let live = generate(
            "rm -rf /tmp/tmx-none-such",
            None,
            std::path::Path::new("."),
            true,
        );
        let stat = generate(
            "rm -rf /tmp/tmx-none-such",
            None,
            std::path::Path::new("."),
            false,
        );
        assert_eq!(live.map(|p| p.summary), stat.map(|p| p.summary));
    }
}
