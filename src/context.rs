use crate::policy::{Action, Decision, DecisionSource};
use std::process::Command;

/// A signal the context engine noticed about the environment or the command.
#[derive(Debug, Clone)]
pub struct Signal {
    pub label: String,
    pub escalate: bool,
}

/// Gather cheap, local context signals. Never fails; absence of signal is fine.
pub fn gather(command: &str) -> Vec<Signal> {
    let mut signals = Vec::new();
    let cmd_lc = command.to_lowercase();

    // Git branch awareness: pushing/committing while on a protected branch.
    if cmd_lc.starts_with("git push") || cmd_lc.starts_with("git commit") {
        if let Some(branch) = current_git_branch() {
            let protected = matches!(
                branch.as_str(),
                "main" | "master" | "production" | "release"
            );
            signals.push(Signal {
                label: format!("current branch: {}", branch),
                escalate: protected && cmd_lc.starts_with("git push"),
            });
        }
    }

    // Force / destructive flags.
    for flag in ["--force", "-f ", "--hard", "--no-verify", "-rf"] {
        if cmd_lc.contains(flag) {
            signals.push(Signal {
                label: format!("destructive flag detected: {}", flag.trim()),
                escalate: true,
            });
        }
    }

    // Production markers in the command itself (connection strings, env names).
    for marker in ["prod", "production"] {
        if cmd_lc.contains(marker) && !cmd_lc.starts_with("git") {
            signals.push(Signal {
                label: format!("possible production target: contains `{}`", marker),
                escalate: true,
            });
            break;
        }
    }

    // SQL red flags.
    for stmt in ["drop table", "drop database", "truncate ", "delete from"] {
        if cmd_lc.contains(stmt) {
            signals.push(Signal {
                label: format!("destructive SQL: `{}`", stmt.trim()),
                escalate: true,
            });
        }
    }

    // Command substitution: contents cannot be statically analyzed, so the
    // presence alone is a reason to put a human in the loop.
    if crate::shell::has_substitution(command) {
        signals.push(Signal {
            label: "command substitution ($(...) or ``) — contents not analyzable".into(),
            escalate: true,
        });
    }

    signals
}

/// Escalation ladder: allow -> ask. `ask` and `deny` are never escalated further
/// (a human is already in the loop, or it's already blocked), and context never
/// downgrades a decision.
/// Uninsurability AMPLIFIES an existing concern; it never creates one.
///
/// Roadmap 2.5. The preview has known since v0.13 whether a command destroys
/// something the backup engine cannot copy aside first, and nothing could act
/// on it - the strongest unused signal in the product.
///
/// The rule is `uninsurable + Ask -> Deny`, NOT `uninsurable -> Deny`, and the
/// difference is the whole design. Measured on a realistic tree before writing
/// this: `rm -rf node_modules` (9,330 files) exceeds the 5,000-file copy
/// budget and reads as uninsurable. It is also the most routine destructive
/// command in JavaScript work, and it destroys nothing that `npm install`
/// cannot rebuild. A gate that denies it out of the box gets uninstalled, and
/// the user who uninstalls it loses protection against the commands that
/// actually matter (#48).
///
/// So uninsurability is a risk AMPLIFIER, not a risk signal. Something else -
/// a policy rule, a context signal, the default - has to have already said
/// "this is worth stopping for". Then uninsurability decides whether asking is
/// safe, because an ask a human approves on a command with no net is a
/// decision made without the fact that matters most.
///
/// This also means no regenerable-directory heuristic is needed. The existing
/// signals establish concern; `rm -rf ~/Documents` is already Ask because it
/// resolves to a user profile, and becomes Deny here. `rm -rf node_modules`
/// has no other concern and keeps whatever verdict it had.
pub fn apply_insurance(decision: Decision, uninsurable: bool) -> (Decision, bool) {
    // The amplifier may STRENGTHEN an existing safety concern; it does not
    // create one from an otherwise-unmatched command.
    //
    // `DecisionSource::Default` is the absence of an opinion, not a weak
    // opinion, and the two are semantically different rather than different
    // strengths of the same thing. Without this clause, a `default: ask`
    // policy - which the starter policy is - turned every unmatched
    // uninsurable command into a deny, including `rm -r node_modules`. That
    // is `uninsurable -> deny` under another name, and it is the posture this
    // design exists to avoid (#48).
    let concerned = decision.source != DecisionSource::Default;
    if uninsurable && concerned && decision.action == Action::Ask {
        return (
            Decision {
                action: Action::Deny,
                source: decision.source,
                matched_rule: decision.matched_rule,
                reason: format!(
                    "{} — and nothing can be recovered afterwards, so this is \
                     refused rather than asked",
                    decision.reason
                ),
            },
            true,
        );
    }
    (decision, false)
}

pub fn apply(decision: Decision, signals: &[Signal]) -> (Decision, bool) {
    let should_escalate = signals.iter().any(|s| s.escalate);
    if should_escalate && decision.action == Action::Allow {
        let labels: Vec<&str> = signals
            .iter()
            .filter(|s| s.escalate)
            .map(|s| s.label.as_str())
            .collect();
        return (
            Decision {
                action: Action::Ask,
                // A context signal CHOSE this ask; it is not the absence of
                // an opinion. That distinction is what lets the insurance
                // amplifier fire here but not on an unmatched command.
                source: DecisionSource::Context,
                matched_rule: decision.matched_rule,
                reason: format!(
                    "{} — escalated to ask by context: {}",
                    decision.reason,
                    labels.join("; ")
                ),
            },
            true,
        );
    }
    (decision, false)
}

fn current_git_branch() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if branch.is_empty() {
        None
    } else {
        Some(branch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(action: Action, source: DecisionSource) -> Decision {
        Decision {
            action,
            source,
            matched_rule: None,
            reason: "because".into(),
        }
    }

    /// THE PRECEDENCE, pinned in every direction so it cannot be misread.
    ///
    /// The amplifier may STRENGTHEN an existing safety concern; it does not
    /// create one from an otherwise-unmatched command.
    ///
    /// Measured before this was written: `rm -rf node_modules` (9,330 files)
    /// exceeds the 5,000-file copy budget and reads as uninsurable. It is
    /// also routine, and destroys nothing `npm install` cannot rebuild. The
    /// first draft fired on any Ask, which under a `default: ask` policy
    /// denied it - `uninsurable -> deny` under another name (#48).
    #[test]
    fn uninsurability_strengthens_a_concern_and_never_invents_one() {
        // 1. Unmatched + default Ask + uninsurable -> Ask.
        //    `rm -r node_modules`. The default is the ABSENCE of an opinion,
        //    not a weak one, and nothing has said this is worth stopping for.
        let (d, esc) = apply_insurance(dec(Action::Ask, DecisionSource::Default), true);
        assert_eq!(
            d.action,
            Action::Ask,
            "an unmatched command is not a concern"
        );
        assert!(!esc);

        // 2. Explicit Ask + uninsurable -> Deny. A rule chose to stop here;
        //    uninsurability says asking is not safe, because a human
        //    approving a command with no net decides without the fact that
        //    matters most.
        let (d, esc) = apply_insurance(dec(Action::Ask, DecisionSource::ExplicitRule), true);
        assert_eq!(d.action, Action::Deny);
        assert!(esc, "the escalation must be reported, not silent");
        assert!(
            d.reason.contains("nothing can be recovered"),
            "{}",
            d.reason
        );

        // 3. Context-escalated Ask + uninsurable -> Deny. `rm -rf ~/Documents`
        //    is Ask because it resolves to a user profile - a signal, not a
        //    shrug.
        let (d, esc) = apply_insurance(dec(Action::Ask, DecisionSource::Context), true);
        assert_eq!(d.action, Action::Deny);
        assert!(esc);

        // 4. Explicit Allow + uninsurable -> Allow. The escape hatch holds:
        //    an operator who wrote the rule outranks the amplifier.
        for src in [DecisionSource::ExplicitRule, DecisionSource::Context] {
            let (d, esc) = apply_insurance(dec(Action::Allow, src), true);
            assert_eq!(d.action, Action::Allow, "an explicit allow is unchanged");
            assert!(!esc);
        }

        // 5. Existing Deny + uninsurable -> Deny, and NOT re-escalated: a
        //    second amplification would double the reason and claim a change
        //    that did not happen.
        let base = dec(Action::Deny, DecisionSource::ExplicitRule);
        let (d, esc) = apply_insurance(base.clone(), true);
        assert_eq!(d.action, Action::Deny);
        assert!(!esc);
        assert_eq!(d.reason, base.reason, "an existing deny is left alone");

        // CONTROL LEG: with insurance available, nothing moves at all - so a
        // failure above is about the amplifier, not about the plumbing.
        for src in [
            DecisionSource::Default,
            DecisionSource::ExplicitRule,
            DecisionSource::Context,
        ] {
            for act in [Action::Allow, Action::Ask, Action::Deny] {
                let (d, esc) = apply_insurance(dec(act, src), false);
                assert_eq!(d.action, act, "insured commands are untouched");
                assert!(!esc);
            }
        }
    }

    use crate::testutil::TestEnv;
    use std::path::{Path, PathBuf};

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git must be available: branch awareness is what is under test");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A repo with one commit, sitting on `branch`, with the process moved
    /// into it — `current_git_branch` reads the cwd, so the branch has to be
    /// real rather than mocked.
    fn repo_on_branch(env: &mut TestEnv, branch: &str) -> PathBuf {
        let dir = env.root().join("repo");
        std::fs::create_dir_all(&dir).expect("repo dir must be creatable");
        git(&dir, &["init", "-q"]);
        git(
            &dir,
            &[
                "-c",
                "user.email=tests@termaxa.invalid",
                "-c",
                "user.name=termaxa tests",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-q",
                "-m",
                "root",
            ],
        );
        git(&dir, &["checkout", "-q", "-B", branch]);
        env.chdir(&dir);
        dir
    }

    fn branch_signal(signals: &[Signal]) -> Signal {
        signals
            .iter()
            .find(|s| s.label.starts_with("current branch:"))
            .cloned()
            .expect("a git command in a repo should report the branch it is on")
    }

    #[test]
    fn committing_reports_the_branch_without_escalating() {
        let mut env = TestEnv::new("ctx-commit");
        repo_on_branch(&mut env, "main");

        let signal = branch_signal(&gather("git commit -m wip"));
        assert_eq!(signal.label, "current branch: main");
        // Being on main is worth showing; a commit is local and reversible,
        // so it is not worth stopping for.
        assert!(!signal.escalate, "a commit on main must not escalate");
    }

    #[test]
    fn pushing_to_a_protected_branch_escalates() {
        let mut env = TestEnv::new("ctx-push-main");
        repo_on_branch(&mut env, "main");

        let signal = branch_signal(&gather("git push origin main"));
        assert_eq!(signal.label, "current branch: main");
        assert!(
            signal.escalate,
            "a push to main is the case this exists for"
        );
    }

    #[test]
    fn pushing_from_a_feature_branch_does_not_escalate() {
        let mut env = TestEnv::new("ctx-push-feature");
        repo_on_branch(&mut env, "feature/widgets");

        let signal = branch_signal(&gather("git push origin feature/widgets"));
        assert_eq!(signal.label, "current branch: feature/widgets");
        assert!(
            !signal.escalate,
            "only the protected branches make a push notable"
        );
    }

    #[test]
    fn a_production_marker_is_flagged_on_a_non_git_command() {
        let signals = gather("psql -h prod-db.internal -c 'select 1'");
        let prod = signals
            .iter()
            .find(|s| s.label.contains("possible production target"))
            .expect("`prod` in a connection string is the whole point of this check");
        assert!(prod.escalate);
    }

    #[test]
    fn git_commands_are_exempt_from_the_production_marker() {
        // Branch and remote names carry `production` constantly; flagging
        // every one of them would train the human to click through.
        let signals = gather("git push origin production");
        assert!(
            !signals
                .iter()
                .any(|s| s.label.contains("possible production target")),
            "a git ref named production is not a production target"
        );
    }

    #[test]
    fn an_ordinary_command_produces_no_signals_at_all() {
        assert!(
            gather("ls -la").is_empty(),
            "a listing is not worth a signal"
        );
    }

    #[test]
    fn destructive_sql_and_flags_are_flagged() {
        let signals = gather("psql -c \"TRUNCATE users\"");
        assert!(signals
            .iter()
            .any(|s| s.label.contains("destructive SQL") && s.escalate));

        let signals = gather("rm -rf build");
        assert!(signals
            .iter()
            .any(|s| s.label.contains("destructive flag") && s.escalate));
    }

    #[test]
    fn command_substitution_is_flagged_because_it_cannot_be_read() {
        let signals = gather("echo $(cat /etc/passwd)");
        assert!(signals
            .iter()
            .any(|s| s.label.contains("command substitution") && s.escalate));
    }

    fn decision(action: Action) -> Decision {
        Decision {
            action,
            source: DecisionSource::ExplicitRule,
            matched_rule: Some("rule".into()),
            reason: "base".into(),
        }
    }

    fn escalating() -> Vec<Signal> {
        vec![Signal {
            label: "destructive flag detected: --force".into(),
            escalate: true,
        }]
    }

    #[test]
    fn context_escalates_allow_to_ask_and_says_why() {
        let (out, escalated) = apply(decision(Action::Allow), &escalating());
        assert_eq!(out.action, Action::Ask);
        assert!(escalated);
        assert!(
            out.reason.contains("base") && out.reason.contains("--force"),
            "the reason must keep the rule's own words and add the signal: {}",
            out.reason
        );
        assert_eq!(
            out.matched_rule,
            Some("rule".into()),
            "escalation does not change which rule matched"
        );
    }

    #[test]
    fn context_never_downgrades_a_decision() {
        // A deny that a signal could soften would be a gate with a bypass.
        let (out, escalated) = apply(decision(Action::Deny), &escalating());
        assert_eq!(out.action, Action::Deny);
        assert!(!escalated);

        let (out, escalated) = apply(decision(Action::Ask), &escalating());
        assert_eq!(out.action, Action::Ask);
        assert!(!escalated);
    }

    #[test]
    fn a_non_escalating_signal_leaves_allow_alone() {
        let noted = vec![Signal {
            label: "current branch: main".into(),
            escalate: false,
        }];
        let (out, escalated) = apply(decision(Action::Allow), &noted);
        assert_eq!(out.action, Action::Allow);
        assert!(!escalated);
        assert_eq!(out.reason, "base", "an untouched decision keeps its reason");
    }
}
