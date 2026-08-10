use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Ask,
    Deny,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Allow => write!(f, "allow"),
            Action::Ask => write!(f, "ask"),
            Action::Deny => write!(f, "deny"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Wildcard pattern matched against the normalized command string.
    /// `*` matches any run of characters. First matching rule wins.
    pub r#match: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notify {
    /// Slack-compatible incoming webhook URL (any endpoint accepting {"text": ...}).
    pub webhook: String,
    /// Which decisions trigger a notification. Default: deny only.
    #[serde(default = "default_notify_on")]
    pub on: Vec<String>,
}

fn default_notify_on() -> Vec<String> {
    vec!["deny".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u32,
    /// Action when no rule matches.
    #[serde(default = "default_action")]
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<Notify>,
}

fn default_version() -> u32 {
    1
}
fn default_action() -> Action {
    Action::Ask
}

fn severity(a: Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Ask => 1,
        Action::Deny => 2,
    }
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub matched_rule: Option<String>,
    pub reason: String,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy file {}", path.display()))?;
        let policy: Policy = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid policy YAML in {}", path.display()))?;
        Ok(policy)
    }

    /// The built-in starter policy, parsed from the embedded template that
    /// `init` writes. Used by `check` when no project `.termaxa/policy.yaml`
    /// exists, so evaluation works with zero setup. Read-only surfaces only —
    /// `run` and `hook` require an explicit project policy (decision #19).
    pub fn builtin() -> Result<Self> {
        serde_yaml::from_str(crate::init::STARTER_POLICY)
            .context("failed to parse built-in starter policy")
    }

    /// Walk up from `start` looking for `.termaxa/policy.yaml`.
    pub fn find_policy_file(start: &Path) -> Option<PathBuf> {
        let mut dir = Some(start.to_path_buf());
        while let Some(d) = dir {
            let candidate = d.join(".termaxa").join("policy.yaml");
            if candidate.is_file() {
                return Some(candidate);
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
        None
    }

    /// Shell-aware evaluation: split into segments, judge each, and let the
    /// MOST DANGEROUS segment govern the combined verdict (deny > ask > allow).
    /// Closes the v0.6.1 field-report bypass where `git status && <anything>`
    /// rode the `git status*` wildcard.
    pub fn evaluate_command(&self, command: &str) -> Decision {
        let segments = crate::shell::split_segments(command);
        if segments.len() <= 1 {
            return self.evaluate(command);
        }
        let total = segments.len();
        let mut worst: Option<(usize, Decision)> = None;
        for (i, seg) in segments.iter().enumerate() {
            let d = self.evaluate(seg);
            let replace = match &worst {
                None => true,
                // higher severity wins; on ties, an explicitly-matched rule
                // out-ranks a default fallthrough — name the real threat.
                Some((_, w)) => {
                    severity(d.action) > severity(w.action)
                        || (severity(d.action) == severity(w.action)
                            && w.matched_rule.is_none()
                            && d.matched_rule.is_some())
                }
            };
            if replace {
                worst = Some((i, d));
            }
        }
        let (i, d) = worst.expect("segments nonempty");
        Decision {
            action: d.action,
            matched_rule: d.matched_rule,
            reason: format!(
                "segment {}/{} `{}` — {}",
                i + 1,
                total,
                segments[i],
                d.reason
            ),
        }
    }

    pub fn evaluate(&self, command: &str) -> Decision {
        let cmd = normalize(command);
        for rule in &self.rules {
            if wildcard_match(&normalize(&rule.r#match), &cmd) {
                return Decision {
                    action: rule.action,
                    matched_rule: Some(rule.r#match.clone()),
                    reason: rule
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("matched rule `{}`", rule.r#match)),
                };
            }
        }
        Decision {
            action: self.default,
            matched_rule: None,
            reason: format!("no rule matched; policy default is `{}`", self.default),
        }
    }
}

/// Collapse whitespace runs to single spaces, trim, and lowercase.
/// Lowercasing makes matching case-insensitive: `DROP TABLE` must not
/// bypass a `drop table` rule.
pub fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Iterative wildcard match where `*` matches any (possibly empty) run of chars.
/// Case-sensitive. Linear-ish, no recursion, no regex dependency.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_basics() {
        assert!(wildcard_match("git push*", "git push"));
        assert!(wildcard_match("git push*", "git push origin main"));
        assert!(!wildcard_match("git push*", "git pull"));
        assert!(wildcard_match("*--force*", "git push --force origin"));
        assert!(wildcard_match("git status", "git status"));
        assert!(!wildcard_match("git status", "git status -s"));
        assert!(wildcard_match("*", "anything at all"));
    }

    #[test]
    fn first_match_wins() {
        let policy: Policy = serde_yaml::from_str(
            r#"
version: 1
default: ask
rules:
  - match: "git push*--force*"
    action: deny
  - match: "git push*"
    action: allow
"#,
        )
        .unwrap();
        assert_eq!(
            policy.evaluate("git push origin main").action,
            Action::Allow
        );
        assert_eq!(
            policy.evaluate("git push --force origin main").action,
            Action::Deny
        );
        assert_eq!(policy.evaluate("terraform apply").action, Action::Ask);
    }

    #[test]
    fn normalization() {
        let policy: Policy = serde_yaml::from_str(
            r#"
rules:
  - match: "kubectl delete*"
    action: deny
"#,
        )
        .unwrap();
        assert_eq!(
            policy.evaluate("kubectl   delete   pod x").action,
            Action::Deny
        );
    }

    #[test]
    fn case_insensitive() {
        let policy: Policy = serde_yaml::from_str(
            r#"
rules:
  - match: "*drop table*"
    action: deny
"#,
        )
        .unwrap();
        assert_eq!(
            policy.evaluate("psql -c 'DROP TABLE users'").action,
            Action::Deny
        );
    }

    #[test]
    fn compound_commands_cannot_hide_behind_prefixes() {
        // v0.6.1 field report: `git status && <anything>` rode `git status*`.
        let policy: Policy = serde_yaml::from_str(
            r#"
default: ask
rules:
  - match: "git status*"
    action: allow
  - match: "rm -rf /*"
    action: deny
"#,
        )
        .unwrap();
        // the trench-coat attack: worst segment governs
        let d = policy.evaluate_command("git status && rm -rf /");
        assert_eq!(d.action, Action::Deny);
        assert!(d.reason.contains("rm -rf /"));
        // benign compound with an unmatched segment falls to default (ask)
        assert_eq!(
            policy.evaluate_command("git status && echo hi").action,
            Action::Ask
        );
        // single commands behave exactly as before
        assert_eq!(policy.evaluate_command("git status").action, Action::Allow);
    }

    #[test]
    fn builtin_policy_parses_and_gates() {
        // The embedded starter policy must always parse (it backs `check`'s
        // zero-setup demo mode) and must classify the headline cases.
        let p = Policy::builtin().expect("built-in starter policy must parse");
        assert_eq!(p.evaluate_command("rm -rf /").action, Action::Deny);
        assert_eq!(
            p.evaluate_command("psql -c 'DROP TABLE users'").action,
            Action::Deny
        );
        assert_eq!(p.evaluate_command("git status").action, Action::Allow);
        assert_eq!(
            p.evaluate_command("git push --force origin main").action,
            Action::Deny
        );
    }

    #[test]
    fn the_starter_policy_defends_its_own_configuration() {
        let p = Policy::builtin().expect("built-in starter policy must parse");

        // The command from the review: `echo *` sat below the denies and
        // allowed this outright, and everything after it was judged by a
        // policy the agent had written.
        let d = p.evaluate_command("echo 'default: allow' > .termaxa/policy.yaml");
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.matched_rule.as_deref(), Some("*.termaxa*"));

        for cmd in [
            "cat /tmp/mine.yaml > .termaxa/policy.yaml",
            "rm -f .termaxa/policy.yaml",
            "sed -i 's/deny/allow/g' .termaxa/policy.yaml",
            "mv /tmp/mine.yaml .termaxa/policy.yaml",
            "copy C:\\tmp\\mine.yaml .termaxa\\policy.yaml",
            "echo '{}' > .claude/settings.json",
            "rm .cursor/hooks.json",
            "mv .codex/hooks.json /tmp/",
            "rm .github/hooks/hooks.json",
        ] {
            assert_eq!(
                p.evaluate_command(cmd).action,
                Action::Deny,
                "must not be able to edit the gate: {cmd}"
            );
        }

        // The self-defence block has to sit ABOVE the read-only allows, or
        // first-match-wins hands it back. Prove the ordering, not just the
        // verdict, by checking a command that both blocks match.
        let idx_self = p
            .rules
            .iter()
            .position(|r| r.r#match == "*.termaxa*")
            .expect("self-defence rule must exist");
        let idx_echo = p
            .rules
            .iter()
            .position(|r| r.r#match == "echo *")
            .expect("echo rule must exist");
        assert!(
            idx_self < idx_echo,
            "self-defence must be reachable: it sits at {idx_self}, `echo *` at {idx_echo}"
        );
    }

    #[test]
    fn reviewing_the_policy_in_a_pr_still_works() {
        let p = Policy::builtin().expect("built-in starter policy must parse");
        // The README calls the policy an in-repo artifact, "reviewable in
        // PRs". These are the commands that workflow is made of; a blanket
        // deny on `*.termaxa*` made every one of them impossible.
        for cmd in [
            "git add .termaxa/policy.yaml",
            "git diff .termaxa/policy.yaml",
            "git diff --cached .termaxa/policy.yaml",
            "git status .termaxa/",
            "git log --oneline .termaxa/policy.yaml",
            "git show HEAD:.termaxa/policy.yaml",
            "git commit -m \"tighten the policy\" .termaxa/policy.yaml",
            "cat .termaxa/policy.yaml",
            "cp .termaxa/policy.yaml backup.yaml",
            // One pattern covers both separators, same as the deny it excepts.
            "git diff .termaxa\\policy.yaml",
        ] {
            assert_eq!(
                p.evaluate_command(cmd).action,
                Action::Allow,
                "the documented review workflow must not be blocked: {cmd}"
            );
        }
    }

    #[test]
    fn the_review_exceptions_only_go_one_direction() {
        let p = Policy::builtin().expect("built-in starter policy must parse");
        // Every exception above the deny is a read. Anything that can put
        // bytes INTO the policy stays denied, including the git verbs whose
        // job is to overwrite the working tree from a ref.
        for cmd in [
            "git checkout .termaxa/policy.yaml",
            "git checkout evil-branch -- .termaxa/policy.yaml",
            "git restore .termaxa/policy.yaml",
            "git config core.hooksPath .termaxa/evil",
            "cp backup.yaml .termaxa/policy.yaml",
            "cat backup.yaml > .termaxa/policy.yaml",
            "tee .termaxa/policy.yaml",
        ] {
            assert_eq!(
                p.evaluate_command(cmd).action,
                Action::Deny,
                "writes into the gate's config must stay denied: {cmd}"
            );
        }
    }

    #[test]
    fn a_review_exception_cannot_shadow_the_hook_config_denies() {
        let p = Policy::builtin().expect("built-in starter policy must parse");
        // A trailing `*` swallows a redirect, so `cat .termaxa*` matches
        // `cat .termaxa/policy.yaml > .claude/settings.json` as well. At the
        // top of the file these allows would shadow the denies that exist to
        // stop exactly that. They sit below them instead.
        for cmd in [
            "cat .termaxa/policy.yaml > .claude/settings.json",
            "git diff .termaxa/policy.yaml > .claude/settings.json",
            "git add .termaxa/policy.yaml > .cursor/hooks.json",
            "cp .termaxa/policy.yaml .codex/hooks.json",
        ] {
            assert_eq!(
                p.evaluate_command(cmd).action,
                Action::Deny,
                "an exception must not become a way through: {cmd}"
            );
        }

        // Prove the ordering, not just the verdict.
        let idx = |pat: &str| {
            p.rules
                .iter()
                .position(|r| r.r#match == pat)
                .unwrap_or_else(|| panic!("rule `{pat}` must exist"))
        };
        assert!(
            idx("*.claude*settings*") < idx("cat .termaxa*"),
            "the hook-config denies must outrank the review exceptions"
        );
        assert!(
            idx("cat .termaxa*") < idx("*.termaxa*"),
            "the review exceptions must outrank the deny they except"
        );
    }

    #[test]
    fn no_preserve_root_is_denied_by_name() {
        let p = Policy::builtin().expect("built-in starter policy must parse");
        // GNU rm refuses a bare `rm -rf /`. This is the spelling it obeys,
        // and it does not contain the substring `rm -rf` that the famous
        // rule matches on.
        assert!(!"rm --no-preserve-root -rf /".contains("rm -rf"));
        for cmd in [
            "rm --no-preserve-root -rf /",
            "sudo rm --no-preserve-root -rf /",
            "rm -r --no-preserve-root /",
        ] {
            assert_eq!(p.evaluate_command(cmd).action, Action::Deny, "{cmd}");
        }
    }

    #[test]
    fn read_only_prefixes_do_not_swallow_neighbouring_commands() {
        let p = Policy::builtin().expect("built-in starter policy must parse");

        // Still allowed — including bare `ls`, which needs its own rule
        // because `ls *` requires the space.
        for cmd in ["ls", "ls -la src", "grep -rn fn src", "cat Cargo.toml"] {
            assert_eq!(p.evaluate_command(cmd).action, Action::Allow, "{cmd}");
        }

        // Different programs that merely start with the same letters. `ls*`
        // and `grep*` used to allow all of these.
        for cmd in ["lsof -i :5432", "lsblk", "lsattr -R /", "grepdiff --help"] {
            assert_ne!(
                p.evaluate_command(cmd).action,
                Action::Allow,
                "a prefix is not a command: {cmd}"
            );
        }
    }
}
