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

    /// Walk up from `start` looking for `.aegis/policy.yaml`.
    pub fn find_policy_file(start: &Path) -> Option<PathBuf> {
        let mut dir = Some(start.to_path_buf());
        while let Some(d) = dir {
            let candidate = d.join(".aegis").join("policy.yaml");
            if candidate.is_file() {
                return Some(candidate);
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }
        None
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
        assert_eq!(policy.evaluate("git push origin main").action, Action::Allow);
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
}
