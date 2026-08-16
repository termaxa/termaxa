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
    /// Wildcard pattern matched against the normalized command STRING.
    /// `*` matches any run of characters. First matching rule wins.
    ///
    /// Optional since v0.16, because a rule that matches on resolved paths
    /// should not have to carry a string pattern it does not mean. Forcing
    /// one produced a live over-blocking bug: the shipped `.env` path rule
    /// carried `match: "*.env*"` purely to satisfy the schema, and that
    /// pattern fired on its own - `cat .env`, `grep KEY .env`,
    /// `git diff .env` and even `vim .env.sample` were all DENIED. Reading a
    /// file is ordinary work, and a gate that denies ordinary work gets
    /// uninstalled (#48).
    ///
    /// See `validate` for the invariant that replaced "always present".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#match: Option<String>,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Match this rule as written instead of case-insensitively.
    ///
    /// EXPLICIT, defaulting to false, and never inferred from the pattern's
    /// spelling. The first draft inferred it from the presence of an
    /// uppercase letter, which silently made `*Remove-Item*-Recurse*`
    /// case-sensitive and let `remove-item -recurse` walk past a deny that
    /// has shipped since v0.11 — the release's own bug class (reading intent
    /// out of spelling) applied to the rule text itself.
    #[serde(default, skip_serializing_if = "is_false")]
    pub case_sensitive: bool,
    /// Match this rule against the command's RESOLVED targets rather than
    /// against the command string.
    ///
    /// Roadmap 2.4. `> ./.env` and `> .env` are the same file and different
    /// strings, so a `match:` rule naming one misses the other - the gap
    /// pinned in known-limitations 0.2. A `match_path:` rule is matched
    /// against each target after resolution, so both spellings reach it.
    ///
    /// A rule may carry both fields. `match:` is required by the schema and
    /// stays the rule's identity in reason lines and audit entries; when
    /// `match_path:` is present, the rule fires if EITHER matches - the string
    /// reading can only add matches, never remove them, which is the same
    /// promise the extra readings make.
    ///
    /// ANY target matching fires the rule, and the reason names WHICH one. A
    /// command with several targets is one command, and a human deciding
    /// whether to approve it needs to know which path tripped the gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_path: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Rule {
    /// Does this rule match one reading of a command?
    ///
    /// A rule matches case-insensitively, as it always has: `drop table`
    /// still catches `DROP TABLE`, and an uppercase SPELLING changes nothing
    /// (`*Remove-Item*` still catches `remove-item`). A rule that opted in
    /// with `case_sensitive: true` is matched as written against the
    /// case-preserved reading, so `git branch*-D*` can mean `-D` and not
    /// `-d`. The field decides; the spelling never does.
    /// Does this rule's `match_path` pattern match a resolved target?
    ///
    /// Matched COMPONENT BY COMPONENT, not as a string glob. `*/.env` means
    /// "a path whose last component is `.env`", and it matches
    /// `/tmp/proj/.env`, `C:\\proj\\.env` and a bare `.env` alike.
    ///
    /// This is deliberately NOT `wildcard_match` over the path string, which
    /// is what the first draft did and which was wrong three ways at once:
    /// `*/.env` missed a target that resolved to a bare `.env` (no separator
    /// to match), missed `C:\\proj\\.env` (backslashes are not `/`), and
    /// would have matched `prod.env` if the pattern were loosened to `*.env`
    /// to compensate. A path is a sequence of components, and a glob over its
    /// printed form is still string thinking - the exact confusion this whole
    /// change exists to end.
    ///
    /// Splitting reuses `protect::segments`, so the command path and the
    /// write path cannot come to disagree about what a component is (#37).
    /// Each component is matched with the same wildcard engine, so
    /// `*/node_modules/*` and `*/.ssh/id_*` read as expected.
    ///
    /// A leading `*` component means "at any depth", so `*/.env` matches
    /// `.env` at the root as well as nested. Without that, a policy author
    /// would have to write two rules for one file.
    pub fn matches_path(&self, path: &str) -> bool {
        let Some(pattern) = &self.match_path else {
            return false;
        };
        let pat: Vec<String> = crate::protect::segments(pattern);
        let seg: Vec<String> = crate::protect::segments(path);
        match_components(&pat, &seg)
    }

    /// Does this rule's STRING pattern match a reading? A rule with no
    /// `match:` matches no string - it speaks only about paths, and saying
    /// otherwise is how the over-blocking bug happened.
    pub fn matches(&self, reading: &str) -> bool {
        let Some(pattern) = &self.r#match else {
            return false;
        };
        if self.case_sensitive {
            wildcard_match(&collapse(pattern), reading)
        } else {
            wildcard_match(&normalize(pattern), reading)
        }
    }

    /// How this rule is named in reason lines and audit entries. A rule
    /// always has at least one matcher (see `Policy::validate`), so there is
    /// always something to name.
    pub fn label(&self) -> String {
        match (&self.r#match, &self.match_path) {
            (Some(m), _) => m.clone(),
            (None, Some(p)) => format!("path:{p}"),
            // Unreachable: validation rejects a rule with neither.
            (None, None) => "<no matcher>".to_string(),
        }
    }
}

/// Collapse whitespace without touching case.
pub fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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

/// Every path this segment touches, resolved once: the redirect targets the
/// splitter already found, plus whatever the delete extractor recognises.
///
/// Two sources rather than one because they answer different questions -
/// `> .env` names a file the command WRITES, `rm .env` names one it DELETES -
/// and a gate that reads only one of them has a hole shaped like the other.
fn resolved_targets(
    segment: &str,
    ctx: &crate::resolve::EvalContext,
) -> Vec<crate::resolve::ResolvedTarget> {
    crate::resolve::command_targets(segment, ctx)
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy file {}", path.display()))?;
        let policy: Policy = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid policy YAML in {}", path.display()))?;
        policy
            .validate()
            .with_context(|| format!("invalid policy in {}", path.display()))?;
        Ok(policy)
    }

    /// THE MATCHER INVARIANT: a rule must carry at least one matcher, and
    /// neither is individually mandatory.
    ///
    ///     match: "git rm *"                        valid
    ///     match_path: "*/.ssh/*"                   valid
    ///     match: "git *" + match_path: "*/.ssh/*"  valid, both apply
    ///     neither                                  INVALID
    ///
    /// This replaces "`match` is always present", which was enforced by the
    /// type system and was the wrong rule: it forced path rules to invent a
    /// string pattern, and an invented pattern still fires. A rule with no
    /// matcher at all would silently never fire, which is worse than a parse
    /// error - a policy author would believe they were protected.
    ///
    /// Checked at both parse entry points rather than at evaluation, so an
    /// unfirable rule cannot reach a decision.
    pub fn validate(&self) -> Result<()> {
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.r#match.is_none() && rule.match_path.is_none() {
                anyhow::bail!(
                    "rule {} has neither `match:` nor `match_path:` - a rule with no \
                     matcher can never fire, so it is a policy that says nothing while \
                     looking like it says something (action: {:?})",
                    i + 1,
                    rule.action
                );
            }
        }
        Ok(())
    }

    /// The built-in starter policy, parsed from the embedded template that
    /// `init` writes. Used by `check` when no project `.termaxa/policy.yaml`
    /// exists, so evaluation works with zero setup. Read-only surfaces only —
    /// `run` and `hook` require an explicit project policy (decision #19).
    pub fn builtin() -> Result<Self> {
        let policy: Policy = serde_yaml::from_str(crate::init::STARTER_POLICY)
            .context("failed to parse built-in starter policy")?;
        policy
            .validate()
            .context("built-in starter policy violates the matcher invariant")?;
        Ok(policy)
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
    pub fn evaluate_command(&self, command: &str, ctx: &crate::resolve::EvalContext) -> Decision {
        let segments = crate::shell::split_segments(command);
        if segments.len() <= 1 {
            return self.evaluate(command, ctx);
        }
        let total = segments.len();
        let mut worst: Option<(usize, Decision)> = None;
        for (i, seg) in segments.iter().enumerate() {
            let d = self.evaluate(seg, ctx);
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

    pub fn evaluate(&self, command: &str, ctx: &crate::resolve::EvalContext) -> Decision {
        // First-match PER READING, MOST SEVERE across readings, earliest rule
        // on ties. See `readings` for what the readings are.
        //
        // Not "first rule matching any reading": post-#16 the policy pattern
        // for exceptions is an anchored allow ABOVE the deny it excepts, and
        // under any-reading matching a quoted spelling could reach the
        // exception through the tokenized reading while the raw reading sat
        // on the deny below it. Severity-across-readings makes that case fail
        // CLOSED instead: a spelling only some readings recognise as the
        // excepted command gets the deny, loudly — the same call #16 made for
        // unlisted reads. The cost, stated: quoted spellings of excepted
        // commands (`"cat" .termaxa/policy.yaml`) now deny where the plain
        // spelling still allows.
        let views = readings(command);
        let mut best: Option<(usize, &Rule)> = None;
        for v in &views {
            if let Some((idx, rule)) = self.rules.iter().enumerate().find(|(_, r)| r.matches(v)) {
                best = Some(match best {
                    None => (idx, rule),
                    Some((bi, br)) => {
                        if severity(rule.action) > severity(br.action)
                            || (severity(rule.action) == severity(br.action) && idx < bi)
                        {
                            (idx, rule)
                        } else {
                            (bi, br)
                        }
                    }
                });
            }
        }
        // Roadmap 2.4: the same rules, matched against what the command
        // actually TOUCHES rather than how it was spelled. Resolution happens
        // once per segment and is reused by both checks below.
        let targets = resolved_targets(command, ctx);

        // A `match_path` rule fires if ANY target matches, and the reason
        // names which one: a command with several targets is one command, and
        // the human approving it needs to know which path tripped the gate.
        let mut path_hit: Option<(usize, &Rule, String, crate::resolve::TargetRole)> = None;
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.match_path.is_none() {
                continue;
            }
            for t in &targets {
                // A path rule protects a file from being CHANGED, so it looks
                // only at roles that change one. `cp .env backup.txt` reads
                // .env and leaves it exactly as it was; denying that is the
                // same false positive the `*.env*` string pattern produced,
                // arriving through a new door (PR #27). `mv .env dst` DOES
                // fire, because a move removes its source - which is the
                // whole reason the extractor reports roles rather than a
                // flat list of paths.
                if !t.role.is_destructive() {
                    continue;
                }
                let Some(p) = &t.resolved else { continue };
                if rule.matches_path(&p.display().to_string()) {
                    let better = match &path_hit {
                        None => true,
                        Some((bi, br, _, _)) => {
                            severity(rule.action) > severity(br.action)
                                || (severity(rule.action) == severity(br.action) && idx < *bi)
                        }
                    };
                    if better {
                        path_hit = Some((idx, rule, t.display(), t.role));
                    }
                    break;
                }
            }
        }

        // An unresolved target carrying a sensitive shape fails closed. NOT a
        // short-circuit: it enters the same most-severe-wins tournament as
        // everything else, so an explicit allow above it still wins, which is
        // the escape hatch every other rule already has. One decision path,
        // not two.
        let shape_deny = targets
            .iter()
            .find(|t| t.is_unresolved() && !t.shapes.is_empty());

        match (path_hit, shape_deny) {
            (Some((_, rule, target, role)), _) if rule.action == Action::Deny => {
                return Decision {
                    action: rule.action,
                    matched_rule: Some(rule.label()),
                    // The role is in the sentence, not just in the type. A
                    // move that reported "overwriting .env" was correct in
                    // its verdict and wrong in its explanation: `mv` does not
                    // overwrite the source, it REMOVES it. The rule's reason
                    // is written for one case; the role says which case this
                    // actually is, and a human approving a prompt should not
                    // have to know that the two can differ.
                    reason: format!(
                        "target `{}` ({}) — {}",
                        target,
                        role.effect(),
                        rule.reason.clone().unwrap_or_else(|| format!(
                            "matched path rule `{}`",
                            rule.match_path.clone().unwrap_or_default()
                        ))
                    ),
                };
            }
            (_, Some(t)) => {
                let why = t
                    .shapes
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                // Only fails closed when it is WORSE than what the string
                // rules concluded - an explicit allow is still an allow.
                let base_sev = best
                    .map(|(_, r)| severity(r.action))
                    .unwrap_or_else(|| severity(self.default));
                if base_sev < severity(Action::Deny) && base_sev > severity(Action::Allow) {
                    return Decision {
                        action: Action::Deny,
                        matched_rule: None,
                        reason: format!(
                            "target `{}` cannot be resolved and {} — refusing rather than \
                             guessing what it points at",
                            t.as_written, why
                        ),
                    };
                }
            }
            _ => {}
        }

        match best {
            Some((_, rule)) => Decision {
                action: rule.action,
                matched_rule: Some(rule.label()),
                reason: rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("matched rule `{}`", rule.label())),
            },
            None => Decision {
                action: self.default,
                matched_rule: None,
                reason: format!("no rule matched; policy default is `{}`", self.default),
            },
        }
    }
}

/// The forms of a command a rule is matched against.
///
/// v0.15. Until now there was one: whitespace-collapsed and lowercased. Two
/// separate bugs came out of that single reading.
///
/// **Quotes.** `normalize` leaves them in, so `"rm" -rf /` missed the
/// `rm -rf /*` deny rule while the intent classifier — which tokenizes, and so
/// strips them — correctly called it a file delete. The layer that understood
/// the command was not the layer that blocked it. Same for `rm -r''f /`.
///
/// **Case.** `evaluate` lowercased the RULE as well as the command, so
/// `git branch -D` and `git branch -d` were both `git branch -d` before
/// `wildcard_match` ever ran. The distinction was destroyed at parse time, and
/// no amount of comparing forms at the match site could recover it. A rule
/// could not mean `-D` even if it spelled it.
///
/// So: three readings, and a rule matching ANY of them applies.
///
/// 1. `normalize` — whitespace-collapsed, lowercased. What we always had.
/// 2. tokenized-and-rejoined, lowercased — quotes gone, so disguises fail.
/// 3. tokenized-and-rejoined, CASE PRESERVED — so a rule that spells `-D`
///    in capitals means it.
///
/// This is strictly a widening: every rule that matched before still matches,
/// because reading 1 is unchanged. It can only make the gate more severe.
///
/// Reported by Tim Schipper.
pub fn readings(command: &str) -> Vec<String> {
    let base = normalize(command);
    let toks = crate::intent::tokens(command).join(" ");
    let cased = toks.split_whitespace().collect::<Vec<_>>().join(" ");
    let lowered = cased.to_lowercase();

    let mut out = vec![base];
    if !out.contains(&lowered) {
        out.push(lowered);
    }
    if !out.contains(&cased) {
        out.push(cased);
    }
    out
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
/// Match a component pattern against a component path.
///
/// `*` as a WHOLE component means "any run of components, including none" -
/// the `**` of most glob languages, spelled `*` because a path rule is always
/// about paths and the two-star distinction buys nothing here. A `*` INSIDE a
/// component (`id_*`, `*.log`) matches within that component only, and never
/// across a separator.
fn match_components(pat: &[String], seg: &[String]) -> bool {
    match pat.split_first() {
        // Pattern exhausted: matches only if the path is too.
        None => seg.is_empty(),
        Some((head, rest)) if head == "*" => {
            // Try consuming zero, one, two ... components here.
            (0..=seg.len()).any(|skip| match_components(rest, &seg[skip..]))
        }
        Some((head, rest)) => match seg.split_first() {
            None => false,
            Some((s, srest)) => wildcard_match(head, s) && match_components(rest, srest),
        },
    }
}

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
mod schema_and_severity_tests {
    use super::*;

    /// Evaluation context for tests: the current directory as both cwd and
    /// root. No test here depends on resolution, which is the point - this
    /// commit changed no verdicts.
    fn here() -> crate::resolve::EvalContext {
        crate::resolve::EvalContext::at(std::path::Path::new("."))
    }

    fn policy_from(yaml: &str) -> Policy {
        serde_yaml::from_str(yaml).expect("policy must parse")
    }

    #[test]
    fn an_omitted_field_gets_the_documented_default() {
        let minimal = policy_from("default: ask\nrules: []\n");
        assert_eq!(minimal.version, 1, "version 1 is the current schema");

        let notifying = policy_from(
            "default: ask\nrules: []\nnotify:\n  webhook: https://example.invalid/hook\n",
        );
        assert_eq!(
            notifying.notify.expect("the notify block must parse").on,
            ["deny"],
            "notifying on every decision trains the reader to ignore them"
        );
    }

    #[test]
    fn case_sensitivity_is_written_out_only_when_it_was_asked_for() {
        let plain = Rule {
            r#match: Some("ls*".into()),
            action: Action::Allow,
            reason: None,
            case_sensitive: false,
            match_path: None,
        };
        let json = serde_json::to_string(&plain).expect("a rule must serialize");
        assert!(
            !json.contains("case_sensitive"),
            "the default must not clutter every rule: {json}"
        );

        let strict = Rule {
            r#match: Some("git branch -D*".into()),
            action: Action::Deny,
            reason: None,
            case_sensitive: true,
            match_path: None,
        };
        let json = serde_json::to_string(&strict).expect("a rule must serialize");
        assert!(
            json.contains("case_sensitive"),
            "an opt-in has to survive the round trip: {json}"
        );
    }

    #[test]
    fn the_readings_include_the_tokenized_form_a_quote_would_hide() {
        let views = readings(r#""rm" -rf /"#);
        assert!(
            views.contains(&r#""rm" -rf /"#.to_string()),
            "the raw reading is still there: {views:?}"
        );
        assert!(
            views.contains(&"rm -rf /".to_string()),
            "quotes must not hide a command from its rule: {views:?}"
        );
    }

    #[test]
    fn an_ordinary_command_is_not_read_twice() {
        // Nothing to strip and nothing to lower: one reading is enough, and a
        // duplicate would just be work.
        assert_eq!(readings("git status"), ["git status"]);
    }

    #[test]
    fn the_earliest_of_two_equally_severe_rules_is_the_one_reported() {
        // The quoted spelling matches rule 1; the tokenized reading matches
        // rule 2. Same severity, so first-match-wins has to survive there
        // being several readings.
        let p = policy_from(
            "default: allow\nrules:\n  - match: '\"rm\"*'\n    action: deny\n  \
             - match: \"rm -rf*\"\n    action: deny\n",
        );
        let d = p.evaluate(r#""rm" -rf /"#, &here());
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.matched_rule.as_deref(), Some("\"rm\"*"));
    }

    #[test]
    fn the_earliest_rule_still_wins_when_the_order_is_reversed() {
        // The mirror image, so "earliest" cannot be satisfied by accident of
        // which reading happens to be examined first.
        let p = policy_from(
            "default: allow\nrules:\n  - match: \"rm -rf*\"\n    action: deny\n  \
             - match: '\"rm\"*'\n    action: deny\n",
        );
        let d = p.evaluate(r#""rm" -rf /"#, &here());
        assert_eq!(d.matched_rule.as_deref(), Some("rm -rf*"));
    }

    #[test]
    fn a_spelling_only_one_reading_recognises_gets_the_worse_verdict() {
        // The documented cost of severity-across-readings: the raw reading
        // matches the allow, the tokenized reading matches the deny, and the
        // deny governs. This case fails CLOSED on purpose.
        let p = policy_from(
            "default: allow\nrules:\n  - match: '\"cat\"*'\n    action: allow\n  \
             - match: \"cat .termaxa*\"\n    action: deny\n",
        );
        let d = p.evaluate(r#""cat" .termaxa/policy.yaml"#, &here());
        assert_eq!(
            d.action,
            Action::Deny,
            "a spelling only some readings recognise must not reach the exception: {}",
            d.reason
        );
    }

    #[test]
    fn the_first_of_two_equally_dangerous_segments_is_the_one_named() {
        // Naming the later one would point the reader at the second-worst
        // thing in the command.
        let p = policy_from(
            "default: allow\nrules:\n  - match: \"rm -rf*\"\n    action: deny\n  \
             - match: \"drop table*\"\n    action: deny\n",
        );
        let d = p.evaluate_command("rm -rf /tmp/x && drop table users", &here());
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.matched_rule.as_deref(), Some("rm -rf*"));
        assert!(d.reason.contains("segment 1/2"), "{}", d.reason);
    }

    #[test]
    fn an_explicit_allow_never_outranks_a_more_dangerous_default() {
        // Segment 1 falls through to the `ask` default; segment 2 matches an
        // explicit allow. A matched rule breaks TIES between equally severe
        // segments — it does not lower the verdict.
        let p = policy_from("default: ask\nrules:\n  - match: \"ls*\"\n    action: allow\n");
        let d = p.evaluate_command("curl https://example.invalid/x | ls", &here());
        assert_eq!(
            d.action,
            Action::Ask,
            "the most dangerous segment governs: {}",
            d.reason
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evaluation context for tests: the current directory as both cwd and
    /// root. No test here depends on resolution, which is the point - this
    /// commit changed no verdicts.
    fn here() -> crate::resolve::EvalContext {
        crate::resolve::EvalContext::at(std::path::Path::new("."))
    }

    /// Schipper review round 2, finding 2. `intent::tokens` strips quotes and
    /// `policy::normalize` does not, so the classifier saw through disguises
    /// the gate could not. The layer that understood the command was not the
    /// layer that blocked it.
    #[test]
    fn quoting_cannot_disguise_a_command_from_a_rule() {
        let p = Policy::builtin().unwrap();
        for cmd in [
            r#""rm" -rf /"#,
            r#"rm -r''f /"#,
            r#""rm" "-rf" "/""#,
            r#"'rm' -rf /"#,
        ] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd} must not slip past the deny rule by quoting"
            );
        }
    }

    /// The case-preservation half. A lowercase rule stays case-insensitive; a
    /// rule with an uppercase letter is matched as written.
    #[test]
    fn a_lowercase_rule_still_matches_either_case() {
        let p = Policy::builtin().unwrap();
        // `*drop table*` is written lowercase, so it must catch both.
        assert_eq!(
            p.evaluate_command("psql -c \"DROP TABLE users\"", &here())
                .action,
            Action::Deny
        );
        assert_eq!(
            p.evaluate_command("psql -c \"drop table users\"", &here())
                .action,
            Action::Deny
        );
        // `*rm -rf*` likewise.
        assert_eq!(
            p.evaluate_command("rm -RF /tmp/x", &here()).action,
            Action::Deny
        );
    }

    /// Until v0.15 this was impossible: `evaluate` lowercased the rule as well
    /// as the command, so `-D` and `-d` were the same string before matching.
    /// The distinction is opted into with `case_sensitive: true`.
    #[test]
    fn a_case_sensitive_rule_means_the_case_it_spells() {
        let rule = Rule {
            r#match: Some("git branch*-D*".into()),
            action: Action::Deny,
            reason: None,
            case_sensitive: true,
            match_path: None,
        };
        let views_upper = readings("git branch -D main");
        let views_lower = readings("git branch -d main");

        assert!(
            views_upper.iter().any(|v| rule.matches(v)),
            "a case-sensitive rule spelling -D must match -D"
        );
        assert!(
            !views_lower.iter().any(|v| rule.matches(v)),
            "a case-sensitive rule spelling -D must NOT match -d — that was the bug"
        );
    }

    /// The collateral the first draft shipped, kept impossible: an uppercase
    /// SPELLING without the field changes nothing. `*Remove-Item*-Recurse*`
    /// has shipped case-insensitive since v0.11, PowerShell accepts any
    /// casing, and agents emit it.
    #[test]
    fn uppercase_spelled_rules_stay_case_insensitive_without_the_field() {
        let p = Policy::builtin().unwrap();
        for cmd in [
            "remove-item -recurse -force c:\\temp\\x",
            "REMOVE-ITEM -Recurse c:\\x",
            // NOTE: *Get-ChildItem*Remove-Item* is NOT here — it was already
            // unreachable in v0.14.2 (split_segments cuts pipelines at `|`,
            // so both words never share a segment). Reported separately.
            "remove-item -force c:\\x",
        ] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd} matched a deny in v0.14.2 and must keep matching"
            );
        }
        // And the starter policy opts in exactly once, on purpose.
        let cs: Vec<String> = p
            .rules
            .iter()
            .filter(|r| r.case_sensitive)
            .map(|r| r.label())
            .collect();
        assert_eq!(
            cs,
            vec!["git branch*-D*"],
            "case sensitivity is a deliberate, rare opt-in"
        );
    }

    /// Severity across readings, against the #16 exception block. A quoted
    /// spelling only the tokenized reading recognises as the excepted command
    /// fails CLOSED — the raw reading hits the `*.termaxa*` deny below the
    /// exception, and the more severe verdict governs. The plain spelling is
    /// untouched. Stated behavior change to the exception block, not a slip.
    #[test]
    fn a_quoted_spelling_of_an_excepted_command_fails_closed() {
        let p = Policy::builtin().unwrap();
        assert_eq!(
            p.evaluate_command("cat .termaxa/policy.yaml", &here())
                .action,
            Action::Allow,
            "the plain excepted read stays allowed"
        );
        assert_eq!(
            p.evaluate_command(r#""cat" .termaxa/policy.yaml"#, &here())
                .action,
            Action::Deny,
            "a disguised spelling of a .termaxa read fails closed, loudly"
        );
    }

    /// The whole change is a widening. Reading 1 is unchanged, so nothing that
    /// matched before can stop matching.
    #[test]
    fn the_extra_readings_can_only_add_matches() {
        for cmd in [
            "git status",
            "ls -la",
            "cargo build",
            "echo hello world",
            "git push --force origin main",
        ] {
            let base = normalize(cmd);
            assert!(
                readings(cmd).contains(&base),
                "the original normalized reading must always be present"
            );
        }
    }

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
            policy.evaluate("git push origin main", &here()).action,
            Action::Allow
        );
        assert_eq!(
            policy
                .evaluate("git push --force origin main", &here())
                .action,
            Action::Deny
        );
        assert_eq!(
            policy.evaluate("terraform apply", &here()).action,
            Action::Ask
        );
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
            policy.evaluate("kubectl   delete   pod x", &here()).action,
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
            policy
                .evaluate("psql -c 'DROP TABLE users'", &here())
                .action,
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
        let d = policy.evaluate_command("git status && rm -rf /", &here());
        assert_eq!(d.action, Action::Deny);
        assert!(d.reason.contains("rm -rf /"));
        // benign compound with an unmatched segment falls to default (ask)
        assert_eq!(
            policy
                .evaluate_command("git status && echo hi", &here())
                .action,
            Action::Ask
        );
        // single commands behave exactly as before
        assert_eq!(
            policy.evaluate_command("git status", &here()).action,
            Action::Allow
        );
    }

    #[test]
    fn builtin_policy_parses_and_gates() {
        // The embedded starter policy must always parse (it backs `check`'s
        // zero-setup demo mode) and must classify the headline cases.
        let p = Policy::builtin().expect("built-in starter policy must parse");
        assert_eq!(p.evaluate_command("rm -rf /", &here()).action, Action::Deny);
        assert_eq!(
            p.evaluate_command("psql -c 'DROP TABLE users'", &here())
                .action,
            Action::Deny
        );
        assert_eq!(
            p.evaluate_command("git status", &here()).action,
            Action::Allow
        );
        assert_eq!(
            p.evaluate_command("git push --force origin main", &here())
                .action,
            Action::Deny
        );
    }

    /// A rule that cannot be reached is not a rule. `*Get-ChildItem*Remove-Item*`
    /// shipped from v0.11 and could never fire: `split_segments` cuts at the
    /// `|`, so no segment ever contains both names. It was removed in v0.16
    /// rather than reworked, and this test records what the policy does with
    /// the pipeline instead, so its removal stays deliberate.
    ///
    /// A bare `Remove-Item` with no destructive flag is `ask`, exactly as
    /// `rm x` and `del x` are: deleting one named path is ordinary work, and a
    /// gate that denies it gets uninstalled (#48). The flagged spellings are
    /// still denied by the sibling rules, which DO fire, because each name and
    /// its flag live in the same segment.
    #[test]
    fn the_powershell_pipeline_is_asked_and_its_flagged_forms_denied() {
        let p = Policy::builtin().unwrap();
        for cmd in ["Get-ChildItem | Remove-Item", "Remove-Item x"] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Ask,
                "{cmd}: an unflagged delete is ordinary work"
            );
        }
        for cmd in [
            "Get-ChildItem . | Remove-Item -Force",
            "Get-ChildItem -Path x | Remove-Item -Recurse -Force",
            "Remove-Item -Recurse x",
        ] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd}: the flag is in the same segment as the name, so it fires"
            );
        }
    }

    #[test]
    fn the_starter_policy_defends_its_own_configuration() {
        let p = Policy::builtin().expect("built-in starter policy must parse");

        // The command from the review: `echo *` sat below the denies and
        // allowed this outright, and everything after it was judged by a
        // policy the agent had written.
        let d = p.evaluate_command("echo 'default: allow' > .termaxa/policy.yaml", &here());
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
                p.evaluate_command(cmd, &here()).action,
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
            .position(|r| r.label() == "*.termaxa*")
            .expect("self-defence rule must exist");
        let idx_echo = p
            .rules
            .iter()
            .position(|r| r.label() == "echo *")
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
                p.evaluate_command(cmd, &here()).action,
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
                p.evaluate_command(cmd, &here()).action,
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
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "an exception must not become a way through: {cmd}"
            );
        }

        // Prove the ordering, not just the verdict.
        let idx = |pat: &str| {
            p.rules
                .iter()
                .position(|r| r.label() == pat)
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
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd}"
            );
        }
    }

    #[test]
    fn read_only_prefixes_do_not_swallow_neighbouring_commands() {
        let p = Policy::builtin().expect("built-in starter policy must parse");

        // Still allowed — including bare `ls`, which needs its own rule
        // because `ls *` requires the space.
        for cmd in ["ls", "ls -la src", "grep -rn fn src", "cat Cargo.toml"] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Allow,
                "{cmd}"
            );
        }

        // Different programs that merely start with the same letters. `ls*`
        // and `grep*` used to allow all of these.
        for cmd in ["lsof -i :5432", "lsblk", "lsattr -R /", "grepdiff --help"] {
            assert_ne!(
                p.evaluate_command(cmd, &here()).action,
                Action::Allow,
                "a prefix is not a command: {cmd}"
            );
        }
    }
}

#[cfg(test)]
mod combined_gate_tests {
    use super::*;

    /// Evaluation context for tests: the current directory as both cwd and
    /// root. No test here depends on resolution, which is the point - this
    /// commit changed no verdicts.
    fn here() -> crate::resolve::EvalContext {
        crate::resolve::EvalContext::at(std::path::Path::new("."))
    }

    /// Roadmap 2.4, the point of the whole change: a rule matched against the
    /// RESOLVED target catches every spelling of one path, which no number of
    /// added string patterns could do. The reason names WHICH target tripped
    /// it, because a command may touch several and the human approving it
    /// needs to know which one.
    #[test]
    fn a_path_rule_catches_every_spelling_and_names_the_target() {
        let p = Policy::builtin().unwrap();
        let d = p.evaluate_command("cat /dev/null > ./.env", &here());
        assert_eq!(d.action, Action::Deny);
        assert!(
            d.reason.contains(".env"),
            "the reason must name the target that tripped the gate: {}",
            d.reason
        );
        // Control leg: the path rule does not fire on a path it does not
        // match. `cat *` allows this one, which is exactly the point - the
        // ordinary file reaches its ordinary verdict, and only the protected
        // path is pulled out of it.
        let ordinary = p.evaluate_command("cat /dev/null > ./notes.md", &here());
        assert_eq!(ordinary.action, Action::Allow);
        assert_eq!(ordinary.matched_rule.as_deref(), Some("cat *"));
    }

    /// An explicit `allow` still wins over an unresolved sensitive target, and
    /// that is the DECIDED behaviour, not an oversight.
    ///
    /// `echo x > $CONFIG` cannot be resolved — the gate does not know what
    /// file that is — and the target carries the UnexpandedVar shape. That
    /// contributes a deny reading, but the reading enters the same
    /// most-severe-wins tournament as everything else and loses to the
    /// explicit `echo *` allow above it. It is not discarded; it is outranked.
    ///
    /// The alternative (unresolved-sensitive outranking an explicit allow)
    /// would introduce a new precedence level above a decision the operator
    /// wrote down deliberately. That is a separate semantic change and needs
    /// its own tests and a migration note, so it is not made here.
    #[test]
    fn an_explicit_allow_outranks_an_unresolved_sensitive_target() {
        let p = Policy::builtin().unwrap();
        assert_eq!(
            p.evaluate_command("echo x > $CONFIG", &here()).action,
            Action::Allow,
            "an explicit allow is an explicit allow"
        );
        // The deny reading exists and is real — the resolver reports the shape
        // — it simply loses the tournament. Asserting this separately is what
        // makes the test about PRECEDENCE rather than about the resolver
        // having failed to notice.
        let t = crate::resolve::target("$CONFIG", crate::resolve::TargetRole::Destination, &here());
        assert!(t.is_unresolved());
        assert!(t.has(crate::resolve::SensitiveShape::UnexpandedVar));

        // And where no explicit allow covers it, the deny reading DOES govern.
        // A REDIRECT to an unresolved target is seen, because redirects are
        // one of the two target sources this commit reads.
        let d = p.evaluate_command("truncate -s 0 x > $CONFIG", &here());
        assert_eq!(
            d.action,
            Action::Deny,
            "unresolved and sensitive, nothing explicit above it: {}",
            d.reason
        );
        assert!(
            d.reason.contains("cannot be resolved"),
            "the reason must say the gate does not know: {}",
            d.reason
        );

        // SCOPE, pinned so it is not mistaken for coverage: targets come from
        // redirects and from the delete extractor. Nothing else has an
        // extractor yet, so `truncate -s 0 $CONFIG` - which destroys a file
        // named by an unresolvable variable - produces NO targets and reaches
        // its ordinary verdict. cp/mv/tee/dd destinations are roadmap 2.1;
        // truncate is covered by nothing. The machinery is only as wide as
        // the extractors feeding it.
        assert!(
            resolved_targets("truncate -s 0 $CONFIG", &here()).is_empty(),
            "if this starts finding targets, an extractor was added and this \
             test should be narrowed rather than deleted"
        );
    }

    /// THE MATCHER INVARIANT: at least one matcher, neither individually
    /// mandatory. Enforced at parse time, because a rule with no matcher can
    /// never fire - it is a policy that says nothing while looking like it
    /// says something, which is worse than a parse error.
    #[test]
    fn a_rule_needs_at_least_one_matcher() {
        let ok = [
            "rules:\n  - match: \"git rm *\"\n    action: deny\n",
            "rules:\n  - match_path: \"*/.ssh/*\"\n    action: deny\n",
            "rules:\n  - match: \"git *\"\n    match_path: \"*/.ssh/*\"\n    action: deny\n",
        ];
        for y in ok {
            let p: Policy = serde_yaml::from_str(y).expect("parses");
            assert!(p.validate().is_ok(), "should be valid:\n{y}");
        }

        let neither = "rules:\n  - action: deny\n    reason: \"says nothing\"\n";
        let p: Policy = serde_yaml::from_str(neither).expect("parses as YAML");
        let err = p.validate().expect_err("a rule with no matcher is invalid");
        assert!(
            err.to_string().contains("neither"),
            "the error must say what is missing: {err}"
        );
    }

    /// The shipped policy obeys its own invariant, and `builtin()` enforces
    /// it rather than trusting the file - the starter policy is the one most
    /// likely to grow a rule by hand.
    #[test]
    fn the_starter_policy_obeys_the_matcher_invariant() {
        let p = Policy::builtin().expect("builtin parses and validates");
        for (i, r) in p.rules.iter().enumerate() {
            assert!(
                r.r#match.is_some() || r.match_path.is_some(),
                "rule {i} has no matcher"
            );
        }
        // And at least one rule now uses match_path WITHOUT a string pattern,
        // which is the shape the schema change exists to allow.
        assert!(
            p.rules
                .iter()
                .any(|r| r.r#match.is_none() && r.match_path.is_some()),
            "the starter policy should exercise the path-only shape it ships"
        );
    }

    /// The reason line names the ROLE, because the verdict and the
    /// explanation were diverging: `mv .env dst` denied with "Overwriting
    /// .env destroys credentials", and `mv` does not overwrite `.env` - it
    /// REMOVES it. The rule's reason text is written for one case; the role
    /// says which case this actually is. A human approving a prompt should
    /// not have to know those can differ.
    #[test]
    fn the_reason_names_what_the_command_does_to_the_target() {
        let p = Policy::builtin().unwrap();

        let moved = p.evaluate_command("mv .env /tmp/archive/", &here());
        assert_eq!(moved.action, Action::Deny);
        assert!(
            moved.reason.contains("(removed)"),
            "a move removes its source, and the sentence should say so: {}",
            moved.reason
        );

        let written = p.evaluate_command("cp backup.txt .env", &here());
        assert_eq!(written.action, Action::Deny);
        assert!(
            written.reason.contains("(written)"),
            "a copy writes its destination: {}",
            written.reason
        );

        // Both still name the target itself - the role is an addition, not a
        // replacement.
        assert!(moved.reason.contains(".env") && written.reason.contains(".env"));
    }

    /// Roadmap 2.1: a path rule fires on roles that CHANGE a file, not on
    /// every path a command mentions.
    ///
    /// Extracting `cp`/`mv`/`tee`/`dd` targets reopened the source-side false
    /// positive from a new direction: `cp .env backup.txt` names `.env`, but
    /// only reads it. Measured before the guard, all four of these denied.
    ///
    /// `mv` is the case the roles exist for. Its source is REMOVED, not read,
    /// so `mv .env /tmp/archive/` must still deny - a move is a delete of
    /// where the file used to be, and reporting only the destination would
    /// miss the destruction entirely.
    #[test]
    fn a_path_rule_fires_on_what_changes_a_file_not_on_what_reads_it() {
        let p = Policy::builtin().unwrap();

        // Destructive roles: the file is written over, or leaves its place.
        for cmd in [
            "cp backup.txt .env",
            "tee .env",
            "dd if=/dev/zero of=.env",
            "mv .env /tmp/archive/",
        ] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd}: this changes the protected file"
            );
        }

        // Read-only roles: the file is exactly as it was afterwards.
        for cmd in ["cp .env backup.txt", "dd if=.env of=copy.txt"] {
            assert_ne!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd}: reading the protected file changes nothing"
            );
        }
    }

    /// REGRESSION, v0.16: the shipped `.env` rule denied ordinary READS.
    ///
    /// The rule carried `match: "*.env*"` purely because the schema demanded
    /// a string pattern, and that pattern fired on its own - a whole-string
    /// substring match on `.env` anywhere in the command. `cat .env`,
    /// `grep KEY .env`, `git diff .env`, `ls -la .env`, `cat
    /// prod.env.example` were all DENIED. Reading a file destroys nothing,
    /// and a gate that denies ordinary work gets uninstalled (#48).
    ///
    /// Both sides are pinned deliberately: a path rule that stops denying
    /// writes is a hole, and one that starts denying reads is the bug this
    /// test exists for.
    #[test]
    fn the_env_rule_denies_writes_and_leaves_reads_alone() {
        let p = Policy::builtin().unwrap();

        // Writes to the protected file, every spelling of one path.
        for cmd in [
            "cat /dev/null > .env",
            "cat /dev/null > ./.env",
            "cat /dev/null > ./sub/../.env",
        ] {
            assert_eq!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd}: one file, every spelling"
            );
        }

        // Reads are ordinary work and stay out of the way.
        for cmd in [
            "cat .env",
            "grep KEY .env",
            "git diff .env",
            "ls -la .env",
            "cat prod.env.example",
        ] {
            assert_ne!(
                p.evaluate_command(cmd, &here()).action,
                Action::Deny,
                "{cmd}: reading a file destroys nothing"
            );
        }

        // The source-side spelling must not trip the path rule: the resolved
        // TARGET here is config/prod.env, which is not `.env`. Before the
        // fix, the `*.env*` string pattern matched this on the source alone.
        let d = p.evaluate_command("cp new.env config/prod.env", &here());
        assert_ne!(
            d.action,
            Action::Deny,
            "a .env source is not a .env target: {}",
            d.reason
        );
    }

    /// Path patterns are matched COMPONENT BY COMPONENT, not as string globs
    /// over the printed path. The first draft used `wildcard_match` on the
    /// whole string and was wrong three ways: `*/.env` missed a bare `.env`
    /// (no separator), missed `C:\proj\.env` (backslash is not `/`), and
    /// loosening it to `*.env` would have caught `prod.env` as collateral.
    #[test]
    fn a_path_pattern_matches_components_not_strings() {
        let r = Rule {
            r#match: None,
            action: Action::Deny,
            reason: None,
            case_sensitive: false,
            match_path: Some("*/.env".into()),
        };
        for hit in [
            "/tmp/proj/.env",
            "C:\\proj\\.env",
            ".env",
            "./.env",
            "/a/b/c/.env",
        ] {
            assert!(r.matches_path(hit), "{hit} names the protected file");
        }
        // Control legs - a component pattern does not match a substring of a
        // component, which is the whole difference from a string glob.
        for miss in [
            "/tmp/proj/prod.env",
            "/tmp/proj/.env.sample",
            "/tmp/proj/.envrc",
            "/tmp/.env/keep.txt",
        ] {
            assert!(!r.matches_path(miss), "{miss} is a different file");
        }
    }

    /// A `*` component means "at any depth", so one rule covers a file
    /// wherever it sits, and a `*` inside a component stays inside it.
    #[test]
    fn a_star_component_spans_depth_and_a_star_inside_one_does_not() {
        let deep = Rule {
            r#match: None,
            action: Action::Deny,
            reason: None,
            case_sensitive: false,
            match_path: Some("*/.ssh/id_*".into()),
        };
        assert!(deep.matches_path("/home/u/.ssh/id_rsa"));
        assert!(deep.matches_path("/home/u/.ssh/id_ed25519"));
        assert!(!deep.matches_path("/home/u/.ssh/known_hosts"));
        // `id_*` must not reach across a separator into the next component.
        assert!(!deep.matches_path("/home/u/.ssh/id_dir/inner"));
    }

    /// GAP CLOSED, v0.16 — the INVERSION of the pinned known-gap test, not a
    /// replacement, so the history stays visible in the place that proves it
    /// is over. It read: "`cat /dev/null > ./.env` walks past the `*> .env*`
    /// string rules (belt), but the redirect scanner still extracts the
    /// target (suspenders)... the full fix is matching on the RESOLVED target
    /// (v0.16)". That fix is this: the starter policy now carries a
    /// `match_path: "*/.env"` rule, so both spellings of one file deny.
    ///
    /// The suspenders are asserted too, unchanged. Insurance did not become
    /// unnecessary when the string gap closed — it is what covered the four
    /// releases in which the gap was open, and a later policy edit could
    /// remove the rule without removing the net.
    #[test]
    fn the_dot_slash_spelling_was_a_known_gap_and_is_now_closed() {
        let p = Policy::builtin().unwrap();
        for spelling in [
            "cat /dev/null > ./.env",
            "cat /dev/null > .env",
            "cat /dev/null > ./sub/../.env",
        ] {
            assert_eq!(
                p.evaluate_command(spelling, &here()).action,
                Action::Deny,
                "{spelling}: one file, every spelling"
            );
        }
        let segs = crate::shell::split_segments("cat /dev/null > ./.env");
        let r = &segs[0].redirects;
        assert!(
            r.len() == 1 && r[0].truncates && r[0].target == "./.env",
            "the net beneath: insurance sees the spelling the string rules miss"
        );
        // And the write-tool path (Schipper, #20) guards the same files the
        // shell path guards, independent of both.
        assert!(crate::protect::classify(".", ".termaxa/policy.yaml").is_some());
        assert!(crate::protect::classify(".", "src/main.rs").is_none());
    }
}
