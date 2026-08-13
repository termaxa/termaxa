//! The paths an agent's file-writing tool may not write to.
//!
//! Policy rules gate **shell commands**, and the starter policy's self-defence
//! block closes that path: `echo 'default: allow' > .termaxa/policy.yaml`
//! matches a deny. It closes only that path. An agent whose `rm` is denied and
//! which reaches for `Write` instead is routing around an obstacle in the most
//! ordinary way an agent does anything, and until this module existed nothing
//! was looking.
//!
//! Scope is deliberately narrow. This answers ONE question about ONE path:
//! does writing here disable the gate or erase its record? It is not a general
//! file-write policy. Gating every write would make Termaxa unusable and is
//! not what it is for, so a path this module does not recognise produces no
//! decision at all — not an `allow`. Declining to answer where we have no
//! opinion leaves the harness's own permission flow exactly as it was.
//!
//! Three assets, and only three:
//!
//! - **the policy and the state** — anything under a `.termaxa` directory,
//!   which covers `.termaxa/policy.yaml` in the repo and the logs, backups and
//!   fingerprint baseline under `$TERMAXA_HOME`;
//! - **the agent hook configuration** — the files that decide whether the hook
//!   runs at all, one per dialect;
//! - **the record**, which lives under `.termaxa` and so is covered by the
//!   first.
//!
//! Matching is on path *segments*, not substrings, so a file called
//! `termaxa-notes.md` is untouched while `/repo/.termaxa/policy.yaml` and
//! `C:\repo\.termaxa\policy.yaml` are both recognised. Comparison is
//! case-insensitive for the same reason policy matching is: the cost of
//! refusing a write to a strangely-cased `.TERMAXA` is one puzzled agent, and
//! the cost of missing one is the gate.

/// Why a write to this path is refused. `what` names the asset for the audit
/// log; `reason` is what the agent is told.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Protected {
    pub what: &'static str,
    pub reason: &'static str,
}

const POLICY_AND_RECORD: Protected = Protected {
    what: "termaxa-state",
    reason: "`.termaxa/` holds the gate's own policy and its record of what happened. \
             Writing to it from a file tool is not something a task needs. \
             Edit it yourself if the change is intended.",
};

const HOOK_CONFIG: Protected = Protected {
    what: "agent-hook-config",
    reason: "Agent hook configuration is off limits — editing it unhooks the gate. \
             Edit it yourself if the change is intended.",
};

/// Is `path` one of the gate's own files?
///
/// `cwd` is the agent's project directory from the hook payload, used only to
/// resolve a relative path. Agents send absolute paths in practice; this keeps
/// a relative one from reading as an unrecognised path and slipping through.
pub fn classify(cwd: &str, path: &str) -> Option<Protected> {
    let joined;
    let full = if is_absolute(path) || cwd.is_empty() {
        path
    } else {
        joined = format!("{}/{}", cwd.trim_end_matches(['/', '\\']), path);
        &joined
    };
    classify_segments(&segments(full))
}

/// Split on both separators and drop the noise `.` and empty segments, so
/// `./repo//.termaxa/policy.yaml` reads the same as `repo/.termaxa/policy.yaml`.
///
/// `..` is deliberately KEPT rather than resolved. Resolving it here would
/// mean re-implementing path normalisation for two platforms in the one place
/// where getting it wrong is silent; leaving it in means `.termaxa/../x` is
/// refused as if it were inside. That is an over-refusal, and an over-refusal
/// is loud.
fn segments(path: &str) -> Vec<String> {
    path.split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn is_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    if b.first() == Some(&b'/') || b.first() == Some(&b'\\') {
        return true;
    }
    // "C:\..." or "c:/..."
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

fn classify_segments(seg: &[String]) -> Option<Protected> {
    if seg.iter().any(|s| s == ".termaxa") {
        return Some(POLICY_AND_RECORD);
    }

    let file = seg.last()?.as_str();
    let parent = seg.get(seg.len().checked_sub(2)?)?.as_str();

    // Claude Code reads `settings.json` and `settings.local.json` from
    // `.claude/`, in the project and in the home directory. The hook lives in
    // whichever one is present, so both are the control plane. Anything else
    // under `.claude/` (skills, agents, commands) is ordinary project content
    // and stays out of this.
    if parent == ".claude" && file.starts_with("settings") && file.ends_with(".json") {
        return Some(HOOK_CONFIG);
    }

    if (parent == ".cursor" || parent == ".codex") && file == "hooks.json" {
        return Some(HOOK_CONFIG);
    }

    // Copilot CLI: `.github/hooks/hooks.json`. The `.github` check is what
    // keeps an ordinary `hooks/hooks.json` in someone's own tree out of it.
    if parent == "hooks" && file == "hooks.json" {
        let grandparent = seg.get(seg.len().checked_sub(3)?)?.as_str();
        if grandparent == ".github" {
            return Some(HOOK_CONFIG);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn what(cwd: &str, path: &str) -> Option<&'static str> {
        classify(cwd, path).map(|p| p.what)
    }

    #[test]
    fn policy_overwrite_is_refused_on_both_separators() {
        assert_eq!(
            what("/repo", "/repo/.termaxa/policy.yaml"),
            Some("termaxa-state")
        );
        assert_eq!(
            what("C:\\repo", "C:\\repo\\.termaxa\\policy.yaml"),
            Some("termaxa-state")
        );
    }

    #[test]
    fn audit_log_under_termaxa_home_is_refused() {
        // The record is the asset with the highest value and it lives outside
        // the repo, so the check has to reach it by segment rather than by
        // project-relative path.
        assert_eq!(
            what(
                "/repo",
                "/home/user/.termaxa/projects/abc123/logs/audit.jsonl"
            ),
            Some("termaxa-state")
        );
    }

    #[test]
    fn claude_settings_both_spellings_are_refused() {
        assert_eq!(
            what("/repo", "/repo/.claude/settings.json"),
            Some("agent-hook-config")
        );
        assert_eq!(
            what("/repo", "/repo/.claude/settings.local.json"),
            Some("agent-hook-config")
        );
        // doctor only inspects the project copy, but the hook is just as
        // disabled by rewriting the one in $HOME.
        assert_eq!(
            what("/repo", "/home/user/.claude/settings.json"),
            Some("agent-hook-config")
        );
    }

    #[test]
    fn every_dialects_hook_file_is_refused() {
        for path in [
            "/repo/.cursor/hooks.json",
            "/repo/.codex/hooks.json",
            "/repo/.github/hooks/hooks.json",
        ] {
            assert_eq!(what("/repo", path), Some("agent-hook-config"), "{}", path);
        }
    }

    #[test]
    fn relative_path_is_resolved_against_the_payload_cwd() {
        // Claude Code sends absolute paths. A dialect that does not must not
        // read as an unrecognised path.
        assert_eq!(what("/repo", ".termaxa/policy.yaml"), Some("termaxa-state"));
        assert_eq!(what("/repo/.termaxa", "policy.yaml"), Some("termaxa-state"));
    }

    #[test]
    fn ordinary_project_files_get_no_decision() {
        for path in [
            "/repo/src/main.rs",
            "/repo/termaxa-notes.md",
            "/repo/docs/termaxa/README.md",
            "/repo/.claude/skills/review/SKILL.md",
            "/repo/.claude/agents/reviewer.md",
            "/repo/.github/workflows/ci.yml",
            "/repo/hooks/hooks.json",
            "/repo/.termaxarc",
        ] {
            assert_eq!(what("/repo", path), None, "{}", path);
        }
    }

    #[test]
    fn segment_match_does_not_fire_on_a_substring() {
        // `*termaxa*` as a substring would refuse all of these. Segments do not.
        assert_eq!(what("/repo", "/repo/my-termaxa-fork/policy.yaml"), None);
        assert_eq!(what("/repo", "/repo/.termaxa-old/policy.yaml"), None);
    }

    #[test]
    fn case_is_ignored_so_a_respelling_does_not_slip_through() {
        assert_eq!(
            what("/repo", "/repo/.TERMAXA/policy.yaml"),
            Some("termaxa-state")
        );
        assert_eq!(
            what("/repo", "/repo/.Claude/Settings.json"),
            Some("agent-hook-config")
        );
    }

    #[test]
    fn traversal_through_a_protected_directory_is_refused() {
        // Documented over-refusal: `..` is not resolved, so this reads as
        // inside. Refusing too much here is the safe direction.
        assert_eq!(
            what("/repo", "/repo/.termaxa/../notes.md"),
            Some("termaxa-state")
        );
    }

    #[test]
    fn a_bare_filename_with_no_directory_is_not_protected() {
        assert_eq!(what("", "policy.yaml"), None);
        assert_eq!(what("", "settings.json"), None);
    }
}
