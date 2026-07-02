/// Shell-aware command splitting.
///
/// Field report, v0.6.1: a live Claude Code session ran
///   `git status && echo "---" && git branch -vv && ...`
/// and the whole line rode through as `allow` because the `git status*`
/// wildcard matched the STRING by prefix — while the shell would execute
/// five separate commands. Wildcards see one string; shells see many
/// commands. This module closes that gap: split on shell operators, judge
/// every segment, let the most dangerous one govern.
///
/// Scope (deliberate):
///   - Splits on `&&`, `||`, `;`, `|`, and newlines, outside quotes.
///   - Single `&` is NOT a separator (it appears in redirections like 2>&1
///     far more often than as a background operator).
///   - `$(...)` and backticks cannot be statically analyzed — their PRESENCE
///     is reported so the context engine can escalate, rather than
///     pretending the contents were checked.
pub fn split_segments(s: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let (mut in_single, mut in_double) = (false, false);

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(c);
            }
            '\\' if in_double && i + 1 < chars.len() => {
                cur.push(c);
                cur.push(chars[i + 1]);
                i += 1;
            }
            _ if in_single || in_double => cur.push(c),
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                flush(&mut segments, &mut cur);
                i += 1; // consume second &
            }
            '|' => {
                flush(&mut segments, &mut cur);
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    i += 1; // `||` — consume second |
                }
            }
            ';' | '\n' => flush(&mut segments, &mut cur),
            _ => cur.push(c),
        }
        i += 1;
    }
    flush(&mut segments, &mut cur);
    segments
}

fn flush(segments: &mut Vec<String>, cur: &mut String) {
    let t = cur.trim();
    if !t.is_empty() {
        segments.push(t.to_string());
    }
    cur.clear();
}

/// Does the command contain command substitution we cannot see inside?
pub fn has_substitution(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut in_single = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\'' => in_single = !in_single,
            '`' if !in_single => return true,
            '$' if !in_single && chars.get(i + 1) == Some(&'(') => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_field_report_command() {
        let cmd = r#"git status && echo "---" && git branch -vv && git log --oneline -5"#;
        let seg = split_segments(cmd);
        assert_eq!(
            seg,
            vec![
                "git status",
                r#"echo "---""#,
                "git branch -vv",
                "git log --oneline -5"
            ]
        );
    }

    #[test]
    fn splits_all_operators() {
        assert_eq!(split_segments("a; b | c || d && e"), vec!["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn quotes_protect_operators() {
        assert_eq!(split_segments("echo 'a && b'"), vec!["echo 'a && b'"]);
        assert_eq!(split_segments(r#"echo "x; y""#), vec![r#"echo "x; y""#]);
    }

    #[test]
    fn redirections_survive() {
        // single & must not split: 2>&1 is a redirection, not an operator
        assert_eq!(split_segments("cmd 2>&1"), vec!["cmd 2>&1"]);
    }

    #[test]
    fn substitution_detected() {
        assert!(has_substitution("echo $(rm -rf /)"));
        assert!(has_substitution("echo `whoami`"));
        assert!(!has_substitution("echo '$(safe)'"));
        assert!(!has_substitution("git status"));
    }
}
