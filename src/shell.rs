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
///   - Splits on `&&`, `||`, `;`, `|`, `&`, and newlines, outside quotes.
///   - A single `&` IS a separator. Until v0.14.1 it was not — the reasoning
///     was that `2>&1` is more common than backgrounding, which is true but
///     answered the wrong question: an allow rule only has to be wrong once.
///     Redirection forms are excluded by shape instead (see
///     `is_redirection_amp`), which costs nothing and closes the bypass.
///   - `$(...)` and backticks cannot be statically analyzed — their PRESENCE
///     is reported so the context engine can escalate, rather than
///     pretending the contents were checked.
///   - Redirect targets are extracted in the SAME walk (v0.15 #14 found `>`
///     lexed and thrown away — `cat /dev/null > .env` wiped a credentials
///     file invisibly; v0.16 §1.5 folded the separate scan back in after two
///     walks over one grammar produced three bugs and then measurably
///     disagreed, decision #37). Each `Segment` carries the `Overwrite`s
///     found in it; there is no second scanner to feed different input.
pub fn split_segments(s: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let mut cur_redirects = Vec::new();
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
            // An escape outside single quotes makes the next character
            // LITERAL: no quote toggle, no separator, no redirect. Until
            // v0.16 this arm only fired inside double quotes; outside them,
            // `\"` toggled quote state and everything after it — including
            // a `;` and whatever command followed — rode inside one segment
            // a permissive rule could match whole. A shell runs that second
            // command. The over-splits go with it: `echo a \; b` is ONE
            // command to a shell, and now one segment here.
            '\\' if !in_single && i + 1 < chars.len() => {
                cur.push(c);
                cur.push(chars[i + 1]);
                i += 1;
            }
            _ if in_single || in_double => cur.push(c),
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                flush(&mut segments, &mut cur, &mut cur_redirects);
                i += 1; // consume second &
            }
            // A lone `&` IS a separator — it backgrounds the segment to its
            // left and starts a new command to its right. Treating it as
            // ordinary text reopened the v0.6.1 bypass on one character:
            // `git status & rm -rf /` stayed a single segment and matched the
            // `git status*` allow rule. The redirection forms it also appears
            // in are `2>&1` / `>&2` / `<&-` (preceded by `>` or `<`) and
            // `&>file` / `&>>file` (followed by `>`); those are not separators.
            '&' if !is_redirection_amp(&chars, i) => {
                flush(&mut segments, &mut cur, &mut cur_redirects)
            }
            // A redirect: consume the operator and its target in THIS walk,
            // recording the Overwrite the segment will carry. Deliberately
            // NOT treated as redirects, because they do not create or
            // truncate a file: `2>&1`, `>&2` (descriptor duplication), `&>`
            // and `&>>` (stream combination), `<>` (read-write open),
            // `>(...)` (process substitution — an operator, not a filename),
            // `\>` (a literal, consumed by the escape arm above), anything
            // inside quotes, and sinks (`/dev/null` and friends — truncating
            // one destroys nothing). `>|` (clobber past noclobber) IS a
            // truncation of the named file, and one operator: splitting at
            // its `|` cut the target into its own segment, hiding the
            // truncation from every engine that splits first.
            '>' => {
                let prev_is_amp = i > 0 && chars[i - 1] == '&';
                let prev_is_lt = i > 0 && chars[i - 1] == '<';
                cur.push(c);
                let mut j = i + 1;
                let truncates = if chars.get(j) == Some(&'>') {
                    cur.push('>');
                    j += 1;
                    false
                } else {
                    true
                };
                if truncates && chars.get(j) == Some(&'|') {
                    cur.push('|');
                    j += 1;
                }
                if chars.get(j) == Some(&'&') {
                    // descriptor duplication — keep the `&` as text and let
                    // the walk continue after it, as `is_redirection_amp`
                    // always classified it
                    cur.push('&');
                    i = j + 1;
                    continue;
                }
                while j < chars.len() && chars[j].is_whitespace() {
                    cur.push(chars[j]);
                    j += 1;
                }
                if chars.get(j) == Some(&'(') {
                    // process substitution: `tee >(gzip)` hands tee a pipe,
                    // not a file — hand the paren back to the walk
                    i = j;
                    continue;
                }
                // The target: everything until unquoted whitespace or an
                // unquoted separator, escapes honored as everywhere else in
                // the walk. Backslashes are RETAINED in the target string,
                // as they always were for non-boundary characters.
                let mut target = String::new();
                let mut quote: Option<char> = None;
                while j < chars.len() {
                    let d = chars[j];
                    match quote {
                        Some(q) if d == q => quote = None,
                        Some(_) => {}
                        None if d == '\'' || d == '"' => quote = Some(d),
                        None if d == '\\' && j + 1 < chars.len() => {
                            cur.push(d);
                            target.push(d);
                            j += 1;
                        }
                        None if d.is_whitespace() => break,
                        None if matches!(d, ';' | '\n' | '|') => break,
                        None if d == '&' && !is_redirection_amp(&chars, j) => break,
                        None => {}
                    }
                    cur.push(chars[j]);
                    target.push(chars[j]);
                    j += 1;
                }
                let target: String = target.trim_matches(|c| c == '\'' || c == '"').to_string();
                if !target.is_empty() && !prev_is_amp && !prev_is_lt && !is_sink(&target) {
                    cur_redirects.push(Overwrite { target, truncates });
                }
                i = j;
                continue;
            }
            '|' => {
                flush(&mut segments, &mut cur, &mut cur_redirects);
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    i += 1; // `||` — consume second |
                }
            }
            ';' | '\n' => flush(&mut segments, &mut cur, &mut cur_redirects),
            _ => cur.push(c),
        }
        i += 1;
    }
    flush(&mut segments, &mut cur, &mut cur_redirects);
    segments
}

/// One shell segment, carrying the redirect targets found in it.
///
/// v0.16 §1.5. Segments and redirect targets used to come from two separate
/// public scanners over the same grammar, and callers chose which to trust —
/// `intent` read redirects per segment while `backup` re-scanned the raw
/// command (decision #37: two engines parsing the same input are already
/// disagreeing). One public type ends the choice: a segment arrives with its
/// redirects attached, from the same split.
///
/// `Deref<Target = str>` keeps every caller that only wants the text
/// unchanged; the field is private so the text cannot drift from the
/// redirects computed for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    text: String,
    /// Files this segment writes over, in order of appearance.
    pub redirects: Vec<Overwrite>,
}

impl std::ops::Deref for Segment {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Tests compare segment lists against string literals; the comparison is on
/// the text alone, which is the only part a string literal can speak for.
impl PartialEq<&str> for Segment {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

/// A file this command will write over, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overwrite {
    /// The path as written, before resolution.
    pub target: String,
    /// True when the write truncates (`>`), false when it appends (`>>`).
    /// Only truncation destroys, and the distinction is the whole point:
    /// a gate that treats `>>` as destructive fires on every log line.
    pub truncates: bool,
}

/// A write to one of these destroys nothing: they are discard devices, not
/// files. Excluding them here — the single extraction point — keeps every
/// engine consistent: no intent, no insurance, no breaker pressure for
/// `> /dev/null`, which is the most common redirect in existence.
fn is_sink(target: &str) -> bool {
    matches!(
        target.to_ascii_lowercase().as_str(),
        "/dev/null"
            | "/dev/zero"
            | "/dev/stdout"
            | "/dev/stderr"
            | "/dev/tty"
            | "/dev/full"
            | "nul"
    )
}

/// Is the `&` at `i` part of a redirection rather than a command separator?
/// `2>&1`, `1>&2`, `<&-` have `>` or `<` immediately before; `&>log` and
/// `&>>log` have `>` immediately after.
fn is_redirection_amp(chars: &[char], i: usize) -> bool {
    let prev_is_redirect = i > 0 && matches!(chars[i - 1], '>' | '<');
    let next_is_redirect = chars.get(i + 1) == Some(&'>');
    prev_is_redirect || next_is_redirect
}

fn flush(segments: &mut Vec<Segment>, cur: &mut String, redirects: &mut Vec<Overwrite>) {
    let t = cur.trim();
    if !t.is_empty() {
        segments.push(Segment {
            text: t.to_string(),
            redirects: std::mem::take(redirects),
        });
    } else {
        // Nothing but whitespace between separators: whatever the redirect
        // scan collected has no segment to ride on. Unreachable in practice
        // (a redirect implies non-whitespace text), cleared for safety.
        redirects.clear();
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

    /// Redirects as callers now receive them: through the split, attached to
    /// the segments they were found in. Flattened here because these tests
    /// assert on targets, not on which segment carried them.
    fn redirects(cmd: &str) -> Vec<Overwrite> {
        split_segments(cmd)
            .into_iter()
            .flat_map(|s| s.redirects)
            .collect()
    }

    /// #14. `>` was lexed and discarded, so a command that destroys a file by
    /// writing over it was invisible to every engine.
    #[test]
    fn truncating_redirects_are_extracted() {
        let r = redirects("cat /dev/null > .env");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, ".env");
        assert!(r[0].truncates);

        assert_eq!(redirects("ls -la > /etc/hosts")[0].target, "/etc/hosts");
        assert_eq!(redirects("echo x >config.json")[0].target, "config.json");
        assert_eq!(
            redirects(r#"echo x > "my file.txt""#)[0].target,
            "my file.txt"
        );
    }

    /// Appending does not destroy. A gate that treats `>>` as destructive
    /// fires on every log line and gets uninstalled.
    #[test]
    fn appending_is_recorded_but_not_truncating() {
        let r = redirects("echo entry >> app.log");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, "app.log");
        assert!(!r[0].truncates, ">> appends, it does not destroy");
    }

    /// Descriptor plumbing names no file. This is the same distinction
    /// `is_redirection_amp` makes for `&`, and getting it wrong would fire
    /// on ordinary `2>&1`.
    #[test]
    fn descriptor_redirects_are_not_file_targets() {
        for cmd in [
            "make 2>&1",
            "cmd >&2",
            "cmd <&-",
            "cmd &> log",
            "cmd &>> log",
            "make 2>&1 | tee out",
        ] {
            assert!(
                redirects(cmd).is_empty(),
                "{cmd} redirects a descriptor, it does not truncate a file"
            );
        }
    }

    /// A `>` inside quotes is text, not an operator — the same property the
    /// segment splitter already guarantees, from the same scanner.
    #[test]
    fn quoted_redirects_are_text() {
        assert!(redirects(r#"echo "a > b""#).is_empty());
        assert!(redirects("echo 'x > y'").is_empty());
        assert!(redirects(r#"git commit -m "fix > bug""#).is_empty());
    }

    /// Sinks destroy nothing, and `> /dev/null` is the most common redirect
    /// in existence. Classifying it fed the breaker on every build command —
    /// the third redirected build log of any session was DENIED.
    #[test]
    fn sinks_are_not_targets() {
        for cmd in [
            "cargo test > /dev/null",
            "cmd 2> /dev/null",
            "make >/dev/null 2>&1",
            "cat big > /dev/zero",
            "echo x > NUL",
        ] {
            assert!(
                redirects(cmd).is_empty(),
                "{cmd} truncates a sink, not a file"
            );
        }
    }

    /// `>(...)` is an operator: `tee >(gzip)` hands tee a pipe. The draft
    /// extracted "(gzip" as a truncating target.
    #[test]
    fn process_substitution_is_not_a_target() {
        for cmd in ["tee >(gzip -c) < data", "diff x >(sort)", "cmd > >(bar)"] {
            assert!(
                redirects(cmd).iter().all(|o| !o.target.starts_with('(')),
                "{cmd}: a paren is an operator, not a filename"
            );
        }
        assert!(redirects("tee >(gzip -c) < data").is_empty());
    }

    /// `\>` outside quotes is a literal; `>|` clobbers — a truncation of the
    /// named file; `<>` opens read-write and destroys nothing.
    #[test]
    fn escapes_clobber_and_read_write_open() {
        assert!(redirects(r"echo a \> b").is_empty());
        let r = redirects("cmd >| forced.txt");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, "forced.txt");
        assert!(r[0].truncates);
        assert!(redirects("cmd <> rw.txt").is_empty());
    }

    /// v0.16 §1.5, behavior CHANGE, pinned deliberately: an escape outside
    /// single quotes makes the next character literal, as a shell reads it.
    /// Before unification `\"` toggled quote state, so the `;` and the
    /// command after it rode inside one segment — `echo \" ; rm -rf x`
    /// matched an `echo *` allow rule whole while the shell ran `rm -rf x`
    /// as its own command. The v0.6.1 class, reopened through an escape.
    #[test]
    fn an_escaped_quote_does_not_open_a_quote() {
        assert_eq!(
            split_segments(r#"echo \" ; rm -rf x"#),
            vec![r#"echo \""#, "rm -rf x"]
        );
        // Control leg — inside double quotes the escape behaves exactly as
        // before: the quoted `;` stays text and the segment stays whole.
        assert_eq!(
            split_segments(r#"echo "keep \" this; here""#),
            vec![r#"echo "keep \" this; here""#]
        );
    }

    /// v0.16 §1.5, behavior CHANGE, pinned deliberately: an escaped
    /// separator is literal, so the line is ONE command — which is what the
    /// shell executes. The old walk split at `\;` and `\&`, judging
    /// segments the shell never runs; an over-split that could fire a rule
    /// on a command that does not exist (#48 territory).
    #[test]
    fn escaped_separators_are_literal() {
        assert_eq!(split_segments(r"echo a \; b"), vec![r"echo a \; b"]);
        assert_eq!(split_segments(r"echo a\;b"), vec![r"echo a\;b"]);
        assert_eq!(
            split_segments(r"git commit -m msg \&\& rm x"),
            vec![r"git commit -m msg \&\& rm x"]
        );
        // Control legs — unescaped separators split exactly as before.
        assert_eq!(split_segments("echo a ; b"), vec!["echo a", "b"]);
        assert_eq!(split_segments("echo a && rm x"), vec!["echo a", "rm x"]);
        // And a redirect on the merged line still surfaces: one segment,
        // its overwrite attached.
        let segs = split_segments(r"echo a \; b > out");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].redirects.len(), 1);
        assert_eq!(segs[0].redirects[0].target, "out");
    }

    /// v0.16 §1.5, behavior CHANGE, pinned deliberately: an escaped space in
    /// a redirect target keeps the filename whole. The old target scan broke
    /// at the space, insuring a file named `a\` instead of the one the shell
    /// writes over. Backslashes are retained in the target string, as they
    /// always were for non-boundary characters.
    #[test]
    fn an_escaped_space_keeps_a_target_whole() {
        let r = redirects(r"cmd > a\ b.txt");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, r"a\ b.txt");
    }

    /// A separator immediately after a target ends the target AND still
    /// splits: the walk finds the redirect and the next command both.
    #[test]
    fn a_separator_ends_a_target_and_still_splits() {
        let segs = split_segments("cmd > log;next");
        assert_eq!(segs, vec!["cmd > log", "next"]);
        assert_eq!(segs[0].redirects[0].target, "log");
        let segs = split_segments("cmd > a&b");
        assert_eq!(segs, vec!["cmd > a", "b"]);
        assert_eq!(segs[0].redirects[0].target, "a");
    }

    /// The empty-target guard, exercised: a trailing redirect names nothing
    /// and must push nothing. The last of the five predicted survivors; the
    /// other four died to `every_sink_spelling_is_a_sink` above.
    #[test]
    fn a_trailing_redirect_with_no_target_pushes_nothing() {
        for cmd in ["cmd >", "cmd > ", "cmd >>", "cmd >|", "echo x 2>"] {
            assert!(
                redirects(cmd).is_empty(),
                "{cmd:?} names no target and must push no Overwrite"
            );
        }
        // Behavior pin, not a mutant killer: the pass ruled both
        // trailing-backslash bound mutants EQUIVALENT (f6a2746dc86a) - no
        // input distinguishes the spellings, so this pins the behavior
        // they share: a bare trailing escape ends the scan with nothing
        // pushed. (The fingerprint is from the pass over the then-public
        // `redirect_targets`; the scan now lives inside `split_segments`
        // itself, and the pinned behavior is the same.)
        assert!(redirects("echo x \\").is_empty());
    }

    #[test]
    fn several_redirects_in_one_segment() {
        let r = redirects("cmd > out.txt 2> err.txt");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].target, "out.txt");
        assert_eq!(r[1].target, "err.txt");
    }

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
        assert_eq!(
            split_segments("a; b | c || d && e"),
            vec!["a", "b", "c", "d", "e"]
        );
    }

    #[test]
    fn quotes_protect_operators() {
        assert_eq!(split_segments("echo 'a && b'"), vec!["echo 'a && b'"]);
        assert_eq!(split_segments(r#"echo "x; y""#), vec![r#"echo "x; y""#]);
    }

    #[test]
    fn redirections_survive() {
        // `&` inside a redirection is not an operator
        assert_eq!(split_segments("cmd 2>&1"), vec!["cmd 2>&1"]);
        assert_eq!(split_segments("cmd >&2"), vec!["cmd >&2"]);
        assert_eq!(split_segments("cmd &> log"), vec!["cmd &> log"]);
        assert_eq!(split_segments("cmd &>> log"), vec!["cmd &>> log"]);
        assert_eq!(split_segments("cmd <&-"), vec!["cmd <&-"]);
        assert_eq!(
            split_segments("make 2>&1 | tee log"),
            vec!["make 2>&1", "tee log"]
        );
        // `>|` is a clobber, not a pipe boundary. Splitting at its `|` hid
        // the truncation from every engine that splits first — intent
        // classified `cmd >| file` as None while backup insured it.
        assert_eq!(
            split_segments("cmd >| forced.txt"),
            vec!["cmd >| forced.txt"]
        );
        assert_eq!(
            split_segments("cmd >| out.txt | grep x"),
            vec!["cmd >| out.txt", "grep x"]
        );
    }

    /// Schipper review, finding 1. `&` backgrounds the left-hand command and
    /// starts a new one; leaving it unsplit meant the whole line matched the
    /// `git status*` allow rule and was ALLOWED.
    #[test]
    fn a_lone_ampersand_splits() {
        assert_eq!(
            split_segments("git status & rm -rf /"),
            vec!["git status", "rm -rf /"]
        );
        assert_eq!(split_segments("ls & rm -rf /"), vec!["ls", "rm -rf /"]);
        assert_eq!(split_segments("npm run dev &"), vec!["npm run dev"]);
        assert_eq!(split_segments("a & b & c"), vec!["a", "b", "c"]);
        // no spaces required, exactly as the shell reads it
        assert_eq!(
            split_segments("echo hi&rm -rf /"),
            vec!["echo hi", "rm -rf /"]
        );
    }

    /// The bypass was reachable because the two splitters disagreed about the
    /// same string. Since v0.14.1 `intent` calls this function, so the only
    /// way they can diverge again is if this test is deleted.
    #[test]
    fn newlines_split_too() {
        assert_eq!(
            split_segments("git status\nrm -rf /"),
            vec!["git status", "rm -rf /"]
        );
    }

    #[test]
    fn substitution_detected() {
        assert!(has_substitution("echo $(rm -rf /)"));
        assert!(has_substitution("echo `whoami`"));
        assert!(!has_substitution("echo '$(safe)'"));
        assert!(!has_substitution("git status"));
    }

    // -----------------------------------------------------------------------
    // The edges of the character walk.
    //
    // Both parsers in this file were tested on realistic commands and never on
    // the boundaries: a quote of one kind inside the other, an operator at the
    // very end of the input, a segment that BEGINS with a redirect, an escape
    // with nothing after it. Those are where a hand-written lexer goes wrong,
    // and where a command slips past the gate whole.
    // -----------------------------------------------------------------------

    #[test]
    fn a_quote_of_one_kind_does_not_open_the_other() {
        // If the apostrophe in `it's` opened a single-quoted run, everything
        // after it would be literal text and the `&&` would stop separating
        // commands. That is a bypass, not a formatting quirk.
        let segs = split_segments("echo \"it's fine\" && rm -rf /tmp/x");
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert!(segs[1].starts_with("rm -rf"), "{segs:?}");

        let segs = split_segments("echo 'say \"hi\"' && rm -rf /tmp/x");
        assert_eq!(segs.len(), 2, "{segs:?}");

        // Same question for the redirect scanner: the apostrophe must not
        // swallow the `>` that follows it.
        let targets = redirects("echo \"it's\" > out.txt");
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0].target, "out.txt");

        let targets = redirects("echo 'a \"b\"' > out.txt");
        assert_eq!(targets[0].target, "out.txt");
    }

    #[test]
    fn single_quotes_hide_a_substitution_and_double_quotes_do_not() {
        // In a shell, `'` protects a backtick and `"` does not. Reading it the
        // other way round either misses a substitution or flags every string.
        assert!(!has_substitution("echo 'a `b` c'"));
        assert!(has_substitution("echo \"a `b` c\""));
        assert!(!has_substitution("echo 'a $(b) c'"));
        assert!(has_substitution("echo \"a $(b) c\""));
    }

    #[test]
    fn an_operator_at_the_very_end_is_not_read_past() {
        // Each of these ends on a character whose handler looks at the NEXT
        // one. Reading past the end is a panic in the hook, which is a gate
        // that stopped answering.
        assert_eq!(split_segments("ls &"), ["ls"]);
        assert_eq!(split_segments("ls |"), ["ls"]);
        assert_eq!(split_segments("ls &&"), ["ls"]);
        assert_eq!(split_segments("ls ||"), ["ls"]);
        // A trailing backslash, inside quotes and bare.
        assert_eq!(split_segments("echo \"a\\"), ["echo \"a\\"]);
        assert_eq!(redirects("echo a\\").len(), 0);
        assert_eq!(redirects("echo > out.txt\\").len(), 1);
    }

    #[test]
    fn a_segment_may_begin_with_the_operator() {
        // Nothing precedes the first character, and the checks for "what came
        // before this?" have to survive that.
        let targets = redirects("> out.txt");
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0].target, "out.txt");
        assert!(targets[0].truncates);

        // A leading `&>` combines streams rather than truncating a file, and
        // asking what precedes the `&` must not run off the front.
        assert_eq!(redirects("&> log.txt").len(), 0);
        assert_eq!(split_segments("&> log.txt"), ["&> log.txt"]);
    }

    #[test]
    fn a_redirect_with_nothing_after_it_has_no_target() {
        // The skip-the-whitespace loop runs to the end of the input here, so
        // the bound on it is the only thing between this and a panic.
        assert_eq!(redirects("echo >").len(), 0);
        assert_eq!(redirects("echo >   ").len(), 0);
        assert_eq!(redirects("echo >>").len(), 0);
    }

    #[test]
    fn a_quoted_target_keeps_the_spaces_inside_it() {
        // The quote has to close, or the scan swallows the rest of the line
        // and reports a target nobody wrote.
        let targets = redirects("echo > 'my file.txt' && ls");
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0].target, "my file.txt");

        let targets = redirects("echo > \"my file.txt\"");
        assert_eq!(targets[0].target, "my file.txt");
    }

    #[test]
    fn an_unbalanced_quote_inside_the_other_kind_changes_nothing() {
        // A balanced pair proves less than it looks: toggling the wrong state
        // twice returns it to where it started. One `"` inside single quotes
        // is what shows whether the guard is consulted, and if it is not, the
        // `&&` after it stops separating commands.
        let segs = split_segments("echo 'it\"s' && rm -rf /tmp/x");
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert!(segs[1].starts_with("rm -rf"), "{segs:?}");

        let targets = redirects("echo 'a\"b' > out.txt");
        assert_eq!(
            targets.len(),
            1,
            "the redirect is outside the quotes: {targets:?}"
        );
        assert_eq!(targets[0].target, "out.txt");
    }

    #[test]
    fn an_escaped_quote_does_not_close_the_string_it_is_inside() {
        // `"a\"b && c"` is one argument containing an ampersand pair, not two
        // commands. If the escape is not honoured, the `"` closes the string
        // and the `&&` becomes a separator.
        let segs = split_segments("echo \"a\\\"b && c\"");
        assert_eq!(segs.len(), 1, "{segs:?}");
        assert_eq!(
            segs[0], "echo \"a\\\"b && c\"",
            "the text must survive intact"
        );
    }

    #[test]
    fn a_backslash_inside_single_quotes_escapes_nothing() {
        // Single quotes are literal in a shell: a backslash there protects
        // nothing, so the closing quote is still a closing quote.
        let targets = redirects("echo '\\' > out.txt");
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0].target, "out.txt");
    }

    #[test]
    fn an_operator_pair_is_consumed_exactly_once() {
        // `&&>` is `&&` followed by a redirect. Consuming one character too
        // few leaves the second `&` in the next segment; one too many eats
        // the character after it.
        assert_eq!(split_segments("ls &&> out.txt"), ["ls", "> out.txt"]);
        // A pipe with no space after it: the character following must reach
        // the next segment rather than being swallowed as part of the operator.
        assert_eq!(split_segments("ls |grep x"), ["ls", "grep x"]);
        assert_eq!(split_segments("ls ||grep x"), ["ls", "grep x"]);
    }

    #[test]
    fn a_segment_may_begin_with_a_backslash() {
        // Nothing precedes the first character, and the escape arm's bound is
        // the only thing keeping the index from running off the front of the
        // input. `\> out.txt` writes a literal `>` and redirects nothing.
        assert_eq!(redirects("\\> out.txt").len(), 0);
        assert_eq!(split_segments("\\> out.txt"), ["\\> out.txt"]);
    }

    #[test]
    fn every_sink_spelling_is_a_sink() {
        // Seven spellings share one `matches!` arm, and the mutation pass
        // cannot see inside a macro: it generates no per-arm mutants, so a
        // spelling dropped from this list would go unnoticed by the tool
        // that checks the rest of this file. Hence the explicit walk.
        for sink in [
            "/dev/null",
            "/dev/zero",
            "/dev/stdout",
            "/dev/stderr",
            "/dev/tty",
            "/dev/full",
            "NUL",
            "nul",
            "/DEV/NULL",
        ] {
            assert!(
                redirects(&format!("echo x > {sink}")).is_empty(),
                "{sink} destroys nothing and must not be an overwrite target"
            );
        }
        // And a path that merely looks like one is still a file.
        for real in ["/dev/null.bak", "/dev/nullify", "nulled.txt"] {
            assert_eq!(
                redirects(&format!("echo x > {real}")).len(),
                1,
                "{real} is an ordinary file"
            );
        }
    }
}
