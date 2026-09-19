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
    // Where every redirection in the current segment sits, as [start, end)
    // char indices into `chars`: operator, any file descriptor number that
    // is its own word before it, and the target. `flush` builds the
    // segment's `command` by leaving these out. Recorded here, in the one
    // walk that finds them, so no engine has to find them again (#61).
    let mut cur_spans: Vec<(usize, usize)> = Vec::new();
    let mut seg_start = 0;
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
                flush(
                    &mut segments,
                    &mut cur,
                    &mut cur_redirects,
                    &chars[seg_start..i],
                    seg_start,
                    &mut cur_spans,
                );
                seg_start = i + 2;
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
                flush(
                    &mut segments,
                    &mut cur,
                    &mut cur_redirects,
                    &chars[seg_start..i],
                    seg_start,
                    &mut cur_spans,
                );
                seg_start = i + 1;
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
                // `&>` and `<>` are one operator whose first character the
                // walk already pushed; the span starts there.
                let start = if prev_is_amp || prev_is_lt {
                    i - 1
                } else {
                    span_start(&chars, seg_start, i)
                };
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
                    // descriptor duplication — keep the `&` and the
                    // descriptor as text, as `is_redirection_amp` always
                    // classified it, and leave the whole of `2>&1` out of
                    // the command text: it names no file.
                    cur.push('&');
                    let end = descriptor(&chars, &mut cur, j + 1);
                    cur_spans.push((start, end));
                    i = end;
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
                let (target, end) = target_word(&chars, &mut cur, j);
                if !target.is_empty() && !prev_is_amp && !prev_is_lt && !is_sink(&target) {
                    cur_redirects.push(Overwrite { target, truncates });
                }
                // A sink or a duplication still occupies the command line;
                // only the Overwrite record is withheld, not the span.
                cur_spans.push((start, end));
                i = end;
                continue;
            }
            '|' => {
                flush(
                    &mut segments,
                    &mut cur,
                    &mut cur_redirects,
                    &chars[seg_start..i],
                    seg_start,
                    &mut cur_spans,
                );
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    i += 1; // `||` — consume second |
                }
                seg_start = i + 1;
            }
            ';' | '\n' => {
                flush(
                    &mut segments,
                    &mut cur,
                    &mut cur_redirects,
                    &chars[seg_start..i],
                    seg_start,
                    &mut cur_spans,
                );
                seg_start = i + 1;
            }
            // An input redirection: `< file`, `<< WORD` (heredoc), `<<< word`
            // (here-string), `<> file`, `<& n`. None of them names a file the
            // command deletes, copies or moves, so the whole thing is a span
            // the command text leaves out. The text keeps it verbatim, as it
            // always did: this arm pushes exactly what the walk pushed before
            // it existed. `<(...)` is process substitution — hand the paren
            // back to the walk.
            '<' => {
                let start = span_start(&chars, seg_start, i);
                cur.push(c);
                let mut j = i + 1;
                if chars.get(j) == Some(&'<') {
                    cur.push('<');
                    j += 1;
                    if chars.get(j) == Some(&'<') {
                        cur.push('<');
                        j += 1;
                    }
                } else if chars.get(j) == Some(&'>') {
                    cur.push('>');
                    j += 1;
                }
                if chars.get(j) == Some(&'&') {
                    cur.push('&');
                    j = descriptor(&chars, &mut cur, j + 1);
                    cur_spans.push((start, j));
                    i = j;
                    continue;
                }
                while j < chars.len() && chars[j].is_whitespace() {
                    cur.push(chars[j]);
                    j += 1;
                }
                if chars.get(j) == Some(&'(') {
                    i = j;
                    continue;
                }
                let (_, end) = target_word(&chars, &mut cur, j);
                cur_spans.push((start, end));
                i = end;
                continue;
            }
            _ => cur.push(c),
        }
        i += 1;
    }
    flush(
        &mut segments,
        &mut cur,
        &mut cur_redirects,
        &chars[seg_start..],
        seg_start,
        &mut cur_spans,
    );
    segments
}

/// Where a redirection's span begins: at the operator, or at the file
/// descriptor number in front of it when that number is a word of its own.
/// `2>err` redirects descriptor 2; `file2>err` is the word `file2` followed
/// by a redirect of stdout — the shell reads it that way, so this does too.
fn span_start(chars: &[char], seg_start: usize, op: usize) -> usize {
    let mut k = op;
    while k > seg_start && chars[k - 1].is_ascii_digit() {
        k -= 1;
    }
    if k < op && (k == seg_start || chars[k - 1].is_whitespace()) {
        k
    } else {
        op
    }
}

/// The descriptor after `>&` or `<&`: digits, or `-` to close. Pushed to
/// the text verbatim; returns the index after it.
fn descriptor(chars: &[char], cur: &mut String, mut j: usize) -> usize {
    while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '-') {
        cur.push(chars[j]);
        j += 1;
    }
    j
}

/// A redirection's target: everything until unquoted whitespace or an
/// unquoted separator, escapes honored as everywhere else in the walk.
/// Backslashes are RETAINED in the target string, as they always were for
/// non-boundary characters. Every character is pushed to the segment text;
/// returns the target with its surrounding quotes stripped, and the index
/// after it.
fn target_word(chars: &[char], cur: &mut String, mut j: usize) -> (String, usize) {
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
            None if d == '&' && !is_redirection_amp(chars, j) => break,
            None => {}
        }
        cur.push(chars[j]);
        target.push(chars[j]);
        j += 1;
    }
    let target: String = target.trim_matches(|c| c == '\'' || c == '"').to_string();
    (target, j)
}

/// POSIX shells whose `-c <string>` runs the string as a command line.
/// Narrow on purpose (#62): each name here is one a cooperative harness or
/// agent has been seen to spell. `ksh` and `ash` wait for a capture; `fish`
/// has its own syntax and is not read.
const POSIX_SHELLS: [&str; 4] = ["sh", "bash", "dash", "zsh"];

/// How many `-c` strings deep the reading goes. `sh -c "sh -c '…'"` is two;
/// four is more than any harness produces and bounds a pathological input.
const MAX_WRAP_DEPTH: usize = 4;

/// `split_segments`, and then through every POSIX shell `-c` string found.
///
/// #62. `sh -c "cat /dev/null > src/main.rs"` was a segment whose head is
/// `sh`, with two arguments, to every engine: no overwrite intent, no
/// preview, no insurance, and the ask it got came from the policy default.
/// The `wrap` shim forwards every agent command in exactly that shape.
///
/// Additive: the wrapper segment stays, and the string's own segments follow
/// it, each carrying the wrapper it was read through in `via`. Nothing that
/// matched before stops matching — a rule on `sh *` still sees the wrapper —
/// and the most dangerous segment still decides. The wrapper's own
/// redirects (`sh -c "…" > log`) stay on the wrapper. Callers that judge a
/// whole command line use this; callers handed one segment's text and
/// asked about that segment alone keep `split_segments`.
pub fn split_segments_deep(s: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    expand_into(&mut out, split_segments(s), None, 0);
    out
}

fn expand_into(out: &mut Vec<Segment>, segments: Vec<Segment>, via: Option<&str>, depth: usize) {
    // A variable assigned earlier in the same command line, in the clear, is
    // not unknown: `SNAPSHOT_FILE=/home/dev/.claude/…` on line one and
    // `>| "$SNAPSHOT_FILE"` on line four name the same file. The bindings
    // are collected in order and substituted, textually and once, into the
    // segments after them; nothing crosses into a nested `-c` string (its
    // own pass starts empty) and nothing comes from the environment.
    // A name assigned twice is the later value from that point on, which
    // is what the shell would do.
    let mut bindings: Vec<(String, String)> = Vec::new();
    let mut inner: Vec<Segment> = Vec::new();
    for mut seg in segments {
        if let Some(v) = via {
            seg.via = Some(v.to_string());
        }
        if !bindings.is_empty() {
            substitute_bindings(&mut seg, &bindings);
        }
        if let Some((name, value)) = simple_assignment(&seg) {
            bindings.retain(|(n, _)| n != &name);
            bindings.push((name, value));
            seg.binds = true;
        }
        inner.push(seg);
    }
    let snapshot = via.is_some() && claude_snapshot_inner(&inner).is_some();
    for mut seg in inner {
        // Scaffolding is only ever a harness's, and a harness only ever
        // speaks through a `-c` string; typed at the top level, the same
        // words are a person's command and are judged as one. Claude Code's
        // startup snapshot is scaffolding as a whole: recognised by its
        // first line and by every one of its writes going to the file that
        // line names (`claude_snapshot`).
        seg.scaffold = via.is_some() && (snapshot || harness_scaffold(&seg));
        let inner = if depth < MAX_WRAP_DEPTH {
            wrapped_command(&seg).or_else(|| wrapped_eval(&seg))
        } else {
            None
        };
        seg.wraps = inner.is_some();
        out.push(seg);
        if let Some((shell, script)) = inner {
            let label = if shell == "eval" {
                "eval".to_string()
            } else {
                format!("{shell} -c")
            };
            expand_into(out, split_segments(&script), Some(&label), depth + 1);
        }
    }
}

/// `NAME=value` or `export NAME=value` and nothing else: the name a shell
/// identifier, the value a literal — after the tokenizer's quote stripping,
/// no `$`, no backtick, no glob character, no whitespace and no shell
/// operator character — so substituting it into a later segment can change
/// which file that segment names and nothing about how it splits. Anything
/// else (`X=$Y`, `X=$(…)`, `X=*.log`, `X="a b"`, an assignment in front of a
/// command, a compound) binds nothing and reads as it always did.
fn simple_assignment(seg: &Segment) -> Option<(String, String)> {
    if !seg.redirects.is_empty() {
        return None;
    }
    let toks = crate::delete::tokenize_detailed(seg.command());
    let (word, exported) = match toks.as_slice() {
        [w] => (w, false),
        [e, w] if e.text == "export" => (w, true),
        _ => return None,
    };
    let _ = exported;
    let (name, value) = word.text.split_once('=')?;
    let ident = !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ident {
        return None;
    }
    // The raw text of the value decides, not the stripped one: `"$Y"` and
    // `$(…)` both strip to something that looks literal.
    let raw_value = seg
        .command()
        .split_once('=')
        .map(|(_, v)| v.trim())
        .unwrap_or("");
    const FORBIDDEN: &[char] = &[
        '$', '`', '*', '?', '[', ';', '&', '|', '<', '>', '(', ')', ' ', '\t', '\n', '\\',
    ];
    if raw_value.contains(FORBIDDEN) {
        return None;
    }
    if !word.single_quoted && value.contains(FORBIDDEN) {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

/// Replace `$NAME` and `${NAME}` for each bound name in the segment's text
/// and redirect targets. `$NAME` only where the name ends: `$NAMEX` is a
/// different variable and stays as written.
fn substitute_bindings(seg: &mut Segment, bindings: &[(String, String)]) {
    // `$NAME` and `${NAME}` outside single quotes; inside them the shell
    // expands nothing, so the text stays what it is. `$NAMEX` is a different
    // name and stays too.
    fn subst(text: &str, name: &str, value: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut in_single = false;
        let mut i = 0;
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' && !in_single && i + 1 < chars.len() {
                out.push(c);
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '\'' {
                in_single = !in_single;
                out.push(c);
                i += 1;
                continue;
            }
            if c == '$' && !in_single {
                let rest: String = chars[i + 1..].iter().collect();
                if let Some(after) = rest.strip_prefix('{') {
                    if let Some(tail) = after.strip_prefix(name) {
                        if tail.starts_with('}') {
                            out.push_str(value);
                            i += 1 + 1 + name.chars().count() + 1;
                            continue;
                        }
                    }
                } else if let Some(tail) = rest.strip_prefix(name) {
                    if !tail.chars().next().is_some_and(ident) {
                        out.push_str(value);
                        i += 1 + name.chars().count();
                        continue;
                    }
                }
            }
            out.push(c);
            i += 1;
        }
        out
    }
    if !seg.text.contains('$') {
        return;
    }
    for (name, value) in bindings {
        seg.text = subst(&seg.text, name, value);
        for r in &mut seg.redirects {
            r.target = subst(&r.target, name, value);
        }
    }
}

/// Claude Code's startup snapshot, run once per session as
/// `bash -c -l "SNAPSHOT_FILE=<path> …"` (42 segments) or the zsh form
/// (149): the first segment binds `SNAPSHOT_FILE` to the harness's own
/// snapshot file name (`is_claude_snapshot`), and every write in the string
/// goes to that file and nowhere else. Sourcing the user's rc and reading
/// aliases, functions and options into that file is what the script does;
/// judged segment by segment it was an unmatched ask on the assignment line
/// or a refused write on a head with no rule, and every wrapped session
/// opened with a refusal. Recognised whole, its segments are scaffolding:
/// transparent unless a rule names one — a hard stop inside a drifted
/// snapshot still fires — and, with nothing named, allowed under the reason
/// `claude_snapshot` returns. A write anywhere else, or a first line that
/// is not that binding, and the string is not a snapshot: judged as before.
fn claude_snapshot_inner(inner: &[Segment]) -> Option<(String, usize)> {
    let first = inner.first()?;
    if !first.binds {
        return None;
    }
    let (name, path) = simple_assignment(first)?;
    if name != "SNAPSHOT_FILE" || !is_claude_snapshot(&path) {
        return None;
    }
    for seg in inner {
        for r in &seg.redirects {
            if r.target.trim_matches('"') != path {
                return None;
            }
        }
    }
    Some((path, inner.len()))
}

/// The snapshot, seen from a deep split: the segments inside the first
/// wrapper. `Some((path, segments))` when they are Claude Code's startup
/// snapshot as `claude_snapshot_inner` defines it.
pub fn claude_snapshot(segs: &[Segment]) -> Option<(String, usize)> {
    let wrapper = segs.first()?;
    if !wrapper.wraps {
        return None;
    }
    let label = format!(
        "{} -c",
        crate::delete::tokenize_public(wrapper.command()).first()?
    );
    let inner: Vec<Segment> = segs
        .iter()
        .skip(1)
        .filter(|s| s.via.as_deref() == Some(label.as_str()))
        .cloned()
        .collect();
    claude_snapshot_inner(&inner)
}

/// The pieces Claude Code puts around every Bash tool call, as it sends
/// them (2.1.267 and 2.1.268, Sep 10, 2026). Matched on the segment's own
/// words with a leading backslash dropped (`\builtin` is how it spells the
/// builtin), so a redirect the piece carries — `2>/dev/null`, `>/dev/null
/// 2>&1` — does not enter the comparison. The `pwd -P` line is the one
/// piece that writes: a fresh `/tmp/claude-<hex>-cwd` per call, which is
/// how the harness learns the directory the command left the shell in.
fn harness_scaffold(seg: &Segment) -> bool {
    let words: Vec<String> = crate::delete::tokenize_public(seg.command())
        .into_iter()
        .map(|w| w.trim_start_matches('\\').to_string())
        .collect();
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    match w.as_slice() {
        ["shopt", "-u", "extglob"]
        | ["setopt", "NO_EXTENDED_GLOB", "NO_BARE_GLOB_QUAL"]
        | ["true"]
        | ["{", "builtin", "unalias", "--", "unsetenv"]
        | ["builtin", "unset", "-f", "--", "unsetenv"]
        | ["}"] => true,
        ["source", path] => is_claude_snapshot(path),
        ["pwd", "-P"] => {
            seg.redirects.len() == 1
                && seg.redirects[0].truncates
                && is_claude_cwd_file(&seg.redirects[0].target)
        }
        _ => false,
    }
}

/// `<home>/.claude/shell-snapshots/snapshot-<shell>-<digits>-<id>.sh`, the
/// file Claude Code writes at startup and sources before every command.
/// `source` runs whatever the file holds, so transparency here is only for
/// that file's own name: no `..` anywhere, and the three-part name exactly.
fn is_claude_snapshot(path: &str) -> bool {
    let Some((dir, file)) = path.rsplit_once('/') else {
        return false;
    };
    if !dir.ends_with("/.claude/shell-snapshots") || dir.split('/').any(|c| c == "..") {
        return false;
    }
    let Some(mid) = file
        .strip_prefix("snapshot-")
        .and_then(|r| r.strip_suffix(".sh"))
    else {
        return false;
    };
    let parts: Vec<&str> = mid.splitn(3, '-').collect();
    parts.len() == 3
        && parts[0].chars().all(|c| c.is_ascii_alphanumeric())
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && parts[2].chars().all(|c| c.is_ascii_alphanumeric())
        && parts.iter().all(|p| !p.is_empty())
}

/// `/tmp/claude-<hex>-cwd`, the one file the preamble writes: where the
/// command left the shell, for the harness to read back. Nothing else.
fn is_claude_cwd_file(target: &str) -> bool {
    target
        .strip_prefix("/tmp/claude-")
        .and_then(|r| r.strip_suffix("-cwd"))
        .is_some_and(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// `eval '<string>'` with exactly one operand that arrived inside single
/// quotes is the string, run as a command line: the shell expands nothing
/// in single quotes, so the text is the command verbatim. Read the same way
/// as a `-c` string, under the label `eval`. Claude Code runs the agent's
/// command through exactly this form. An `eval` with a double-quoted or
/// bare operand may expand before it runs and is not read; it stays a
/// segment the policy judges as typed, which is the default for `eval`.
fn wrapped_eval(seg: &Segment) -> Option<(String, String)> {
    let toks = crate::delete::tokenize_detailed(seg.command());
    let words: Vec<String> = toks.iter().map(|t| t.text.clone()).collect();
    let (head, at) = crate::delete::resolve_head(&words)?;
    if head != "eval" || toks.len() != at + 2 {
        return None;
    }
    let arg = &toks[at + 1];
    if !arg.single_quoted || arg.text.trim().is_empty() {
        return None;
    }
    Some((head, arg.text.clone()))
}

/// The command as the context check should read it: the segments that
/// decide, joined, with unnamed wrappers and harness scaffolding left out.
/// Claude Code's preamble carries `unset -f`, and read raw it was a
/// "destructive flag" on every command the agent ran, escalating each
/// allowed one to an ask (Sep 10, 2026). What remains here is what the
/// policy judged. A command with nothing to leave out is returned as typed;
/// one with nothing left after leaving out is empty.
pub fn context_text(command: &str) -> String {
    let segs = split_segments_deep(command);
    if segs.len() <= 1 {
        return command.to_string();
    }
    let kept: Vec<&str> = segs
        .iter()
        .filter(|s| !s.wraps && !s.scaffold && !s.binds)
        .map(|s| s.text.as_str())
        .collect();
    // Nothing left to judge - a `-c` string that is all preamble, or the
    // startup snapshot recognised whole - is nothing to read signals off:
    // returning the raw line here would hand `declare -f` and `unset -f`
    // back to the flag scan the reading just took them out of.
    kept.join("; ")
}

/// The shell and the string, when this segment is a POSIX shell running a
/// `-c` string. The head is resolved past `sudo`/`env` and by file stem, so
/// `sudo /bin/sh -c "…"` counts. The flag may be its own token or part of
/// a cluster — `bash -lc "…"` is how Codex spells it — and the string is the
/// token after it. `sh script.sh`, a bare `sh -c`, and a `-c` with nothing
/// after it are not read.
fn wrapped_command(seg: &Segment) -> Option<(String, String)> {
    let tokens = crate::delete::tokenize_public(seg.command());
    let (head, at) = crate::delete::resolve_head(&tokens)?;
    if !POSIX_SHELLS.contains(&head.as_str()) {
        return None;
    }
    // The same walk the wrap shim makes (#69): long options are stepped
    // over, `-o` takes an argument, `--` and `-` end the options, and the
    // first operand is a script file, which is not read.
    let mut i = at + 1;
    while let Some(tok) = tokens.get(i) {
        if tok == "--" || tok == "-" || !tok.starts_with('-') {
            return None; // end of options, or a script file
        }
        if tok == "-o" {
            i += 2;
            continue;
        }
        if !tok.starts_with("--") && tok[1..].contains('c') {
            // The string is the first operand after the options, not the
            // token after `-c`: a shell accepts options in any order, and
            // Claude Code spells its shell `zsh -c -l "..."` (measured
            // Sep 10, 2026, under `wrap`). Reading `-l` as the command made
            // every command the agent ran an unmatched ask.
            let mut j = i + 1;
            while let Some(t) = tokens.get(j) {
                if t == "--" {
                    j += 1;
                    break;
                }
                if t == "-" || !t.starts_with('-') {
                    break;
                }
                j += if t == "-o" { 2 } else { 1 };
            }
            let script = tokens.get(j)?;
            if script.trim().is_empty() {
                return None;
            }
            return Some((head, script.clone()));
        }
        i += 1;
    }
    None
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
    /// The text with every redirection left out — operator, descriptor and
    /// target — so a caller reading the command's own words does not take
    /// `2>/dev/null` for a file it deletes. Built by the split from the spans
    /// it found; nothing re-scans (#61).
    command: String,
    /// Files this segment writes over, in order of appearance.
    pub redirects: Vec<Overwrite>,
    /// The shell wrapper this segment was read through, as `sh -c`, when
    /// `split_segments_deep` found it inside a `-c` string. `None` for a
    /// segment typed at the top level (#62).
    pub via: Option<String>,
    /// True when this segment is a shell wrapper whose `-c` string was read
    /// and follows it as segments of its own. The policy treats such a
    /// segment as transparent unless a rule names it: the string inside
    /// decides, not the policy default applied to `sh` (#65, decision of
    /// 2026-09-03).
    pub wraps: bool,
    /// True when this segment is scaffolding a harness puts around the
    /// command it actually runs. Claude Code sends every Bash tool call as
    /// `shopt -u extglob 2>/dev/null || true && { \builtin unalias --
    /// 'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true
    /// && eval '<cmd>' < /dev/null && pwd -P >| /tmp/claude-<hex>-cwd`, with
    /// `setopt …` under zsh and a `source ~/.claude/shell-snapshots/….sh`
    /// in front when its snapshot exists (measured Sep 10, 2026, under
    /// `wrap`). Each of those pieces is recognised by exact form, and only
    /// inside a `-c` string; the policy treats it as transparent unless a
    /// rule names it, the same way it treats an unnamed wrapper. The
    /// command inside the `eval` decides. Anything the harness changes in
    /// that preamble stops matching and falls back to the default: closed.
    pub scaffold: bool,
    /// True when this segment is nothing but a simple assignment,
    /// `NAME=value` or `export NAME=value`, with a literal path-like value.
    /// It runs nothing; the value it binds has already been substituted into
    /// the segments after it (see `expand_into`), so the policy treats it as
    /// transparent unless a rule names it, and the context check leaves it
    /// out. Claude Code's startup snapshot opens with one
    /// (`SNAPSHOT_FILE=<path>`, then 41 or 148 segments using it), and read
    /// as an unmatched segment it was the whole reason the zsh form fell to
    /// the default (Sep 12, 2026, #94).
    pub binds: bool,
}

impl Segment {
    /// The segment's own words: program, flags and operands, with the
    /// redirections removed. `rm -rf ./cache > /dev/null 2>&1` reads
    /// `rm -rf ./cache`. Use this to find what a command acts on; use the
    /// `Deref` text to match rules against what was typed.
    pub fn command(&self) -> &str {
        &self.command
    }
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

fn flush(
    segments: &mut Vec<Segment>,
    cur: &mut String,
    redirects: &mut Vec<Overwrite>,
    source: &[char],
    seg_start: usize,
    spans: &mut Vec<(usize, usize)>,
) {
    let t = cur.trim();
    if !t.is_empty() {
        // The text is the source between separators, verbatim (every arm of
        // the walk pushes the characters it consumed), so the command is
        // the same source with the recorded spans left out.
        let command: String = source
            .iter()
            .enumerate()
            .filter(|(k, _)| {
                let at = seg_start + k;
                !spans.iter().any(|&(a, b)| a <= at && at < b)
            })
            .map(|(_, c)| *c)
            .collect();
        segments.push(Segment {
            text: t.to_string(),
            command: command.trim().to_string(),
            redirects: std::mem::take(redirects),
            via: None,
            wraps: false,
            scaffold: false,
            binds: false,
        });
    } else {
        // Nothing but whitespace between separators: whatever the redirect
        // scan collected has no segment to ride on. Unreachable in practice
        // (a redirect implies non-whitespace text), cleared for safety.
        redirects.clear();
    }
    spans.clear();
    cur.clear();
}

/// Does the command contain command substitution we cannot see inside?
/// The inner text of every command substitution in `s`: `$(…)` with its
/// parentheses balanced, and `` `…` ``. Single quotes hide both, as they do
/// for `has_substitution`. An unbalanced `$(` yields the rest of the string,
/// which no policy will allow, and that is the right answer for a
/// substitution the reader cannot see the end of.
pub fn substitutions(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut in_single = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\'' => {
                in_single = !in_single;
                i += 1;
            }
            '`' if !in_single => {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != '`' {
                    j += 1;
                }
                out.push(chars[start..j].iter().collect());
                i = j + 1;
            }
            '$' if !in_single && chars.get(i + 1) == Some(&'(') => {
                let start = i + 2;
                let mut depth = 1;
                let mut j = start;
                let mut inner_single = false;
                while j < chars.len() {
                    match chars[j] {
                        '\'' => inner_single = !inner_single,
                        '(' if !inner_single => depth += 1,
                        ')' if !inner_single => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                out.push(chars[start..j.min(chars.len())].iter().collect());
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// A substitution that is data rather than a command: `cat` fed a heredoc
/// with a quoted delimiter (`cat <<'EOF' … EOF`), which the shell expands
/// nothing inside. Claude Code writes every commit message this way
/// (`git commit -m "$(cat <<'EOF' … EOF)"`), and read as an unanalyzable
/// substitution it escalated every commit to an ask (replay of Sep 20,
/// 2026).
pub fn is_literal_heredoc(inner: &str) -> bool {
    let t = inner.trim_start();
    let Some(rest) = t.strip_prefix("cat") else {
        return false;
    };
    let rest = rest.trim_start();
    let Some(rest) = rest.strip_prefix("<<") else {
        return false;
    };
    let rest = rest.trim_start_matches('-').trim_start();
    rest.starts_with('\'') || rest.starts_with('"')
}

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
    fn the_command_text_leaves_every_redirection_out() {
        // (input, the command each segment reads as)
        for (cmd, want) in [
            ("rm -rf ./cache 2>/dev/null", vec!["rm -rf ./cache"]),
            ("rm -rf ./cache > /dev/null 2>&1", vec!["rm -rf ./cache"]),
            ("rm -rf ./cache >log 2>&1", vec!["rm -rf ./cache"]),
            ("rm -rf ./cache 2>&1 >/dev/null", vec!["rm -rf ./cache"]),
            ("cat /dev/null > src/main.rs", vec!["cat /dev/null"]),
            ("sort < in.txt > out.txt", vec!["sort"]),
            ("cmd &>all.log", vec!["cmd"]),
            ("cmd &>>all.log", vec!["cmd"]),
            ("echo a >> log", vec!["echo a"]),
            ("echo a >| log", vec!["echo a"]),
            ("cat > \"my file.txt\"", vec!["cat"]),
            ("rm > early -rf ./cache", vec!["rm  -rf ./cache"]),
            ("cat <<EOF\nbody\nEOF", vec!["cat", "body", "EOF"]),
            ("cat <<< word", vec!["cat"]),
            ("exec 3<&0", vec!["exec"]),
            ("exec 3<> /tmp/f", vec!["exec"]),
            // a digit that is part of a word is not a descriptor
            ("rm -rf ./cache2>log", vec!["rm -rf ./cache2"]),
            // process substitution is an operand, not a redirection
            ("tee >(gzip) file", vec!["tee >(gzip) file"]),
            ("diff <(ls a) <(ls b)", vec!["diff <(ls a) <(ls b)"]),
            // separators still split, and each side keeps its own words
            (
                "git status & rm -rf / 2>/dev/null",
                vec!["git status", "rm -rf /"],
            ),
            ("echo a > x && echo b > y", vec!["echo a", "echo b"]),
            // quoted operators are text, in both readings
            ("echo \"a > b\"", vec!["echo \"a > b\""]),
        ] {
            let segs = split_segments(cmd);
            let got: Vec<&str> = segs.iter().map(|s| s.command()).collect();
            assert_eq!(got, want, "{cmd}");
        }
    }

    /// The command text is derived; the text is what was typed. Adding the
    /// derivation must not have moved a single character of the text or a
    /// single recorded redirect.
    #[test]
    fn the_command_text_changes_nothing_about_the_text_or_the_redirects() {
        for (cmd, texts) in [
            (
                "rm -rf ./cache > /dev/null 2>&1",
                vec!["rm -rf ./cache > /dev/null 2>&1"],
            ),
            ("sort < in.txt > out.txt", vec!["sort < in.txt > out.txt"]),
            ("cat <<EOF\nbody\nEOF", vec!["cat <<EOF", "body", "EOF"]),
            ("exec 3<&0", vec!["exec 3<&0"]),
            ("tee >(gzip) file", vec!["tee >(gzip) file"]),
            ("cat > \"my file.txt\"", vec!["cat > \"my file.txt\""]),
            ("echo \"a > b\"", vec!["echo \"a > b\""]),
            ("git status & rm -rf /", vec!["git status", "rm -rf /"]),
        ] {
            let segs = split_segments(cmd);
            let got: Vec<&str> = segs.iter().map(|s| &**s).collect();
            assert_eq!(got, texts, "{cmd}: the text is verbatim");
        }
        let targets =
            |cmd: &str| -> Vec<String> { redirects(cmd).into_iter().map(|o| o.target).collect() };
        assert_eq!(targets("rm -rf ./cache >log 2>&1"), vec!["log"]);
        assert_eq!(targets("cat > \"my file.txt\""), vec!["my file.txt"]);
        assert!(redirects("sort < in.txt").is_empty());
        // a segment without redirections reads the same both ways
        let seg = &split_segments("rm -rf ./cache")[0];
        assert_eq!(seg.command(), &**seg);
    }

    /// #62. A POSIX shell's -c string is read as segments of its own,
    /// after the wrapper, each marked with the wrapper it came through.
    /// Claude Code spells its shell `zsh -c -l "..."`, options after `-c`
    /// (captured under `wrap`, Sep 10, 2026). The string is the first
    /// operand after the options, whichever side of `-c` they sit on.
    #[test]
    fn options_after_dash_c_are_stepped_over() {
        for cmd in [
            r#"zsh -c -l "rm -rf ./dist""#,
            r#"bash -c -e -o pipefail "rm -rf ./dist""#,
            r#"sh -c -- "rm -rf ./dist""#,
        ] {
            let segs = split_segments_deep(cmd);
            assert!(
                segs.iter().any(|s| s.command().contains("rm -rf ./dist")
                    && !s.command().starts_with("zsh")
                    && !s.command().starts_with("bash")
                    && !s.command().starts_with("sh")),
                "the inner command must be its own segment for {cmd}: {:?}",
                segs.iter()
                    .map(|s| s.command().to_string())
                    .collect::<Vec<_>>()
            );
        }
        // Nothing after the options is not a -c string.
        assert_eq!(split_segments_deep("sh -c -l").len(), 1);
    }

    #[test]
    fn a_posix_shell_c_string_is_read_as_its_own_segments() {
        let segs = split_segments_deep(r#"sh -c "cat /dev/null > src/main.rs""#);
        let texts: Vec<&str> = segs.iter().map(|s| &**s).collect();
        assert_eq!(
            texts,
            [
                r#"sh -c "cat /dev/null > src/main.rs""#,
                "cat /dev/null > src/main.rs"
            ]
        );
        assert_eq!(segs[0].via, None, "the wrapper was typed at the top level");
        assert_eq!(segs[1].via.as_deref(), Some("sh -c"));
        assert!(
            segs[0].redirects.is_empty(),
            "the quoted `>` is text to the wrapper"
        );
        assert_eq!(segs[1].redirects[0].target, "src/main.rs");

        // Codex's spelling: the flag in a cluster, a compound inside.
        let segs = split_segments_deep(r#"bash -lc "rm -rf ./dist && echo done""#);
        let texts: Vec<&str> = segs.iter().map(|s| &**s).collect();
        assert_eq!(
            texts,
            [
                r#"bash -lc "rm -rf ./dist && echo done""#,
                "rm -rf ./dist",
                "echo done"
            ]
        );
        assert!(segs[1..]
            .iter()
            .all(|s| s.via.as_deref() == Some("bash -c")));

        // Resolved past sudo and by file stem; every shell on the list.
        for cmd in [
            r#"sudo sh -c "rm -rf ./dist""#,
            r#"/bin/sh -c "rm -rf ./dist""#,
            r#"dash -c "rm -rf ./dist""#,
            r#"zsh -ec "rm -rf ./dist""#,
            r#"sh -e -c "rm -rf ./dist""#,
            r#"bash --norc -c "rm -rf ./dist""#,
            r#"bash -o pipefail -c "rm -rf ./dist""#,
            "sh -c 'rm -rf ./dist'",
        ] {
            let segs = split_segments_deep(cmd);
            assert_eq!(segs.len(), 2, "{cmd}");
            assert_eq!(&*segs[1], "rm -rf ./dist", "{cmd}");
        }

        // The wrapper's own redirect stays on the wrapper.
        let segs = split_segments_deep(r#"sh -c "echo hi" > out.log"#);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].redirects[0].target, "out.log");
        assert!(segs[1].redirects.is_empty());
        assert_eq!(&*segs[1], "echo hi");
    }

    /// Claude Code's Bash tool call, verbatim from the audit log of the first
    /// routed session (Sep 10, 2026): every piece around the `eval` is
    /// scaffolding, the `eval` is a wrapper, and the agent's command follows
    /// it as segments of its own. The zsh form and the form with a snapshot
    /// to source are read the same way. The preamble's `unset -f` is left
    /// out of the text the context check reads.
    #[test]
    fn claude_codes_preamble_is_scaffolding_and_its_eval_is_read() {
        let bash = r#"bash -c -l "shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'ls -la /home/dev/proj/ 2>&1; echo \"--- scratch check ---\"; ls -la /home/dev/proj/scratch 2>&1' < /dev/null && pwd -P >| /tmp/claude-c32c-cwd""#;
        let segs = split_segments_deep(bash);
        let texts: Vec<&str> = segs.iter().map(|s| &**s).collect();
        assert_eq!(
            texts,
            [
                bash,
                "shopt -u extglob 2>/dev/null",
                "true",
                r"{ \builtin unalias -- 'unsetenv'",
                r"\builtin unset -f -- 'unsetenv'",
                "} >/dev/null 2>&1",
                "true",
                r#"eval 'ls -la /home/dev/proj/ 2>&1; echo "--- scratch check ---"; ls -la /home/dev/proj/scratch 2>&1' < /dev/null"#,
                "ls -la /home/dev/proj/ 2>&1",
                r#"echo "--- scratch check ---""#,
                "ls -la /home/dev/proj/scratch 2>&1",
                "pwd -P >| /tmp/claude-c32c-cwd",
            ]
        );
        let scaffold: Vec<bool> = segs.iter().map(|s| s.scaffold).collect();
        assert_eq!(
            scaffold,
            [false, true, true, true, true, true, true, false, false, false, false, true]
        );
        assert!(
            segs[0].wraps && segs[7].wraps,
            "the shell and the eval are wrappers"
        );
        assert_eq!(segs[8].via.as_deref(), Some("eval"));
        assert_eq!(segs[10].via.as_deref(), Some("eval"));
        assert_eq!(
            context_text(bash),
            r#"ls -la /home/dev/proj/ 2>&1; echo "--- scratch check ---"; ls -la /home/dev/proj/scratch 2>&1"#,
            "the context check reads the agent's command, not the preamble"
        );
        assert!(!context_text(bash).contains("unset -f"));

        let zsh = r#"zsh -c -l "setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'rm -rf ./scratch' < /dev/null && pwd -P >| /tmp/claude-b1de-cwd""#;
        let segs = split_segments_deep(zsh);
        let inner: Vec<&str> = segs
            .iter()
            .filter(|s| !s.wraps && !s.scaffold)
            .map(|s| &**s)
            .collect();
        assert_eq!(inner, ["rm -rf ./scratch"]);
        assert_eq!(context_text(zsh), "rm -rf ./scratch");

        let sourced = r#"bash -c "source /home/dev/.claude/shell-snapshots/snapshot-bash-1789077199590-d2kylp.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && eval 'git status' < /dev/null && pwd -P >| /tmp/claude-0a1b-cwd""#;
        let segs = split_segments_deep(sourced);
        assert!(segs[1].scaffold, "sourcing its own snapshot: {}", &*segs[1]);
        let inner: Vec<&str> = segs
            .iter()
            .filter(|s| !s.wraps && !s.scaffold)
            .map(|s| &**s)
            .collect();
        assert_eq!(inner, ["git status"]);
    }

    /// What `substitutions` sees: each `$(…)` with its parentheses balanced,
    /// each backtick pair, nothing inside single quotes, and an unbalanced
    /// `$(` as the rest of the line. And what a literal heredoc is: `cat`
    /// with a quoted delimiter, in either quote, with or without `-`.
    #[test]
    fn substitutions_are_extracted_balanced_and_a_quoted_heredoc_is_literal() {
        assert_eq!(
            substitutions("git log origin/$(git branch --show-current) -1"),
            ["git branch --show-current"]
        );
        assert_eq!(
            substitutions("echo $(dirname $(pwd)) `whoami`"),
            ["dirname $(pwd)", "whoami"]
        );
        assert_eq!(substitutions("echo '$(not one)'"), Vec::<String>::new());
        assert_eq!(substitutions("echo $(unbalanced"), ["unbalanced"]);
        assert_eq!(
            substitutions("git commit -m \"$(cat <<'EOF'\nfeat: x (y)\nEOF\n)\""),
            ["cat <<'EOF'\nfeat: x (y)\nEOF\n"]
        );
        assert!(is_literal_heredoc("cat <<'EOF'\nbody\nEOF\n"));
        assert!(is_literal_heredoc("cat <<\"EOF\"\nbody\nEOF\n"));
        assert!(is_literal_heredoc("cat <<-'EOF'\n\tbody\n\tEOF\n"));
        assert!(
            !is_literal_heredoc("cat <<EOF\n$HOME\nEOF\n"),
            "unquoted: expands"
        );
        assert!(!is_literal_heredoc("cat file"));
        assert!(!is_literal_heredoc("rm -rf /"));
    }

    /// Claude Code's startup snapshot, in the shape the record holds (Sep
    /// 10–12, 2026): the first line binds `SNAPSHOT_FILE`, every write goes
    /// there, and the heredoc bodies are the harness's own text. The binding
    /// substitutes into every later segment, the assignment segment is
    /// transparent, the snapshot is recognised whole, and a write anywhere
    /// else or a different first line makes it an ordinary string again.
    #[test]
    fn a_variable_bound_earlier_in_the_string_resolves_and_the_snapshot_is_recognised() {
        let script = concat!(
            "SNAPSHOT_FILE=/home/dev/.claude/shell-snapshots/snapshot-bash-1789080866426-67di03.sh\n",
            "      source \"/home/dev/.bashrc\" < /dev/null\n",
            "      # First, create/clear the snapshot file\n",
            "      echo \"# Snapshot file\" >| \"$SNAPSHOT_FILE\"\n",
            "      echo \"unalias -a 2>/dev/null || true\" >> \"$SNAPSHOT_FILE\"\n",
            "      cat >> \"$SNAPSHOT_FILE\" << 'RIPGREP_FUNC_END'\n",
            "  function rg {\n",
            "  local _cc_bin=\"${CLAUDE_CODE_EXECPATH:-}\"\n",
            "  [[ -x $_cc_bin ]] || _cc_bin=/home/dev/.local/bin/claude\n",
            "  if [[ ! -x $_cc_bin ]]; then command rg ${1+\"$@\"}; return; fi\n",
            "}\n",
            "RIPGREP_FUNC_END\n",
            "      declare -f | head -n 1000 >> \"$SNAPSHOT_FILE\"\n",
            "      cat >> \"$SNAPSHOT_FILE\" << 'PATH_END_f5fnw4s2sag'\n",
            "export PATH=/home/dev/.termaxa/shims:/home/dev/.local/bin:/usr/bin:/bin\n",
            "PATH_END_f5fnw4s2sag\n",
            "      if [ ! -f \"$SNAPSHOT_FILE\" ]; then\n",
            "        echo \"Error: Snapshot file was not created at $SNAPSHOT_FILE\" >&2\n",
            "        exit 1\n",
            "      fi\n",
        );
        let path = "/home/dev/.claude/shell-snapshots/snapshot-bash-1789080866426-67di03.sh";
        let argv: Vec<String> = ["bash", "-c", "-l", script]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let command = crate::runner::shell_join(&argv);
        let segs = split_segments_deep(&command);
        assert!(segs[0].wraps);
        assert!(
            segs[1].binds,
            "the first inner segment binds: {}",
            &*segs[1]
        );
        assert_eq!(&*segs[1], &format!("SNAPSHOT_FILE={path}"));
        let writes: Vec<&str> = segs
            .iter()
            .flat_map(|s| s.redirects.iter())
            .map(|r| r.target.as_str())
            .collect();
        assert!(!writes.is_empty());
        assert!(
            writes.iter().all(|t| t.trim_matches('"') == path),
            "every write resolved to the bound path: {writes:?}"
        );
        assert!(
            segs.iter().skip(1).all(|s| s.scaffold),
            "recognised whole: every inner segment is scaffolding"
        );
        let (found, n) = claude_snapshot(&segs).expect("the snapshot is recognised");
        assert_eq!(found, path);
        assert_eq!(n, segs.len() - 1);
        assert!(
            !context_text(&command).contains("-f"),
            "{}",
            context_text(&command)
        );

        // A second binding of the same name is the later value from then on.
        let segs = split_segments_deep("X=/a; echo one > $X; X=/b; echo two > $X");
        let targets: Vec<&str> = segs
            .iter()
            .flat_map(|s| s.redirects.iter())
            .map(|r| r.target.as_str())
            .collect();
        assert_eq!(targets, ["/a", "/b"]);

        // A write anywhere else: not a snapshot, judged as before.
        let drifted = script.replace(
            "declare -f | head -n 1000 >> \"$SNAPSHOT_FILE\"",
            "declare -f | head -n 1000 >> /home/dev/.bashrc",
        );
        let argv: Vec<String> = ["bash", "-c", "-l", drifted.as_str()]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let segs = split_segments_deep(&crate::runner::shell_join(&argv));
        assert!(claude_snapshot(&segs).is_none());
        assert!(segs.iter().skip(1).any(|s| !s.scaffold));

        // A first line binding some other name, or a path outside the
        // harness's own: not a snapshot.
        for first in [
            "SNAPSHOT_FILE=/home/dev/notes.sh",
            "OTHER=/home/dev/.claude/shell-snapshots/snapshot-bash-1-a.sh",
            "SNAPSHOT_FILE=/home/dev/.claude/shell-snapshots/../../x/snapshot-bash-1-a.sh",
        ] {
            let cmd = format!(r#"bash -c "{first}; echo hi >| \"$SNAPSHOT_FILE\"""#);
            assert!(
                claude_snapshot(&split_segments_deep(&cmd)).is_none(),
                "{first}"
            );
        }
    }

    /// What binds and what does not: a literal path-like value binds, with
    /// or without `export`, quoted or bare, empty included; anything the
    /// shell would still expand, glob or split does not; single quotes keep
    /// a `$` literal; a name that merely starts with the bound one is not it.
    #[test]
    fn only_a_literal_assignment_binds_and_only_outside_single_quotes() {
        let bound = |cmd: &str| -> Vec<String> {
            split_segments_deep(cmd)
                .iter()
                .filter(|s| !s.binds)
                .map(|s| s.text.clone())
                .collect()
        };
        assert_eq!(bound("X=/tmp/a; rm -rf $X"), ["rm -rf /tmp/a"]);
        assert_eq!(bound("export X=/tmp/a; rm -rf ${X}/b"), ["rm -rf /tmp/a/b"]);
        assert_eq!(bound("X='/tmp/a'; rm -rf $X"), ["rm -rf /tmp/a"]);
        assert_eq!(bound("X=\"/tmp/a\"; rm -rf $X"), ["rm -rf /tmp/a"]);
        assert_eq!(
            bound("X=; rm -rf $X/*"),
            ["rm -rf /*"],
            "an empty value binds"
        );
        assert_eq!(bound("X=/tmp/a; rm -rf $XY"), ["rm -rf $XY"]);
        assert_eq!(bound("X=/tmp/a; rm -rf '$X'"), ["rm -rf '$X'"]);
        for not_bound in [
            "X=$Y; rm -rf $X",
            "X=$(pwd); rm -rf $X",
            "X=`pwd`; rm -rf $X",
            "X=*.log; rm -rf $X",
            "X=\"a b\"; rm -rf $X",
            "X=/tmp/a rm -rf $X",
            "if true; then X=/tmp/a; fi; rm -rf $X",
        ] {
            let segs = split_segments_deep(not_bound);
            let last = segs.last().unwrap();
            assert!(
                last.text.contains("$X"),
                "{not_bound}: nothing bound, read as written: {}",
                last.text
            );
        }
        // A binding does not cross into a nested `-c` string.
        let segs = split_segments_deep(r#"X=/tmp/a; sh -c "rm -rf $X""#);
        let inner = segs.iter().find(|s| s.via.is_some()).unwrap();
        assert!(inner.text.contains("$X"), "{}", inner.text);
        assert!(!split_segments_deep("rm -rf x")[0].binds);
        assert!(split_segments_deep("X=1")[0].binds);
    }

    /// What the scaffolding reading leaves alone: the same words typed at
    /// the top level, a preamble that drifted, a `source` of anything but
    /// the harness's own snapshot, a `pwd` writing anywhere else, and an
    /// `eval` whose operand the shell could still expand.
    #[test]
    fn what_the_scaffolding_reading_leaves_alone() {
        for top in ["shopt -u extglob", "true", "pwd -P >| /tmp/claude-c32c-cwd"] {
            let segs = split_segments_deep(top);
            assert!(!segs[0].scaffold, "typed at the top level: {top}");
        }
        for inside in [
            "shopt -u extglob nullglob 2>/dev/null",
            "setopt NO_EXTENDED_GLOB 2>/dev/null",
            r"\\builtin unset -f -- 'rm'",
            "source /home/dev/.bashrc 2>/dev/null",
            "source /home/dev/.claude/shell-snapshots/../../.bashrc 2>/dev/null",
            "pwd -P >| /home/dev/notes.txt",
            "pwd -P >> /tmp/claude-c32c-cwd",
            "pwd >| /tmp/claude-c32c-cwd",
        ] {
            let segs = split_segments_deep(&format!(r#"bash -c "{inside}""#));
            assert_eq!(segs.len(), 2, "{inside}");
            assert!(!segs[1].scaffold, "not the measured form: {inside}");
        }
        // The snapshot path check is on the path, not on the word `source`.
        let ok = split_segments_deep(
            r#"bash -c "source /Users/x/.claude/shell-snapshots/snapshot-zsh-1-abc.sh 2>/dev/null""#,
        );
        assert!(ok[1].scaffold);

        for not_read in [
            r#"eval "$cmd""#,
            "eval $cmd",
            "eval 'ls' 'more'",
            "eval",
            "eval ''",
        ] {
            let segs = split_segments_deep(not_read);
            assert_eq!(segs.len(), 1, "{not_read}");
            assert!(!segs[0].wraps, "{not_read}");
        }
        // A single-quoted eval is read wherever it stands, and a wrapper
        // inside the eval is read on too.
        let segs = split_segments_deep("eval 'sh -c \"rm -rf ./dist\"'");
        let texts: Vec<&str> = segs.iter().map(|s| &**s).collect();
        assert_eq!(
            texts,
            [
                "eval 'sh -c \"rm -rf ./dist\"'",
                "sh -c \"rm -rf ./dist\"",
                "rm -rf ./dist"
            ]
        );
        assert_eq!(segs[1].via.as_deref(), Some("eval"));
        assert_eq!(segs[2].via.as_deref(), Some("sh -c"));
        // A line with nothing to leave out reads as typed.
        assert_eq!(context_text("git push --force"), "git push --force");
        assert_eq!(context_text("ls && rm -rf x"), "ls; rm -rf x");
    }

    /// What is deliberately not read: a script file, a bare `-c`, a shell
    /// off the list, and the string beyond the depth limit.
    #[test]
    fn what_a_shell_wrapper_reading_leaves_alone() {
        for cmd in [
            "sh deploy.sh",
            "bash ./scripts/clean.sh --force",
            "sh -c",
            "sh -c \"\"",
            r#"fish -c "rm -rf ./dist""#,
            r#"ksh -c "rm -rf ./dist""#,
            r#"python -c "import shutil; shutil.rmtree('dist')""#,
            "sh - script.sh",
            "bash --norc script.sh",
        ] {
            let segs = split_segments_deep(cmd);
            assert_eq!(segs.len(), 1, "{cmd}");
            assert_eq!(segs[0].via, None, "{cmd}");
        }
        // Nesting is read to the limit and no further.
        let two = r#"sh -c "bash -c 'rm -rf ./dist'""#;
        let segs = split_segments_deep(two);
        let texts: Vec<&str> = segs.iter().map(|s| &**s).collect();
        assert_eq!(texts, [two, "bash -c 'rm -rf ./dist'", "rm -rf ./dist"]);
        assert_eq!(segs[1].via.as_deref(), Some("sh -c"));
        assert_eq!(segs[2].via.as_deref(), Some("bash -c"));
        // Six wrappers deep, double-quoted with the inner quotes escaped.
        let mut deep = "rm -rf ./dist".to_string();
        for _ in 0..6 {
            deep = format!(
                "sh -c \"{}\"",
                deep.replace('\\', "\\\\").replace('"', "\\\"")
            );
        }
        let segs = split_segments_deep(&deep);
        assert_eq!(
            segs.len(),
            MAX_WRAP_DEPTH + 1,
            "one wrapper per level, then stop"
        );
        assert_ne!(
            &*segs[MAX_WRAP_DEPTH], "rm -rf ./dist",
            "the innermost string was not reached"
        );
        // The plain split is unchanged: one segment, no reading through.
        assert_eq!(split_segments(two).len(), 1);
    }

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

    /// Kills predicted survivors 1-3 from the suppressions-retirement
    /// commit, before the mutation pass runs. Each leg names its mutant.
    #[test]
    fn the_predicted_survivors_are_killed() {
        // 1. `i > 0` -> `i >= 0` in prev_is_amp / prev_is_lt: a command
        // BEGINNING with `>` must extract its target without underflowing.
        let r = redirects("> x");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, "x");
        assert!(r[0].truncates);
        assert!(!redirects(">> log").is_empty());
        // 2. `truncates &&` -> `||` in the clobber check: `>>|` is not an
        // operator anywhere - bash rejects it and nothing runs, so any
        // segmentation is safe. The walk splits at the `|` (only `>|`
        // consumes one), extracting no target; the mutant would merge the
        // segments and invent a redirect on `x`.
        let segs = split_segments("cmd >>| x");
        assert_eq!(segs, vec!["cmd >>", "x"]);
        assert!(segs.iter().all(|s| s.redirects.is_empty()));
        // 3. `j + 1 < len` -> `<=` in the target escape arm: a trailing
        // backslash in TARGET position is a literal, kept in the target as
        // backslashes always are, and must not read past the end.
        let r = redirects(r"cmd > a\");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, r"a\");
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
