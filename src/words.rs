//! The words a shell makes of one.
//!
//! Before a command sees its arguments the shell has opened them. A brace
//! list or a range becomes its words (`.claud{e,x}` is `.claude .claudx`,
//! `.claud{e..e}` is `.claude`), and a word with a pattern in it becomes
//! the names it matches on disk (`.clau[d]e`, `.cl?ude`, `.cl*`). Every
//! reader in this crate read such a word as the name it spells, which is a
//! name no rule has: `echo x > .clau[d]e/settings.json` wrote Claude
//! Code's hook config through `echo *`, in both modes, from v0.14.2 on, the
//! first release that refused the plain spelling (measured Nov 16, 2026,
//! release by release, each line run by bash and by zsh).
//!
//! `opened_until` respells one segment the way the shell hands it to the
//! command, and the policy judges that spelling beside the one that was
//! typed (`Policy::judge_command`): a rule that denies what the shell runs
//! denies the line. `directory` is the same reading for the one word of a
//! `cd`.
//!
//! What is opened is what bash opens with its defaults, and zsh with it:
//! braces first, then `*`, `?` and `[…]` in any component of a path, a
//! name that starts with a dot only by a pattern that starts with one.
//! Read as the walk in `shell.rs` reads a line: a quote or a backslash
//! takes a character's meaning, nothing is opened in a comment or after the
//! line's first newline (a heredoc's body is the file's contents), and a
//! word that holds something only the running shell can open (`$X`, `$(
//! … )`) has its braces opened and its patterns left.
//!
//! Where a word matches nothing the shell hands over the word itself, and
//! so does this.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A brace list is opened into at most this many words. A longer one is
/// not read at all, and the policy refuses the line (`Opened::unread`): a
/// list too long to read is a way to carry one name past every rule.
pub const MOST_WORDS: usize = 100_000;

/// The words one word may open into and still be written out whole. Past
/// this, only the ones a deny rule could be about are (`opened_until`'s `keep`):
/// `rm -rf node_modules/*` is fifteen hundred names nobody guards, and the
/// line with all of them written out is one every rule has to read. A word
/// with more than this many that a rule could be about, or one that takes
/// longer than `LONGEST_ASKING` to ask about, is not read at all
/// (`Opened::unread`).
const MOST_KEPT: usize = 64;
const LONGEST_ASKING: Duration = Duration::from_secs(1);

/// The directory entries, and the names looked up, one word's patterns may
/// read, and for how long. Past either the word is not read at all
/// (`Opened::unread`), and so is every word left once the opening of a
/// whole line has taken `LONGEST_LINE` (`opened_until`). A pattern left as
/// written past a budget is a name no path rule sees, and before v0.25.2
/// one word could spend the budget of every word after it: `cat x
/// /*/*/*/*/none > .clau[d]e/settings.json` wrote the hook config past the
/// rule that guards it. And a check that runs past the harness's own
/// timeout is no check in most of them: the command runs. In tests the
/// entries are 1,000, so that a test can spend them with a directory it
/// makes.
const MOST_ENTRIES: usize = if cfg!(test) { 1_000 } else { 100_000 };
const LONGEST: Duration = Duration::from_secs(1);
pub const LONGEST_LINE: Duration = Duration::from_secs(4);

/// A group of alternatives inside a word, as `shell::group_as_pattern`
/// writes it for this module to read: zsh's `.claud(e|x)` and ksh's
/// `@(e|x)` arrive as `GROUP_OPENS e GROUP_OR x GROUP_CLOSES`. Private-use
/// characters, which the walk gives no meaning to: the `|` of a group is
/// not a pipe. A line typed with one of these in it is read as holding a
/// group, which only ever adds a name for a rule to see.
pub const GROUP_OPENS: char = '\u{e000}';
pub const GROUP_OR: char = '\u{e001}';
pub const GROUP_CLOSES: char = '\u{e002}';

/// The flat patterns a group may be written out into before it is read as
/// `*` instead, which matches whatever any of them would.
const MOST_ALTERNATIVES: usize = 256;

/// One piece of a word, as the shell has it after its quotes are read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    /// A character, and whether a quote or a backslash took its meaning.
    Ch(char, bool),
    /// Something only the running shell can open, as written: `$X`, `${X}`,
    /// `$( … )`, a backtick pair, a double-quoted stretch that holds one.
    Opaque(String),
}

/// What `opened_until` made of a segment.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Opened {
    /// The segment with its words opened, when that is not the segment as
    /// written.
    pub text: Option<String>,
    /// A word in it opens into more than `MOST_WORDS` words, or into more
    /// than `MOST_KEPT` that a rule could be about, or into more than there
    /// was time to ask about, and nothing read them.
    pub unread: bool,
}

/// What a line has told its shell about patterns, where that widens what
/// one matches: `shopt -s dotglob` and zsh's `setopt globdots` let `*`
/// match a name that starts with a dot, and `nocaseglob` takes case out of
/// the comparison. Read off the line's own words (`loosened`): an option
/// the shell was started with is not known here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Loose {
    pub dots: bool,
    pub case: bool,
}

/// The options `line` names, anywhere in it: a line that says `dotglob`
/// is read with it on from its first word, which is more than the shell
/// does and never less.
pub fn loosened(line: &str) -> Loose {
    if !line.to_ascii_lowercase().contains("glob") {
        return Loose::default();
    }
    // zsh takes an option's name in any case and with underscores.
    let named: String = line
        .chars()
        .filter(|c| *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    Loose {
        dots: named.contains("dotglob") || named.contains("globdots"),
        case: named.contains("caseglob"),
    }
}

/// How much of the disk the patterns of one word may still read: its own
/// entries and time, and no later than the line's end (`line`).
struct Budget {
    entries: usize,
    until: Instant,
    spent: bool,
}

impl Budget {
    fn new(line: Option<Instant>) -> Self {
        let own = Instant::now() + LONGEST;
        Self {
            entries: MOST_ENTRIES,
            until: line.map_or(own, |line| line.min(own)),
            spent: false,
        }
    }

    /// One more directory entry or name looked up; false once the budget
    /// is gone. The clock is read every time: one entry on a cold disk or
    /// a network share can take as long as thousands on a warm one.
    fn entry(&mut self) -> bool {
        if self.spent {
            return false;
        }
        if self.entries == 0 || Instant::now() > self.until {
            self.spent = true;
            return false;
        }
        self.entries -= 1;
        true
    }
}

/// A character that ends a word wherever it stands outside quotes.
fn ends_word(c: char) -> bool {
    c.is_whitespace() || matches!(c, ';' | '&' | '|' | '<' | '>' | '(' | ')')
}

/// A character the walk gives no meaning to wherever it stands in a word.
fn plain(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '+' | ',' | ':' | '@' | '%' | '=')
}

/// `segment` as the shell hands it to the command: each word with its
/// brace lists and ranges opened and its patterns replaced by what they
/// match, read from `dir` (`None` when the directory the segment runs in is
/// not known: braces are opened, which need no disk, and patterns are
/// not).
///
/// `keep` is asked only about a word that opens into more than
/// `MOST_KEPT`: whether a deny rule could be about this one of its words,
/// told the operator before it when the word is a redirection's target,
/// since a rule written with the operator (`*> /etc/*`) is about the word
/// in that place. Those are written out and the rest are left out; a word
/// none of whose words is kept stays as written.
///
/// A redirection's target that opens into several words is written as one
/// redirection each: bash refuses such a line and zsh writes every one of
/// them, so each is a file the line may write.
///
/// Each word reads the disk on a budget of its own (`Budget`): what one
/// word spends, no later word goes without. And no word is read past
/// `line`, the time the opening of the whole line ends, `LONGEST_LINE`
/// after it began: every word not read by then is unread
/// (`Opened::unread`).
pub fn opened_until(
    segment: &str,
    dir: Option<&Path>,
    loose: Loose,
    keep: &dyn Fn(&str, Option<&str>) -> bool,
    line: Option<Instant>,
) -> Opened {
    if !segment.contains(['*', '?', '[', '{', GROUP_OPENS]) {
        return Opened::default();
    }
    let chars: Vec<char> = segment.chars().collect();
    let mut out = String::with_capacity(segment.len() + 16);
    let mut changed = false;
    let mut unread = false;
    // What stands between the last word and this one.
    let mut gap = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // The line ends here: what follows is another line, or a heredoc's
        // body, and neither is this command's words.
        if c == '\n' {
            break;
        }
        if ends_word(c) {
            out.push(c);
            gap.push(c);
            i += 1;
            continue;
        }
        // A comment, to the end of the line: no shell opens a word of it.
        if c == '#' {
            break;
        }
        let (pieces, end) = read_word(&chars, i);
        let raw: String = chars[i..end].iter().collect();
        let operator = redirection(&gap);
        let ask = |word: &str| keep(word, operator);
        let mut budget = Budget::new(line);
        match open_word(&pieces, dir, loose, &mut budget, &ask) {
            Opening::AsWritten => out.push_str(&raw),
            Opening::Unread => {
                unread = true;
                out.push_str(&raw);
            }
            Opening::Words(words) => {
                changed = true;
                for (n, word) in words.iter().enumerate() {
                    if n > 0 {
                        out.push(' ');
                        if let Some(op) = operator {
                            out.push_str(op);
                            out.push(' ');
                        }
                    }
                    out.push_str(&spelled(word));
                }
            }
        }
        gap.clear();
        i = end;
    }
    out.extend(chars[i..].iter());
    Opened {
        text: changed.then_some(out),
        unread,
    }
}

/// The redirection operator `gap` is, when the word after it is a
/// redirection's target: `>`, `>>`, `>|`, `&>`, `<>` and their kind.
fn redirection(gap: &str) -> Option<&str> {
    let op = gap.trim();
    (op.contains('>') && op.chars().all(|c| matches!(c, '>' | '<' | '&' | '|'))).then_some(op)
}

/// Where a `cd` goes when its word holds a brace list or a pattern.
#[derive(Debug, PartialEq, Eq)]
pub enum Goes {
    /// The one directory the word opens into.
    To(PathBuf),
    /// Nothing matches it: the shell hands `cd` the word as written.
    AsWritten,
    /// Several words, or one that is no directory: `cd` fails, or the shell
    /// chooses, and where the line goes from there is not known.
    NotKnown,
}

/// `word`, the argument of a `cd` with its quotes already off, opened from
/// `dir`.
pub fn directory(word: &str, dir: &Path) -> Goes {
    let chars: Vec<char> = word.chars().collect();
    let pieces: Vec<Piece> = chars.iter().map(|c| Piece::Ch(*c, false)).collect();
    let Ok(words) = braces(&pieces, MOST_KEPT) else {
        return Goes::NotKnown;
    };
    let [one] = words.as_slice() else {
        return Goes::NotKnown;
    };
    if !has_pattern(one) {
        return Goes::To(crate::delete::resolve_path_in(&text_of(one), dir));
    }
    let mut budget = Budget::new(None);
    match matches(one, dir, Loose::default(), &mut budget).as_deref() {
        Some([]) => Goes::AsWritten,
        Some([only]) => {
            let path = crate::delete::resolve_path_in(only, dir);
            if path.is_dir() {
                Goes::To(path)
            } else {
                Goes::NotKnown
            }
        }
        _ => Goes::NotKnown,
    }
}

/// Whether `word`, a token with its quotes off, holds anything `directory`
/// opens: a pattern or a brace list.
pub fn is_opened(word: &str) -> bool {
    let pieces: Vec<Piece> = word.chars().map(|c| Piece::Ch(c, false)).collect();
    has_pattern(&pieces) || braces(&pieces, 2).map_or(true, |w| w.len() != 1 || w[0] != pieces)
}

/// The word that starts at `chars[i]`, and where it ends.
fn read_word(chars: &[char], mut i: usize) -> (Vec<Piece>, usize) {
    let mut out: Vec<Piece> = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        if ends_word(c) {
            break;
        }
        match c {
            '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    out.push(Piece::Ch(chars[i], true));
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                let (stretch, end) = double_quoted(chars, i);
                out.extend(stretch);
                i = end;
            }
            // Outside quotes a backslash and the character after it are
            // those two characters to the walk, and neither means anything
            // (`delete::tokenize_detailed` keeps both: a Windows path). A
            // backslash before a newline joins the lines.
            '\\' => match chars.get(i + 1) {
                Some('\n') => i += 2,
                Some(next) => {
                    out.push(Piece::Ch('\\', true));
                    out.push(Piece::Ch(*next, true));
                    i += 2;
                }
                None => {
                    out.push(Piece::Ch('\\', true));
                    i += 1;
                }
            },
            '$' | '`' => match expansion_end(chars, i) {
                Some(end) => {
                    let raw: String = chars[i..end].iter().collect();
                    match default_of(&raw) {
                        Some(word) => out.extend(word.chars().map(|c| Piece::Ch(c, false))),
                        None => out.push(Piece::Opaque(raw)),
                    }
                    i = end;
                }
                None => {
                    out.push(Piece::Ch(c, true));
                    i += 1;
                }
            },
            _ => {
                out.push(Piece::Ch(c, false));
                i += 1;
            }
        }
    }
    (out, i.min(chars.len()))
}

/// The double-quoted stretch that opens at `chars[i]`: its characters, each
/// with its meaning taken, or the stretch as written when it holds
/// something only the shell can open. And where it ends.
fn double_quoted(chars: &[char], open: usize) -> (Vec<Piece>, usize) {
    let mut out: Vec<Piece> = Vec::new();
    let mut opaque = false;
    let mut i = open + 1;
    while i < chars.len() && chars[i] != '"' {
        match chars[i] {
            '\\' => match chars.get(i + 1) {
                Some(n) if matches!(n, '$' | '`' | '"' | '\\') => {
                    out.push(Piece::Ch(*n, true));
                    i += 2;
                }
                Some('\n') => i += 2,
                _ => {
                    out.push(Piece::Ch('\\', true));
                    i += 1;
                }
            },
            '$' | '`' => match expansion_end(chars, i) {
                Some(end) => {
                    opaque = true;
                    i = end;
                }
                None => {
                    out.push(Piece::Ch(chars[i], true));
                    i += 1;
                }
            },
            c => {
                out.push(Piece::Ch(c, true));
                i += 1;
            }
        }
    }
    let end = (i + 1).min(chars.len());
    if opaque {
        (vec![Piece::Opaque(chars[open..end].iter().collect())], end)
    } else {
        (out, end)
    }
}

/// The word a parameter expansion hands over when its variable is unset
/// (`${X:-word}`, `${X-word}`, `${X:=word}`, `${X=word}`) or set
/// (`${X:+word}`, `${X+word}`), when the word is literal: no expansion,
/// quote or backslash in it. Which of the two the line gets is the running
/// shell's to know, so the word is read as one of the spellings the line
/// may have; the line as written is the other. Unquoted, the shell opens
/// the word as it opens any other: `${X:-.clau[d]e}/settings.json` is the
/// hook config wherever `X` is unset.
fn default_of(raw: &str) -> Option<&str> {
    let inner = raw.strip_prefix("${")?.strip_suffix('}')?;
    let name = inner
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(inner.len());
    if name == 0 {
        return None;
    }
    let rest = &inner[name..];
    let word = [":-", ":=", ":+", "-", "=", "+"]
        .iter()
        .find_map(|op| rest.strip_prefix(op))?;
    (!word.contains(['$', '`', '\'', '"', '\\'])).then_some(word)
}

/// Where the expansion that starts at `chars[i]`, a `$` or a backtick,
/// ends: `$name`, `${ … }`, `$( … )` to its matching parenthesis, a
/// positional or special parameter, a backtick pair. `None` for a `$` that
/// opens none.
fn expansion_end(chars: &[char], i: usize) -> Option<usize> {
    if chars[i] == '`' {
        let close = chars[i + 1..].iter().position(|c| *c == '`');
        return Some(close.map_or(chars.len(), |p| i + p + 2));
    }
    match chars.get(i + 1)? {
        '(' => {
            let mut depth = 0usize;
            let mut quote: Option<char> = None;
            let mut j = i + 1;
            while j < chars.len() {
                let c = chars[j];
                match quote {
                    Some(q) if c == q => quote = None,
                    Some('"') if c == '\\' => j += 1,
                    Some(_) => {}
                    None => match c {
                        '\'' | '"' => quote = Some(c),
                        '\\' => j += 1,
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(j + 1);
                            }
                        }
                        _ => {}
                    },
                }
                j += 1;
            }
            Some(chars.len())
        }
        // To its matching brace: `${X:-.cl{a..a}ude}` holds a brace
        // list of its own.
        '{' => {
            let mut depth = 0usize;
            for (j, c) in chars.iter().enumerate().skip(i + 1) {
                match c {
                    '{' => depth += 1,
                    '}' if depth == 1 => return Some(j + 1),
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            Some(chars.len())
        }
        c if c.is_ascii_alphabetic() || *c == '_' => {
            let mut j = i + 1;
            while chars
                .get(j)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                j += 1;
            }
            Some(j)
        }
        c if c.is_ascii_digit() || matches!(c, '@' | '*' | '#' | '?' | '$' | '!' | '-') => {
            Some(i + 2)
        }
        _ => None,
    }
}

/// What a word opens into.
enum Opening {
    /// Itself: nothing in it to open, or nothing it matches.
    AsWritten,
    /// A brace list longer than `MOST_WORDS`, more words than can be asked
    /// about, or patterns the walk ran out of budget reading.
    Unread,
    /// These words.
    Words(Vec<Vec<Piece>>),
}

fn open_word(
    word: &[Piece],
    dir: Option<&Path>,
    loose: Loose,
    budget: &mut Budget,
    keep: &dyn Fn(&str) -> bool,
) -> Opening {
    let unquoted = |c: char| word.contains(&Piece::Ch(c, false));
    if !['*', '?', '[', '{', GROUP_OPENS].into_iter().any(unquoted) {
        return Opening::AsWritten;
    }
    let Ok(listed) = braces(word, MOST_WORDS) else {
        return Opening::Unread;
    };
    let mut words: Vec<Vec<Piece>> = Vec::new();
    for one in listed {
        let read = dir.and_then(|dir| here(&one, dir));
        let one_read = read.as_deref().unwrap_or(&one);
        let on_disk = match dir {
            Some(dir) if might_match(one_read) && readable(one_read) && has_pattern(one_read) => {
                matches(one_read, dir, loose, budget)
            }
            _ => None,
        };
        // The walk stopped before it knew what the pattern matches: the
        // word is not what it says, and nothing read what it is.
        if budget.spent {
            return Opening::Unread;
        }
        match on_disk {
            Some(names) if !names.is_empty() => {
                for name in names {
                    words.push(name.chars().map(|c| Piece::Ch(c, true)).collect());
                }
            }
            _ => words.push(one),
        }
    }
    if words.len() == 1 && words[0] == word {
        return Opening::AsWritten;
    }
    if words.len() > MOST_KEPT {
        // More of them than can be written out, or than there is time to
        // ask about, is a word nothing read: `tee .claude/settings.{json,
        // {1..9999}}` carries one name among ten thousand.
        let until = Instant::now() + LONGEST_ASKING;
        let mut kept = Vec::new();
        for (n, word) in words.into_iter().enumerate() {
            if n % 256 == 255 && Instant::now() > until {
                return Opening::Unread;
            }
            if keep(&text_of(&word)) {
                kept.push(word);
                if kept.len() > MOST_KEPT {
                    return Opening::Unread;
                }
            }
        }
        if kept.is_empty() {
            return Opening::AsWritten;
        }
        words = kept;
    }
    Opening::Words(words)
}

/// `word` with the directory it runs in for a `$PWD` it starts with (and
/// `${PWD}`, `"$PWD"`, `~+`), which is that directory to the shell:
/// `"$PWD"/.clau[d]e/settings.json` opens as `.clau[d]e/settings.json`
/// does. `None` when the word starts with no such thing.
fn here(word: &[Piece], dir: &Path) -> Option<Vec<Piece>> {
    // What follows `$PWD` inside its own double quotes is literal:
    // `"$PWD/.claude"/settin*`.
    let mut quoted: Vec<Piece> = Vec::new();
    let rest = match word {
        [Piece::Opaque(raw), rest @ ..] => {
            let inside = raw
                .strip_prefix('"')
                .and_then(|r| r.strip_suffix('"'))
                .unwrap_or(raw);
            let after = inside
                .strip_prefix("${PWD}")
                .or_else(|| inside.strip_prefix("$PWD"))
                .filter(|after| {
                    !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                })?;
            if after.contains(['$', '`', '\\'])
                || (after.contains('"') || raw == inside && !after.is_empty())
            {
                return None;
            }
            quoted.extend(after.chars().map(|c| Piece::Ch(c, true)));
            rest
        }
        [Piece::Ch('~', false), Piece::Ch('+', false), rest @ ..] => rest,
        _ => return None,
    };
    let next = quoted.first().or(rest.first());
    if !matches!(next, None | Some(Piece::Ch('/', _))) {
        return None;
    }
    let mut out: Vec<Piece> = dir
        .display()
        .to_string()
        .chars()
        .map(|c| Piece::Ch(c, true))
        .collect();
    out.extend(quoted);
    out.extend(rest.iter().cloned());
    Some(out)
}

/// Whether every part of `word` is one this reading can find on disk: no
/// `$X` or substitution in it, and no `~` that names another user's home or
/// the directory stack.
fn readable(word: &[Piece]) -> bool {
    if word.iter().any(|p| matches!(p, Piece::Opaque(_))) {
        return false;
    }
    match word {
        [Piece::Ch('~', false)] => true,
        [Piece::Ch('~', false), Piece::Ch(next, _), ..] => is_separator(*next),
        _ => true,
    }
}

fn is_separator(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

/// The characters of `word`, with no quote left on any of them.
fn text_of(word: &[Piece]) -> String {
    let mut out = String::new();
    for piece in word {
        match piece {
            Piece::Ch(c, _) => out.push(*c),
            Piece::Opaque(raw) => out.push_str(raw),
        }
    }
    out
}

/// `word` in the walk's own spelling: a character the walk would give a
/// meaning to is written quoted, unless the shell would have opened it and
/// found nothing (a pattern that matches nothing is handed over as it is).
fn spelled(word: &[Piece]) -> String {
    let mut out = String::new();
    let mut quoted = String::new();
    let flush = |quoted: &mut String, out: &mut String| {
        if !quoted.is_empty() {
            out.push('\'');
            out.push_str(quoted);
            out.push('\'');
            quoted.clear();
        }
    };
    for piece in word {
        match piece {
            Piece::Ch('\'', true) => {
                flush(&mut quoted, &mut out);
                out.push_str("\"'\"");
            }
            Piece::Ch(c, true) if !plain(*c) => quoted.push(*c),
            Piece::Ch(c, _) => {
                flush(&mut quoted, &mut out);
                out.push(*c);
            }
            Piece::Opaque(raw) => {
                flush(&mut quoted, &mut out);
                out.push_str(raw);
            }
        }
    }
    flush(&mut quoted, &mut out);
    if out.is_empty() {
        out.push_str("''");
    }
    out
}

/// A brace list longer than the caller reads.
struct TooMany;

/// `word` with its brace lists and ranges opened, in the shell's order:
/// `a{b,c}d{e,f}` is `abde abdf acde acdf`. A brace that opens neither a
/// list nor a range is a character (`{a}`, `{}`, `HEAD@{1}`).
fn braces(word: &[Piece], most: usize) -> Result<Vec<Vec<Piece>>, TooMany> {
    for open in 0..word.len() {
        if word[open] != Piece::Ch('{', false) {
            continue;
        }
        let Some((close, commas)) = closing_brace(word, open) else {
            continue;
        };
        let inner = &word[open + 1..close];
        let alternatives: Vec<Vec<Piece>> = if commas.is_empty() {
            match range(inner, most)? {
                Some(steps) => steps,
                None => continue,
            }
        } else {
            let mut parts = Vec::with_capacity(commas.len() + 1);
            let mut from = open + 1;
            for comma in commas.iter().copied().chain([close]) {
                parts.push(word[from..comma].to_vec());
                from = comma + 1;
            }
            parts
        };
        let rest = braces(&word[close + 1..], most)?;
        let mut out: Vec<Vec<Piece>> = Vec::new();
        for alternative in alternatives {
            for middle in braces(&alternative, most)? {
                for end in &rest {
                    if out.len() >= most {
                        return Err(TooMany);
                    }
                    let mut one = word[..open].to_vec();
                    one.extend(middle.iter().cloned());
                    one.extend(end.iter().cloned());
                    out.push(one);
                }
            }
        }
        return Ok(out);
    }
    Ok(vec![word.to_vec()])
}

/// The `}` that closes the `{` at `word[open]`, and the commas of its own
/// list between them.
fn closing_brace(word: &[Piece], open: usize) -> Option<(usize, Vec<usize>)> {
    let mut depth = 0usize;
    let mut commas = Vec::new();
    for (j, piece) in word.iter().enumerate().skip(open + 1) {
        match piece {
            Piece::Ch('{', false) => depth += 1,
            Piece::Ch('}', false) if depth == 0 => return Some((j, commas)),
            Piece::Ch('}', false) => depth -= 1,
            Piece::Ch(',', false) if depth == 0 => commas.push(j),
            _ => {}
        }
    }
    None
}

/// What `{x..y}` or `{x..y..step}` counts through, when `inner` is one:
/// two integers or two letters, and a step. `{01..10}` pads with zeros to
/// the wider of the two.
fn range(inner: &[Piece], most: usize) -> Result<Option<Vec<Vec<Piece>>>, TooMany> {
    let mut text = String::new();
    for piece in inner {
        match piece {
            Piece::Ch(c, false) => text.push(*c),
            _ => return Ok(None),
        }
    }
    // Two characters, whatever they are, are a range to zsh (`{....}` is a
    // dot); bash wants two letters, and leaves the rest as written.
    let chars: Vec<char> = text.chars().collect();
    let single = (chars.len() >= 4 && chars[1] == '.' && chars[2] == '.')
        .then(|| (chars[0].to_string(), chars[3].to_string(), &chars[4..]));
    let parts: Vec<&str> = text.split("..").collect();
    let (from, to, step): (String, String, i64) = match (&single, parts.as_slice()) {
        (Some((from, to, [])), _) => (from.clone(), to.clone(), 1),
        (Some((from, to, ['.', '.', step @ ..])), _) => {
            match step.iter().collect::<String>().parse::<i64>() {
                Ok(step) => (from.clone(), to.clone(), step.unsigned_abs().max(1) as i64),
                Err(_) => return Ok(None),
            }
        }
        (_, [from, to]) => (from.to_string(), to.to_string(), 1),
        (_, [from, to, step]) => match step.parse::<i64>() {
            Ok(step) => (
                from.to_string(),
                to.to_string(),
                step.unsigned_abs().max(1) as i64,
            ),
            Err(_) => return Ok(None),
        },
        _ => return Ok(None),
    };
    let (from, to) = (from.as_str(), to.as_str());
    // What a range counts through is literal, `;` and `<` included, except
    // a pattern's own characters: `{*..*}` is a `*` the shell then opens.
    let word = |s: String| {
        s.chars()
            .map(|c| Piece::Ch(c, !matches!(c, '*' | '?' | '[')))
            .collect::<Vec<Piece>>()
    };
    let letter = |s: &str| {
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => Some(c as i64),
            _ => None,
        }
    };
    let (a, b, render): (i64, i64, Box<dyn Fn(i64) -> String>) =
        match (from.parse::<i64>(), to.parse::<i64>()) {
            (Ok(a), Ok(b)) => {
                let padded = |s: &str| {
                    let digits = s.trim_start_matches(['-', '+']);
                    digits.len() > 1 && digits.starts_with('0')
                };
                let width = if padded(from) || padded(to) {
                    from.len().max(to.len())
                } else {
                    0
                };
                (a, b, Box::new(move |n| format!("{n:0width$}")))
            }
            _ => match (letter(from), letter(to)) {
                (Some(a), Some(b)) => (
                    a,
                    b,
                    Box::new(|n| char::from_u32(n as u32).unwrap_or('?').to_string()),
                ),
                _ => return Ok(None),
            },
        };
    let count = (a.abs_diff(b) / step.unsigned_abs()) as usize + 1;
    if count > most {
        return Err(TooMany);
    }
    let mut out = Vec::with_capacity(count);
    let mut n = a;
    for _ in 0..count {
        out.push(word(render(n)));
        n += if a <= b { step } else { -step };
    }
    Ok(Some(out))
}

/// One element of a pattern, within one component of a path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Glob {
    Is(char),
    Any,
    Star,
    /// `[…]`: the ranges it lists (a single character is a range of one),
    /// and whether it is negated. `everything` for a class this does not
    /// read (`[[:alpha:]]` and its kind are read; `[[=a=]]` is not): it
    /// matches whatever stands there, which is more than the shell matches
    /// and never less.
    Class {
        ranges: Vec<(char, char)>,
        negated: bool,
        everything: bool,
    },
}

/// The patterns `component` is, or `None` when nothing in it is one: more
/// than one when it holds a group, each alternative written out (`a(b|c)d`
/// is `abd` and `acd`).
fn pattern(component: &[(char, bool)]) -> Option<Vec<Vec<Glob>>> {
    let (flat, any) = flattened(component);
    any.then_some(flat)
}

/// `component` as flat patterns, and whether anything in it is a pattern
/// at all.
fn flattened(component: &[(char, bool)]) -> (Vec<Vec<Glob>>, bool) {
    let mut out: Vec<Vec<Glob>> = vec![Vec::new()];
    let mut any = false;
    let push = |out: &mut Vec<Vec<Glob>>, glob: Glob| {
        for flat in out.iter_mut() {
            if !(glob == Glob::Star && flat.last() == Some(&Glob::Star)) {
                flat.push(glob.clone());
            }
        }
    };
    let mut i = 0;
    while i < component.len() {
        let (c, lit) = component[i];
        match c {
            '*' if !lit => {
                any = true;
                push(&mut out, Glob::Star);
                i += 1;
            }
            '?' if !lit => {
                any = true;
                push(&mut out, Glob::Any);
                i += 1;
            }
            '[' if !lit => match class(component, i) {
                Some((glob, end)) => {
                    any = true;
                    push(&mut out, glob);
                    i = end;
                }
                None => {
                    push(&mut out, Glob::Is(c));
                    i += 1;
                }
            },
            GROUP_OPENS if !lit => match group(component, i) {
                Some((alternatives, end)) => {
                    any = true;
                    let mut each: Vec<Vec<Glob>> = Vec::new();
                    for alternative in alternatives {
                        each.extend(flattened(alternative).0);
                    }
                    if out.len().saturating_mul(each.len()) > MOST_ALTERNATIVES {
                        push(&mut out, Glob::Star);
                    } else {
                        let before = std::mem::take(&mut out);
                        for flat in &before {
                            for alternative in &each {
                                let mut one = flat.clone();
                                for glob in alternative {
                                    if !(*glob == Glob::Star && one.last() == Some(&Glob::Star)) {
                                        one.push(glob.clone());
                                    }
                                }
                                out.push(one);
                            }
                        }
                    }
                    i = end;
                }
                None => {
                    push(&mut out, Glob::Is(c));
                    i += 1;
                }
            },
            _ => {
                push(&mut out, Glob::Is(c));
                i += 1;
            }
        }
    }
    (out, any)
}

/// The alternatives of the group that opens at `component[open]`, and
/// where it ends; `None` when nothing closes it.
#[allow(clippy::type_complexity)]
fn group(component: &[(char, bool)], open: usize) -> Option<(Vec<&[(char, bool)]>, usize)> {
    let mut depth = 0usize;
    let mut from = open + 1;
    let mut alternatives = Vec::new();
    for (j, (c, lit)) in component.iter().enumerate().skip(open + 1) {
        if *lit {
            continue;
        }
        match *c {
            GROUP_OPENS => depth += 1,
            GROUP_CLOSES if depth == 0 => {
                alternatives.push(&component[from..j]);
                return Some((alternatives, j + 1));
            }
            GROUP_CLOSES => depth -= 1,
            GROUP_OR if depth == 0 => {
                alternatives.push(&component[from..j]);
                from = j + 1;
            }
            _ => {}
        }
    }
    None
}

/// The bracket expression that opens at `component[open]`, and where it
/// ends; `None` when no `]` closes it, and the `[` is a character.
fn class(component: &[(char, bool)], open: usize) -> Option<(Glob, usize)> {
    let mut i = open + 1;
    let negated = matches!(component.get(i), Some(('!' | '^', false)));
    if negated {
        i += 1;
    }
    let mut ranges: Vec<(char, char)> = Vec::new();
    let mut everything = false;
    let mut first = true;
    loop {
        let (c, lit) = *component.get(i)?;
        if c == ']' && !lit && !first {
            return Some((
                Glob::Class {
                    ranges,
                    negated,
                    everything,
                },
                i + 1,
            ));
        }
        first = false;
        // `[:alpha:]`, `[=a=]`, `[.a.]` inside the brackets.
        if c == '[' && !lit {
            if let Some((kind, _)) = component.get(i + 1).filter(|(k, _)| ":=.".contains(*k)) {
                let close = (i + 2..component.len().saturating_sub(1))
                    .find(|&j| component[j].0 == *kind && component[j + 1].0 == ']');
                if let Some(close) = close {
                    let name: String = component[i + 2..close].iter().map(|(c, _)| *c).collect();
                    match (*kind, named(&name)) {
                        (':', Some(listed)) => ranges.extend(listed),
                        _ => everything = true,
                    }
                    i = close + 2;
                    continue;
                }
            }
        }
        match (component.get(i + 1), component.get(i + 2)) {
            (Some(('-', false)), Some((to, to_lit))) if *to != ']' || *to_lit => {
                ranges.push((c, *to));
                i += 3;
            }
            _ => {
                ranges.push((c, c));
                i += 1;
            }
        }
    }
}

/// The characters a named class holds, for the ASCII ones; `None` for a
/// name this does not know.
fn named(name: &str) -> Option<Vec<(char, char)>> {
    Some(match name {
        "alpha" => vec![('a', 'z'), ('A', 'Z')],
        "digit" => vec![('0', '9')],
        "alnum" => vec![('a', 'z'), ('A', 'Z'), ('0', '9')],
        "upper" => vec![('A', 'Z')],
        "lower" => vec![('a', 'z')],
        "xdigit" => vec![('0', '9'), ('a', 'f'), ('A', 'F')],
        "word" => vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')],
        "space" => vec![(' ', ' '), ('\t', '\r')],
        "blank" => vec![(' ', ' '), ('\t', '\t')],
        "punct" => vec![('!', '/'), (':', '@'), ('[', '`'), ('{', '~')],
        _ => return None,
    })
}

/// Whether `name`, one component of a path, is matched by `pattern`, read
/// as rsync reads an `--exclude` and unzip a member's name (#12): `*`, `?`
/// and `[...]`, within the component, and a name that starts with a dot
/// matched like any other. Not the shell's reading: no group, no brace.
pub fn component_matches(pattern: &str, name: &str) -> bool {
    let component: Vec<(char, bool)> = pattern.chars().map(|c| (c, false)).collect();
    names(
        &flattened(&component).0,
        name,
        Loose {
            dots: true,
            case: false,
        },
    )
}

/// Whether `name`, one entry of a directory, is matched by `glob`. A name
/// that starts with a dot is matched only by a pattern that starts with
/// one, as in bash and zsh, unless the line said otherwise (`Loose`). On
/// Windows the comparison ignores case, as cmd's and PowerShell's do.
fn names(patterns: &[Vec<Glob>], name: &str, loose: Loose) -> bool {
    patterns.iter().any(|glob| names_one(glob, name, loose))
}

fn names_one(glob: &[Glob], name: &str, loose: Loose) -> bool {
    if name.starts_with('.') && !loose.dots && glob.first() != Some(&Glob::Is('.')) {
        return false;
    }
    let fold = |c: char| {
        if cfg!(windows) || loose.case {
            c.to_ascii_lowercase()
        } else {
            c
        }
    };
    let one = |g: &Glob, c: char| match g {
        Glob::Is(p) => fold(*p) == fold(c),
        Glob::Any => true,
        Glob::Star => false,
        Glob::Class {
            ranges,
            negated,
            everything,
        } => {
            *everything
                || ranges.iter().any(|(a, b)| {
                    (*a..=*b).contains(&c) || (fold(*a)..=fold(*b)).contains(&fold(c))
                }) != *negated
        }
    };
    let text: Vec<char> = name.chars().collect();
    let (mut g, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if g < glob.len() && one(&glob[g], text[t]) {
            g += 1;
            t += 1;
        } else if g < glob.len() && glob[g] == Glob::Star {
            star = Some((g, t));
            g += 1;
        } else if let Some((at, mark)) = star {
            star = Some((at, mark + 1));
            g = at + 1;
            t = mark + 1;
        } else {
            return false;
        }
    }
    glob[g..].iter().all(|x| *x == Glob::Star)
}

/// Whether `word` holds a character a pattern is made of, outside quotes:
/// the cheap question before `has_pattern`, asked of every word a brace
/// list opens into.
fn might_match(word: &[Piece]) -> bool {
    word.iter()
        .any(|p| matches!(p, Piece::Ch('*' | '?' | '[' | GROUP_OPENS, false)))
}

/// Whether a component of `word` is a pattern.
fn has_pattern(word: &[Piece]) -> bool {
    components(word)
        .iter()
        .any(|(component, _)| pattern(component).is_some())
}

/// `word` as the components of a path, each with the separator written
/// after it: `/` everywhere, and on Windows a backslash too.
#[allow(clippy::type_complexity)]
fn components(word: &[Piece]) -> Vec<(Vec<(char, bool)>, Option<char>)> {
    let mut out = Vec::new();
    let mut current: Vec<(char, bool)> = Vec::new();
    for piece in word {
        match piece {
            Piece::Ch(c, _) if is_separator(*c) => {
                out.push((std::mem::take(&mut current), Some(*c)));
            }
            Piece::Ch(c, lit) => current.push((*c, *lit)),
            // Not a name this can match against a directory's entries; the
            // caller has already said so (`readable`).
            Piece::Opaque(raw) => current.extend(raw.chars().map(|c| (c, true))),
        }
    }
    out.push((current, None));
    out
}

/// The names `word` matches from `dir`, each as the word the shell hands
/// over: the part before the first pattern as it was written, and then the
/// names found. Empty when nothing matches; `None` when the budget ran out
/// before that was known.
///
/// A component that is `**` and not the last is any number of directories,
/// none included: zsh's `**/`, and bash's once `globstar` is on, which is
/// more than bash's `*` without it (`.claude/**/settings.json` is
/// `.claude/settings.json` there too).
fn matches(word: &[Piece], dir: &Path, loose: Loose, budget: &mut Budget) -> Option<Vec<String>> {
    let parts = components(word);
    let first = parts.iter().position(|(c, _)| pattern(c).is_some())?;
    let mut written = String::new();
    for (component, separator) in &parts[..first] {
        written.extend(component.iter().map(|(c, _)| *c));
        written.extend(*separator);
    }
    let base = if written.is_empty() {
        dir.to_path_buf()
    } else {
        crate::delete::resolve_path_in(&written, dir)
    };
    let mut found: Vec<(PathBuf, String)> = vec![(base, written)];
    for (n, (component, separator)) in parts.iter().enumerate().skip(first) {
        let last = n + 1 == parts.len();
        let mut next: Vec<(PathBuf, String)> = Vec::new();
        if component.is_empty() {
            // `dir*/`: a directory, and the separator is already written.
            if last {
                let mut dirs = Vec::with_capacity(found.len());
                for (path, written) in found {
                    if !budget.entry() {
                        return None;
                    }
                    if path.is_dir() {
                        dirs.push((path, written));
                    }
                }
                found = dirs;
            }
            continue;
        }
        let spell = |written: &str, name: &str| {
            let mut out = format!("{written}{name}");
            out.extend(*separator);
            out
        };
        match pattern(component) {
            Some(glob) => {
                let any_depth = !last
                    && component.len() > 1
                    && component.iter().all(|(c, lit)| *c == '*' && !lit);
                if any_depth {
                    // No directory, or any number of them below: zsh's
                    // `**/`, and bash's with `globstar`. A link is not
                    // followed, and a dot-name is entered only where the
                    // line said so (`Loose`).
                    let mut below: Vec<(PathBuf, String)> = found.clone();
                    while let Some((path, written)) = below.pop() {
                        next.push((path.clone(), written.clone()));
                        let Ok(entries) = std::fs::read_dir(&path) else {
                            continue;
                        };
                        let mut here: Vec<String> = Vec::new();
                        for entry in entries.flatten() {
                            if !budget.entry() {
                                return None;
                            }
                            let name = entry.file_name().to_string_lossy().into_owned();
                            if (loose.dots || !name.starts_with('.'))
                                && entry.file_type().is_ok_and(|t| t.is_dir())
                            {
                                here.push(name);
                            }
                        }
                        here.sort();
                        for name in here.into_iter().rev() {
                            let written = format!("{written}{name}{}", separator.unwrap_or('/'));
                            below.push((path.join(&name), written));
                        }
                    }
                    found = next;
                    continue;
                }
                for (path, written) in &found {
                    let Ok(entries) = std::fs::read_dir(path) else {
                        continue;
                    };
                    let mut here: Vec<String> = Vec::new();
                    for entry in entries.flatten() {
                        if !budget.entry() {
                            return None;
                        }
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if names(&glob, &name, loose) {
                            here.push(name);
                        }
                    }
                    here.sort();
                    for name in here {
                        next.push((path.join(&name), spell(written, &name)));
                    }
                }
            }
            None => {
                let name: String = component.iter().map(|(c, _)| *c).collect();
                for (path, written) in &found {
                    if !budget.entry() {
                        return None;
                    }
                    let path = path.join(&name);
                    if std::fs::symlink_metadata(&path).is_ok() {
                        next.push((path, spell(written, &name)));
                    }
                }
            }
        }
        found = next;
        if found.is_empty() {
            break;
        }
    }
    Some(found.into_iter().map(|(_, written)| written).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(_: &str, _: Option<&str>) -> bool {
        true
    }

    /// `opened_until` with no end set for the line, as the tests open a
    /// segment on its own.
    fn opened(
        segment: &str,
        dir: Option<&Path>,
        loose: Loose,
        keep: &dyn Fn(&str, Option<&str>) -> bool,
    ) -> Opened {
        opened_until(segment, dir, loose, keep, None)
    }

    fn open(segment: &str, dir: &Path) -> Option<String> {
        opened(segment, Some(dir), Loose::default(), &all).text
    }

    fn project() -> crate::testutil::TempTree {
        let tmp = crate::testutil::TempTree::new("words");
        tmp.file(".claude/settings.json", "{}\n");
        tmp.file(".claude/settings.local.json", "{}\n");
        tmp.file(".termaxa/policy.yaml", "default: ask\nrules: []\n");
        tmp.file(".env", "K=1\n");
        tmp.file("sub/.env", "K=1\n");
        tmp.file("notes.md", "n\n");
        tmp.file("src/a.ts", "a\n");
        tmp.file("src/b.ts", "b\n");
        tmp.file("src/lib/c.ts", "c\n");
        tmp.file("app/[id]/page.tsx", "p\n");
        tmp.file("my dir/x y.txt", "s\n");
        tmp
    }

    /// The spellings this module exists for: each names a file a rule
    /// guards, through a brace or a pattern, and is written out as that
    /// file.
    #[test]
    fn a_guarded_name_behind_a_brace_or_a_pattern_is_written_out() {
        let tmp = project();
        for (typed, read) in [
            (
                "echo x > .clau[d]e/settings.json",
                "echo x > .claude/settings.json",
            ),
            (
                "echo x > .cl?ude/setting[r-t].json",
                "echo x > .claude/settings.json",
            ),
            (
                "echo x > .claud{e..e}/settings.json",
                "echo x > .claude/settings.json",
            ),
            (
                "cat notes.md | tee .claud{e,x}/settings.json",
                "cat notes.md | tee .claude/settings.json .claudx/settings.json",
            ),
            (
                "touch .clau[!x]e/settings.json",
                "touch .claude/settings.json",
            ),
            (
                "touch .clau[^x]e/settings.jso[[:alpha:]]",
                "touch .claude/settings.json",
            ),
            ("rm -rf .claud{e,x}", "rm -rf .claude .claudx"),
            ("echo x > .t*/policy.yaml", "echo x > .termaxa/policy.yaml"),
            ("echo x > sub/.en[v]", "echo x > sub/.env"),
            ("cp notes.md */.env", "cp notes.md sub/.env"),
            ("cd .clau[d]e", "cd .claude"),
            (
                "sed -i s/a/b/ .cl*/settings.json",
                "sed -i s/a/b/ .claude/settings.json",
            ),
            // A variable's default, where it applies.
            (
                "echo x > ${NOPE:-.clau[d]e}/settings.json",
                "echo x > .claude/settings.json",
            ),
            (
                "echo x > ${NOPE:-.claude}/setting[s].json",
                "echo x > .claude/settings.json",
            ),
            (
                "echo x > ${NOPE:-.cl{a..a}ude}/settings.json",
                "echo x > .claude/settings.json",
            ),
        ] {
            assert_eq!(open(typed, tmp.path()).as_deref(), Some(read), "{typed}");
        }
    }

    /// A redirection whose target opens into several words is one
    /// redirection each: zsh writes them all.
    #[test]
    fn a_redirection_into_several_words_is_one_redirection_each() {
        let tmp = project();
        for (typed, read) in [
            (
                "echo x > .claude/s*",
                "echo x > .claude/settings.json > .claude/settings.local.json",
            ),
            (
                "echo x >> .claud{e,x}/settings.json",
                "echo x >> .claude/settings.json >> .claudx/settings.json",
            ),
            (
                "echo x 2>.claude/setting?.json",
                "echo x 2>.claude/settings.json",
            ),
            ("echo x &> src/{a,b}.ts", "echo x &> src/a.ts &> src/b.ts"),
        ] {
            assert_eq!(open(typed, tmp.path()).as_deref(), Some(read), "{typed}");
        }
    }

    /// What the shell does not open is left as it is: a quoted or escaped
    /// character, a comment, a heredoc's body, a word with nothing behind
    /// its pattern, a brace that opens no list.
    #[test]
    fn what_the_shell_leaves_alone_is_left_alone() {
        let tmp = project();
        for typed in [
            "echo x > '.clau[d]e/settings.json'",
            "echo x > \".clau[d]e/settings.json\"",
            "echo x > .clau\\[d\\]e/settings.json",
            "echo x > .cl\\*/settings.json",
            "echo '{a,b}' \"{a,b}\" \\{a,b\\}",
            "git status # .clau[d]e/settings.json and {a,b}",
            "cat > app/[id]/page.tsx",
            "cd app/[id]",
            "ls nothing-here-*",
            "git show HEAD@{1}",
            "find . -name x -exec rm {} +",
            "echo ${a[*]} $(ls *.md) `ls *.md`",
            "echo \"$HOME/*\"",
            "echo x > $HOME/.clau[d]e/settings.json",
            "echo x > ~nobody/.clau[d]e/settings.json",
            "[ -f notes.md ]",
            "echo {a} {} {a..}",
        ] {
            assert_eq!(open(typed, tmp.path()), None, "{typed}");
        }
        // The first line's words, and nothing of the lines after it.
        assert_eq!(
            open(
                "cat > src/[ab].ts <<'EOF'\nconst xs = [*.md];\nEOF",
                tmp.path()
            )
            .as_deref(),
            Some("cat > src/a.ts > src/b.ts <<'EOF'\nconst xs = [*.md];\nEOF")
        );
    }

    /// A name that needs quoting is written quoted, so the walk reads it as
    /// the one word it is.
    #[test]
    fn a_name_the_walk_would_split_is_written_quoted() {
        let tmp = project();
        assert_eq!(
            open("rm my*/*.txt", tmp.path()).as_deref(),
            Some("rm my' 'dir/x' 'y.txt")
        );
        assert_eq!(
            open("rm app/*/page.tsx", tmp.path()).as_deref(),
            Some("rm app/'['id']'/page.tsx")
        );
        // A brace list around something only the shell can open keeps it.
        assert_eq!(
            open("echo x > \"$PWD\"/.claud{e..e}/settings.json", tmp.path()).as_deref(),
            Some("echo x > \"$PWD\"/.claude/settings.json")
        );
        // `**` reaches any depth, through a dot-name only where the line
        // said so.
        let dots = Loose {
            dots: true,
            case: false,
        };
        assert_eq!(
            opened("echo x > **/c.ts", Some(tmp.path()), Loose::default(), &all)
                .text
                .as_deref(),
            Some("echo x > src/lib/c.ts")
        );
        assert_eq!(
            opened("echo x > **/policy.yaml", Some(tmp.path()), dots, &all)
                .text
                .as_deref(),
            Some("echo x > .termaxa/policy.yaml")
        );
        assert_eq!(
            opened(
                "echo x > .claud{e..e}/setting[s].json",
                None,
                Loose::default(),
                &all
            )
            .text
            .as_deref(),
            Some("echo x > .claude/setting[s].json"),
            "with no directory to read, a brace is still opened"
        );
    }

    #[test]
    fn braces_open_in_the_shells_order() {
        let tmp = project();
        for (typed, read) in [
            ("echo a{b,c}d{e,f}", "echo abde abdf acde acdf"),
            ("echo {a,b{c,d}}", "echo a bc bd"),
            ("echo x{,y}", "echo x xy"),
            ("echo {1..4}", "echo 1 2 3 4"),
            ("echo {4..1}", "echo 4 3 2 1"),
            ("echo {08..10}", "echo 08 09 10"),
            ("echo {1..9..4}", "echo 1 5 9"),
            ("echo {a..e..2}", "echo a c e"),
            ("echo {a}{b,c}", "echo {a}b {a}c"),
            ("echo {a,'b c'}", "echo a b' 'c"),
            // Any two characters are a range to zsh.
            ("echo x{-..0}y", "echo x-y x.y x/y x0y"),
            ("echo x{9..=}", "echo x9 x: x';' x'<' x="),
        ] {
            assert_eq!(open(typed, tmp.path()).as_deref(), Some(read), "{typed}");
        }
    }

    /// A word that opens into more than is written out keeps the words a
    /// rule could be about, and a list too long to read is said to be.
    #[test]
    fn a_long_list_keeps_what_a_rule_could_be_about() {
        let tmp = project();
        let guarded = |word: &str, _: Option<&str>| word.contains("settings");
        let read = opened(
            "tee .claude/{settings.json,x{1..500}}",
            Some(tmp.path()),
            Loose::default(),
            &guarded,
        );
        assert_eq!(read.text.as_deref(), Some("tee .claude/settings.json"));
        let read = opened(
            "tee x{1..500}",
            Some(tmp.path()),
            Loose::default(),
            &guarded,
        );
        assert_eq!(read, Opened::default(), "none of them is one");
        let read = opened(
            "tee .claude/settings.{json,{1..200000}}",
            Some(tmp.path()),
            Loose::default(),
            &guarded,
        );
        assert!(read.unread && read.text.is_none());
        // Many words, more than 64 of them a rule could be about.
        let read = opened(
            "tee .claude/settings.{json,{1..500}}",
            Some(tmp.path()),
            Loose::default(),
            &guarded,
        );
        assert!(read.unread, "one name among many that look like it");
        // And a hundred thousand plain ones are read.
        let read = opened(
            "for i in {1..100000}",
            Some(tmp.path()),
            Loose::default(),
            &guarded,
        );
        assert_eq!(read, Opened::default());
        let read = opened(
            "echo {1..99999}{1..99999}",
            Some(tmp.path()),
            Loose::default(),
            &all,
        );
        assert!(read.unread);
    }

    /// `keep` is told the operator before a redirection's target and
    /// nothing before any other word: a rule written with the operator is
    /// about the target where the line writes it.
    #[test]
    fn keep_is_told_the_operator_before_a_target() {
        let tmp = project();
        let asked = std::cell::RefCell::new(Vec::new());
        let note = |_: &str, operator: Option<&str>| {
            asked.borrow_mut().push(operator.map(str::to_string));
            false
        };
        for (line, operator) in [
            ("tee x{1..70}", None),
            ("echo y > x{1..70}", Some(">")),
            ("echo y >> x{1..70}", Some(">>")),
            ("echo y &> x{1..70}", Some("&>")),
        ] {
            asked.borrow_mut().clear();
            let read = opened(line, Some(tmp.path()), Loose::default(), &note);
            assert_eq!(read, Opened::default(), "nothing kept: {line}");
            let asked = asked.borrow();
            assert_eq!(asked.len(), 70, "{line}");
            assert!(
                asked.iter().all(|op| op.as_deref() == operator),
                "{line}: {asked:?}"
            );
        }
    }

    /// Each word reads the disk on a budget of its own (`MOST_ENTRIES`,
    /// 1,000 in tests), the names looked up after a pattern count against
    /// it, and a word whose walk runs out is unread rather than left as
    /// written: a pattern left as written is a name no path rule sees.
    #[test]
    fn a_word_reads_the_disk_on_a_budget_of_its_own() {
        let tmp = project();
        for i in 0..600 {
            tmp.file(&format!("a/f{i:04}"), "v\n");
            tmp.file(&format!("b/f{i:04}"), "v\n");
            tmp.file(&format!("d/s{i:04}/x"), "v\n");
        }
        for i in 0..1001 {
            tmp.file(&format!("big/f{i:04}"), "v\n");
        }
        // No rule is about the names in `a/` and `b/`, as no rule is about
        // `node_modules/*`: past 64 of them they are left out.
        let none = |_: &str, _: Option<&str>| false;
        let read = |line: &str| opened(line, Some(tmp.path()), Loose::default(), &none);
        // 600 entries each: neither spends the other's walk.
        let both = read("cat a/* b/* > .clau[d]e/settings.json");
        assert!(!both.unread);
        let text = both.text.expect("opened");
        assert_eq!(text, "cat a/* b/* > .claude/settings.json");
        // 1,001 entries in one word, or 600 entries and 600 names looked up
        // after them: unread.
        for line in ["cat big/* > x", "cat x big/*/none", "ls d/*/x"] {
            assert_eq!(
                read(line),
                Opened {
                    text: None,
                    unread: true
                },
                "{line}"
            );
        }
        // Past the end of the line nothing is read, and a word that needs
        // no disk is opened as before.
        let gone = Instant::now().checked_sub(Duration::from_secs(1));
        let late = opened_until("cat a/*", Some(tmp.path()), Loose::default(), &all, gone);
        assert!(late.unread);
        let braces = opened_until(
            "touch q{1,2}",
            Some(tmp.path()),
            Loose::default(),
            &all,
            gone,
        );
        assert!(!braces.unread);
        assert_eq!(braces.text.as_deref(), Some("touch q1 q2"));
    }

    #[test]
    fn a_cd_goes_where_its_one_word_opens() {
        let tmp = project();
        let at = |name: &str| Goes::To(tmp.path().join(name));
        assert_eq!(directory(".clau[d]e", tmp.path()), at(".claude"));
        assert_eq!(directory(".claud{e..e}", tmp.path()), at(".claude"));
        assert_eq!(directory(".cl*", tmp.path()), at(".claude"));
        assert_eq!(directory("s?c/l*", tmp.path()), at("src/lib"));
        // Nothing matches: the word itself, which is a directory here.
        assert_eq!(directory("app/[id]", tmp.path()), Goes::AsWritten);
        assert_eq!(directory("nowhere*", tmp.path()), Goes::AsWritten);
        // Two words, two matches, a file.
        assert_eq!(directory(".claud{e,x}", tmp.path()), Goes::NotKnown);
        assert_eq!(directory("s*", tmp.path()), Goes::NotKnown);
        assert_eq!(directory("notes.m[d]", tmp.path()), Goes::NotKnown);
        for word in [".clau[d]e", ".cl*", "a?", ".claud{e..e}", "{a,b}"] {
            assert!(is_opened(word), "{word}");
        }
        for word in [".claude", "app/[id", "HEAD@{1}", "{a}", "a]b"] {
            assert!(!is_opened(word), "{word}");
        }
    }

    /// bash, asked: each word here is opened by `opened` into the words
    /// bash prints for it, in the same directory.
    #[cfg(unix)]
    #[test]
    fn bash_opens_a_word_as_this_does() {
        let Some(bash) = crate::shell::bash_for_tests() else {
            return;
        };
        let tmp = project();
        tmp.file("src/.hidden.ts", "h\n");
        tmp.file("a-b", "x\n");
        tmp.file("a]b", "x\n");
        tmp.file("x1", "x\n");
        tmp.file("x2", "x\n");
        tmp.file("x10", "x\n");
        // The directory as `getcwd` names it, and bash's `$PWD` with it: on
        // macOS the temporary directory is behind a link (`/var` is
        // `/private/var`), and a bash whose inherited `PWD` names another
        // directory takes the name `getcwd` gives.
        let here = std::fs::canonicalize(tmp.path()).expect("the tree exists");
        // What bash has opened this way only since 4.0 (a padded range, a
        // step) or 5.2 (`.*` without `.` and `..`): macOS ships 3.2.
        let version = std::process::Command::new(bash)
            .args([
                "--norc",
                "--noprofile",
                "-c",
                "echo ${BASH_VERSINFO[0]}${BASH_VERSINFO[1]}",
            ])
            .output()
            .ok()
            .and_then(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(0);
        let newer: &[&str] = if version >= 52 {
            &[".*", "src/.*", "{03..1}", "{1..9..4}", "{a..e..2}"]
        } else {
            &[]
        };
        let every = [
            ".clau[d]e/settings.json",
            ".cl*/settings.json",
            ".cl?ude/s*",
            ".c*/*",
            "*",
            "s*/*",
            "src/*.ts",
            "src/[!a]*",
            "src/[^a].ts",
            "src/[a-b].ts",
            "src/[[:alpha:]].ts",
            "*/*/c.ts",
            "*/.env",
            "{.env,sub/.env}",
            ".claud{e,x}/settings.json",
            ".claud{e..e}/setting[s].json",
            "x{1,2,3}",
            "x{1..3}",
            "x{10..8}",
            "x[0-9]",
            "x?",
            "x*",
            "a[-x]b",
            "a[]]b",
            "a[]-]b",
            "app/[id]/page.tsx",
            "app/*/page.tsx",
            "my*/x*",
            "'*'",
            "\"*\"",
            "s'r'c/*.ts",
            "src/\"a\"*",
            "{a,b}{1,2}",
            "{a,b,{c,d}e}",
            "{a..c}{1..2}",
            "{-2..2}",
            "{a,b",
            "a}b",
            "{a}",
            "nothing*",
            "./src/*.ts",
            "src//*.ts",
            "src/../src/a*",
            "src/*/",
            "*/",
            "${NOPE:-src/*.ts}",
            "${NOPE-s?c}/[ab].ts",
            "\"$PWD\"/src/*.ts",
            "\"$PWD/src\"/*.ts",
        ];
        for word in every.iter().chain(newer) {
            let line = format!("printf '%s\\n' {word}");
            let ran = std::process::Command::new(bash)
                .args(["--norc", "--noprofile", "-c", &line])
                .current_dir(&here)
                .env("PWD", &here)
                .env("LC_ALL", "C")
                .output()
                .expect("bash runs");
            let theirs: Vec<String> = String::from_utf8_lossy(&ran.stdout)
                .lines()
                .map(str::to_string)
                .collect();
            let read = open(&line, &here).unwrap_or(line.clone());
            // The words after `printf '%s\n'`, as the walk's own tokenizer
            // reads the spelling.
            let ours: Vec<String> = crate::delete::tokenize_public(&read)
                .into_iter()
                .skip(2)
                .collect();
            assert_eq!(ours, theirs, "{word}: read as `{read}`");
        }
    }
}
