//! What a `sed` invocation can do besides print.
//!
//! The starter allows `sed -n *` as a read-only lookup, and three things
//! hide behind that prefix (reported by Tim Schipper, Sep 27, 2026, and
//! extended the same day): `-i` edits the input files in place (`sed -n -i`,
//! and GNU sed's own manual warns that `sed -ni` can empty a file); the `w`
//! command and the `w` flag of `s` write a named file; and the `e` command and
//! the `e` flag of `s` run a shell command. This module reads the arguments and
//! the script well enough to say which of those an invocation does, and says
//! "not understood" rather than guessing when it cannot tell.

/// The arguments, sorted into what sed will do with them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Invocation {
    /// `-i`, `-i.bak`, `-ni`, `--in-place[=SUFFIX]`: every input file is
    /// rewritten.
    pub in_place: bool,
    /// Scripts given inline (`-e`, `--expression=`, or the first operand).
    pub scripts: Vec<String>,
    /// `-f FILE` / `--file=FILE`: a script the gate does not read.
    pub script_file: bool,
    /// `--sandbox`: sed itself refuses `w`, `e` and `r`.
    pub sandbox: bool,
    /// Input files.
    pub files: Vec<String>,
}

/// What the scripts do beyond printing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Effects {
    /// Files written by `w FILE`, `W FILE`, or `s///w FILE`.
    pub writes: Vec<String>,
    /// An `e` command or an `s///e` flag: a shell command runs.
    pub executes: bool,
    /// Something the reader did not recognise; treat as "could do anything".
    pub not_understood: bool,
}

pub fn parse_args(args: &[String]) -> Invocation {
    let mut inv = Invocation::default();
    let explicit = args.iter().any(|a| {
        a == "-e"
            || a == "-f"
            || a.starts_with("--expression")
            || a.starts_with("--file")
            || (a.starts_with('-') && !a.starts_with("--") && short_cluster_names_script(a))
    });
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;
    let mut options_done = false;
    while i < args.len() {
        let a = &args[i];
        if options_done || !a.starts_with('-') || a == "-" {
            positionals.push(a.clone());
        } else if a == "--" {
            options_done = true;
        } else if let Some(long) = a.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            match name {
                "in-place" => inv.in_place = true,
                "sandbox" => inv.sandbox = true,
                "expression" => match value {
                    Some(v) => inv.scripts.push(v),
                    None => {
                        i += 1;
                        if let Some(v) = args.get(i) {
                            inv.scripts.push(v.clone());
                        }
                    }
                },
                "file" => {
                    inv.script_file = true;
                    if value.is_none() {
                        i += 1;
                    }
                }
                "line-length" if value.is_none() => i += 1,
                _ => {}
            }
        } else {
            // A short cluster: `-n`, `-ni`, `-i.bak`, `-ne 's/x/y/'`, `-E`.
            // `e`, `f`, `l` take the rest of the cluster or the next word;
            // `i` takes the rest of the cluster as a backup suffix. So
            // `-ie` is in-place with suffix "e", not -i -e.
            let chars: Vec<char> = a[1..].chars().collect();
            let mut k = 0;
            while k < chars.len() {
                match chars[k] {
                    'i' => {
                        inv.in_place = true;
                        break;
                    }
                    'e' | 'f' | 'l' => {
                        let rest: String = chars[k + 1..].iter().collect();
                        let value = if rest.is_empty() {
                            i += 1;
                            args.get(i).cloned()
                        } else {
                            Some(rest)
                        };
                        match chars[k] {
                            'e' => {
                                if let Some(v) = value {
                                    inv.scripts.push(v)
                                }
                            }
                            'f' => inv.script_file = true,
                            _ => {}
                        }
                        break;
                    }
                    _ => {}
                }
                k += 1;
            }
        }
        i += 1;
    }
    let mut pos = positionals.into_iter();
    if !explicit {
        if let Some(script) = pos.next() {
            inv.scripts.push(script);
        }
    }
    inv.files = pos.collect();
    inv
}

fn short_cluster_names_script(a: &str) -> bool {
    for c in a[1..].chars() {
        match c {
            'e' | 'f' => return true,
            'i' | 'l' => return false,
            _ => {}
        }
    }
    false
}

/// Read a script for `w`, `W`, `e`, and the `w`/`e` flags of `s`.
pub fn effects(script: &str) -> Effects {
    let c: Vec<char> = script.chars().collect();
    let mut fx = Effects::default();
    let mut i = 0;
    let n = c.len();
    let to_eol = |i: &mut usize| {
        let start = *i;
        while *i < n && c[*i] != '\n' {
            *i += 1;
        }
        c[start..*i].iter().collect::<String>().trim().to_string()
    };
    let skip_ws = |i: &mut usize| {
        while *i < n && (c[*i] == ' ' || c[*i] == '\t') {
            *i += 1;
        }
    };
    // A delimited part (`/re/` or `s` pattern/replacement): returns false if
    // the closing delimiter is missing.
    let delimited = |i: &mut usize, d: char| -> bool {
        while *i < n {
            let ch = c[*i];
            if ch == '\\' {
                *i += 2;
                continue;
            }
            if ch == '[' && d != '[' {
                // Bracket expression: `]` right after `[` or `[^` is literal.
                *i += 1;
                if *i < n && c[*i] == '^' {
                    *i += 1;
                }
                if *i < n && c[*i] == ']' {
                    *i += 1;
                }
                while *i < n && c[*i] != ']' {
                    *i += 1;
                }
                *i += 1;
                continue;
            }
            *i += 1;
            if ch == d {
                return true;
            }
        }
        false
    };
    'commands: loop {
        while i < n && matches!(c[i], ' ' | '\t' | '\n' | ';') {
            i += 1;
        }
        if i >= n {
            break;
        }
        // Up to two addresses, then an optional `!`.
        for pass in 0..2 {
            if pass == 1 {
                if i < n && c[i] == ',' {
                    i += 1;
                } else {
                    break;
                }
            }
            if i < n && (c[i] == '+' || c[i] == '~') {
                i += 1;
            }
            if i < n && (c[i].is_ascii_digit() || c[i] == '$') {
                while i < n && (c[i].is_ascii_digit() || c[i] == '$' || c[i] == '~') {
                    i += 1;
                }
            } else if i < n && (c[i] == '/' || c[i] == '\\') {
                let d = if c[i] == '\\' {
                    i += 1;
                    if i >= n {
                        fx.not_understood = true;
                        break 'commands;
                    }
                    c[i]
                } else {
                    '/'
                };
                i += 1;
                if !delimited(&mut i, d) {
                    fx.not_understood = true;
                    break 'commands;
                }
                while i < n && (c[i] == 'I' || c[i] == 'M') {
                    i += 1;
                }
            }
        }
        skip_ws(&mut i);
        if i < n && c[i] == '!' {
            i += 1;
            skip_ws(&mut i);
        }
        if i >= n {
            break;
        }
        let cmd = c[i];
        i += 1;
        match cmd {
            '{' | '}' | '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'x' | 'n' | 'N' | 'p' | 'P'
            | 'z' | 'F' => {}
            'q' | 'Q' | 'l' | 'L' => {
                skip_ws(&mut i);
                while i < n && c[i].is_ascii_digit() {
                    i += 1;
                }
            }
            '#' | 'a' | 'i' | 'c' | 'r' | 'R' | 'v' => {
                to_eol(&mut i);
            }
            ':' | 'b' | 't' | 'T' => {
                while i < n && !matches!(c[i], ';' | '\n' | '}') {
                    i += 1;
                }
            }
            'w' | 'W' => {
                skip_ws(&mut i);
                let f = to_eol(&mut i);
                if f.is_empty() {
                    fx.not_understood = true;
                } else {
                    fx.writes.push(f);
                }
            }
            'e' => {
                fx.executes = true;
                to_eol(&mut i);
            }
            's' | 'y' => {
                if i >= n {
                    fx.not_understood = true;
                    break;
                }
                let d = c[i];
                i += 1;
                if !delimited(&mut i, d) || !delimited(&mut i, d) {
                    fx.not_understood = true;
                    break;
                }
                if cmd == 's' {
                    while i < n && !matches!(c[i], ';' | '\n' | '}') {
                        match c[i] {
                            'w' => {
                                i += 1;
                                skip_ws(&mut i);
                                let f = to_eol(&mut i);
                                if f.is_empty() {
                                    fx.not_understood = true;
                                } else {
                                    fx.writes.push(f);
                                }
                                break;
                            }
                            'e' => fx.executes = true,
                            'g' | 'p' | 'i' | 'I' | 'm' | 'M' | ' ' | '\t' => {}
                            d if d.is_ascii_digit() => {}
                            _ => {
                                fx.not_understood = true;
                                break 'commands;
                            }
                        }
                        i += 1;
                    }
                }
            }
            _ => {
                fx.not_understood = true;
                break;
            }
        }
    }
    fx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn in_place_is_found_in_every_spelling_and_only_there() {
        for a in [
            v(&["-n", "-i", "s/a/b/", "f"]),
            v(&["-ni", "s/a/b/", "f"]),
            v(&["-i.bak", "s/a/b/", "f"]),
            v(&["--in-place", "s/a/b/", "f"]),
            v(&["--in-place=.orig", "-e", "s/a/b/", "f"]),
            v(&["-ie", "s/a/b/", "f"]),
        ] {
            let inv = parse_args(&a);
            assert!(inv.in_place, "{a:?}");
            assert_eq!(inv.files.last().map(String::as_str), Some("f"), "{a:?}");
        }
        // `-ne SCRIPT`: the `e` takes the script, so an `i` inside it is not
        // an option.
        let inv = parse_args(&v(&["-ne", "s/i/x/", "f"]));
        assert!(!inv.in_place);
        assert_eq!(inv.scripts, v(&["s/i/x/"]));
        assert_eq!(inv.files, v(&["f"]));
        let inv = parse_args(&v(&["-n", "1,5p", "README.md"]));
        assert!(!inv.in_place && !inv.script_file);
        assert_eq!(inv.scripts, v(&["1,5p"]));
        assert!(parse_args(&v(&["-n", "-f", "x.sed", "f"])).script_file);
        assert!(parse_args(&v(&["--sandbox", "-n", "w out", "f"])).sandbox);
    }

    #[test]
    fn the_script_says_when_it_writes_or_runs_something() {
        assert_eq!(
            effects("w /tmp/important.txt").writes,
            v(&["/tmp/important.txt"])
        );
        assert_eq!(effects("s/x/y/w out.txt").writes, v(&["out.txt"]));
        assert_eq!(effects("1,3W log").writes, v(&["log"]));
        assert!(effects("1e rm -r ./scratch").executes);
        assert!(effects("s/.*/ls/e").executes);
        // Print-only scripts, including ones whose regexes contain the
        // letters of the dangerous commands.
        for ok in [
            "1,5p",
            "/error/p",
            "$p",
            "s/foo/bar/gp",
            "/[/]w/p",
            "10q",
            "/^w /!d;p",
            "s|/w|x|p",
            "y/abc/xyz/;p",
        ] {
            let fx = effects(ok);
            assert!(
                fx.writes.is_empty() && !fx.executes && !fx.not_understood,
                "{ok}: {fx:?}"
            );
        }
        assert!(effects("1k").not_understood);
        assert!(effects("s/unterminated").not_understood);
    }
}
