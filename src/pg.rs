use crate::preview::Preview;
use std::process::Command;

/// Postgres impact analysis.
///
/// Two tiers, degrading gracefully:
///   1. STATIC  — parse the SQL out of a `psql ... -c "..."` command and
///      identify destructive statements (no database needed).
///   2. LIVE    — reuse the command's own connection arguments to run
///      read-only introspection: row estimates + FK dependents.
///
/// The preview NEVER executes the analyzed statement and NEVER runs anything
/// but SELECTs against system catalogs. Row counts are planner estimates
/// (pg_class.reltuples), never COUNT(*) — a preview must not scan tables.
#[derive(Debug, PartialEq)]
pub enum Destructive {
    DropTable {
        tables: Vec<String>,
        cascade: bool,
        if_exists: bool,
    },
    Truncate {
        tables: Vec<String>,
        cascade: bool,
    },
    DeleteFrom {
        table: String,
        has_where: bool,
    },
}

/// `live` gates the catalog query only. Static analysis of the SQL always
/// runs, so a denied command still gets "DROP users" in its reason string —
/// it just doesn't cause a connection to the database it was blocked from.
pub fn preview_for(command: &str, cwd: &std::path::Path, live: bool) -> Option<Preview> {
    let tokens = shell_tokens(command);
    if tokens.first().map(|t| !t.ends_with("psql") && t != "psql") != Some(false) {
        return None; // not a psql invocation
    }
    let sql = extract_sql(&tokens)?;
    let stmts = parse_destructive(&sql);
    if stmts.is_empty() {
        return None; // nothing destructive found — no preview needed
    }

    let mut lines = Vec::new();
    let mut summary_parts = Vec::new();
    let mut live_reached = false;

    for stmt in stmts.iter().take(3) {
        match stmt {
            Destructive::DropTable {
                tables, cascade, ..
            } => {
                for t in tables {
                    lines.push(format!(
                        "  DROP TABLE {}{}",
                        t,
                        if *cascade { " CASCADE" } else { "" }
                    ));
                    let info = if live { introspect(command, t) } else { None };
                    if let Some(info) = &info {
                        live_reached = true;
                        lines.push(format!("    rows (estimate) : {}", info.rows_display()));
                        if info.dependents.is_empty() {
                            lines.push("    referenced by   : nothing — no FK dependents".into());
                        } else {
                            lines.push(format!(
                                "    referenced by   : {} ({} table{})",
                                info.dependents.join(", "),
                                info.dependents.len(),
                                if info.dependents.len() == 1 { "" } else { "s" }
                            ));
                            if *cascade {
                                lines.push("    CASCADE effect  : drops the FK constraints in those tables".into());
                            } else {
                                lines.push(
                                    "    without CASCADE : this DROP will FAIL (dependents exist)"
                                        .into(),
                                );
                            }
                        }
                        summary_parts.push(format!(
                            "DROP {} ~{} rows, {} dependent(s)",
                            t,
                            info.rows_display(),
                            info.dependents.len()
                        ));
                    } else {
                        summary_parts.push(format!("DROP {}", t));
                    }
                }
            }
            Destructive::Truncate { tables, cascade } => {
                for t in tables {
                    lines.push(format!(
                        "  TRUNCATE {}{}",
                        t,
                        if *cascade { " CASCADE" } else { "" }
                    ));
                    if let Some(info) = live.then(|| introspect(command, t)).flatten() {
                        live_reached = true;
                        lines.push(format!(
                            "    rows to erase (estimate) : {}",
                            info.rows_display()
                        ));
                        if !info.dependents.is_empty() && !*cascade {
                            lines.push(format!(
                                "    without CASCADE : will FAIL — referenced by {}",
                                info.dependents.join(", ")
                            ));
                        }
                        summary_parts.push(format!("TRUNCATE {} ~{} rows", t, info.rows_display()));
                    } else {
                        summary_parts.push(format!("TRUNCATE {}", t));
                    }
                }
            }
            Destructive::DeleteFrom { table, has_where } => {
                if *has_where {
                    lines.push(format!("  DELETE FROM {} (filtered by WHERE)", table));
                    lines.push(
                        "    affected rows depend on the filter — cannot estimate cheaply".into(),
                    );
                    summary_parts.push(format!("DELETE FROM {} (filtered)", table));
                } else {
                    lines.push(format!(
                        "  DELETE FROM {} — NO WHERE CLAUSE (deletes every row)",
                        table
                    ));
                    if let Some(info) = live.then(|| introspect(command, table)).flatten() {
                        live_reached = true;
                        lines.push(format!(
                            "    rows to delete (estimate) : {}",
                            info.rows_display()
                        ));
                        summary_parts.push(format!(
                            "DELETE ALL from {} ~{} rows",
                            table,
                            info.rows_display()
                        ));
                    } else {
                        summary_parts.push(format!("DELETE ALL from {}", table));
                    }
                }
            }
        }
    }

    // Roadmap 2.5: the same question the delete preview asks, and it already
    // had the answer - `plan` returning None IS uninsurable, and the line
    // below has said so since v0.13 without anything able to act on it.
    let uninsurable = crate::backup::plan(command, cwd).is_none();
    match crate::backup::plan(command, cwd) {
        Some(plan) => lines.push(format!("  insurance : {} (automatic on run/hook)", plan)),
        None => lines.push("  insurance : none — not reversible without a backup".into()),
    }

    if !live_reached {
        lines.push("  (database unreachable — static analysis only)".into());
    }

    Some(Preview {
        title: "postgres impact".into(),
        lines,
        summary: summary_parts.join("; "),
        uninsurable,
    })
}

// ---------------------------------------------------------------------------
// Tier 2: live introspection — reuse the command's own connection arguments
// ---------------------------------------------------------------------------

/// FK dependents of a table, using the command's own connection (for backup
/// scoping: a CASCADE truncate empties these too, so insurance must cover them).
pub fn fk_dependents(original_command: &str, table: &str) -> Vec<String> {
    introspect(original_command, table)
        .map(|i| i.dependents)
        .unwrap_or_default()
}

struct TableInfo {
    rows: i64, // -1 = table never analyzed; planner has no estimate
    dependents: Vec<String>,
}

impl TableInfo {
    fn rows_display(&self) -> String {
        if self.rows < 0 {
            "unknown (never analyzed)".into()
        } else {
            group_thousands(self.rows)
        }
    }
}

/// Take the original psql command, extract ONLY its connection parameters, and
/// run our own read-only catalog query against them.
///
/// SECURITY (v0.14.1). This function used to copy the user's argv wholesale and
/// merely strip `-c`. That passed every other flag through to a psql we
/// ourselves executed — and psql honours `-f` and `-c` in the same invocation.
/// So `psql -d shop -f wipe.sql -c "DROP TABLE users"` made the *preview* run
/// wipe.sql. `hook::run` generates the preview before returning a decision, so
/// it happened on commands Termaxa then denied: the gate performed the damage
/// it had just blocked. Reproduced end-to-end against a live database.
///
/// The fix is not "also strip -f". A denylist is a losing game — `-o` truncates
/// an arbitrary file, `-L` writes one, `-W` blocks on a prompt, and psql may add
/// more. We now REBUILD the argv from a small allowlist of connection
/// parameters, so nothing we did not explicitly recognise can reach the child
/// process. `-w` is forced so the preview can never hang waiting for a password.
fn introspect(original_command: &str, table: &str) -> Option<TableInfo> {
    let esc = table.replace('\'', "''"); // embed safely inside '...'
    let q = format!(
        "SET default_transaction_read_only = on; \
         SELECT COALESCE((SELECT reltuples::bigint FROM pg_class WHERE oid = '{esc}'::regclass), -1); \
         SELECT COALESCE(string_agg(DISTINCT c.conrelid::regclass::text, ','), '') \
           FROM pg_constraint c WHERE c.contype = 'f' AND c.confrelid = '{esc}'::regclass;"
    );

    let tokens = shell_tokens(original_command);
    let prog = psql_program(&tokens)?;
    let mut args = connection_args(&tokens);
    args.extend(["-w", "-t", "-A", "-X", "-c"].iter().map(|s| s.to_string()));
    args.push(q);

    let out = Command::new(&prog)
        .args(&args)
        .env("PGCONNECT_TIMEOUT", "3")
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // wrong table, no permissions, db down — degrade to static
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // psql echoes a command-status tag for the leading SET even under -t -A,
    // so it arrives as a line before the two result rows. Drop it explicitly
    // rather than positionally — a silent parse failure here degrades the
    // preview to "database unreachable", which reads like a connection problem.
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "SET");
    let rows: i64 = lines.next()?.trim().parse().ok()?;
    let dependents: Vec<String> = lines
        .next()
        .map(|l| {
            l.trim()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    Some(TableInfo { rows, dependents })
}

/// The psql binary to invoke, taken from the command's own first token so a
/// non-PATH install (`/usr/local/pgsql/bin/psql`) still works. The file name
/// must be exactly `psql`; `ends_with("psql")` would also accept `evilpsql`.
pub fn psql_program(tokens: &[String]) -> Option<String> {
    let first = tokens.first()?;
    let name = first.rsplit(['/', '\\']).next().unwrap_or(first);
    let stem = name.strip_suffix(".exe").unwrap_or(name);
    if stem == "psql" {
        Some(first.clone())
    } else {
        None
    }
}

/// psql short options that consume a value, so a dropped flag also drops its
/// argument instead of leaving it to be mistaken for the positional dbname.
const PSQL_VALUE_SHORT: &[char] = &[
    'c', 'd', 'f', 'v', 'L', 'o', 'F', 'P', 'R', 'T', 'h', 'p', 'U',
];

/// psql long options that consume a value.
const PSQL_VALUE_LONG: &[&str] = &[
    "command",
    "dbname",
    "file",
    "set",
    "variable",
    "log-file",
    "output",
    "field-separator",
    "pset",
    "record-separator",
    "table-attr",
    "host",
    "port",
    "username",
];

/// Extract ONLY the connection parameters from a psql command, rebuilt into a
/// canonical form. This is an allowlist, and deliberately so.
///
/// Termaxa executes two children derived from a user's psql command: the
/// preview's catalog query, and `pg_dump` for insurance. Copying the user's
/// argv into either is unsafe in both directions:
///
///   - Into psql, `-f` executes a SQL file, `-o`/`-L` truncate arbitrary files,
///     and `-W` blocks on a password prompt.
///   - Into pg_dump, the flag namespaces disagree: psql's `-t` (tuples-only)
///     is pg_dump's `--table`, and `-X`, `-A`, `-1` are not pg_dump options at
///     all — so pg_dump exits non-zero and the backup is silently never taken.
///     A harmless `-X` on the command line decided whether insurance existed.
///
/// Only `-h/-p/-U/-d` and a positional dbname survive, re-emitted as separate
/// tokens. Everything else — including anything psql adds in future — is
/// dropped, which fails toward "no live introspection", never toward
/// "unexpected execution".
pub fn connection_args(tokens: &[String]) -> Vec<String> {
    let mut host: Option<String> = None;
    let mut port: Option<String> = None;
    let mut user: Option<String> = None;
    let mut dbname: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = 1; // token 0 is the program
    while i < tokens.len() {
        let t = &tokens[i];

        // ---- long options -------------------------------------------------
        if let Some(body) = t.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            let takes_value = PSQL_VALUE_LONG.contains(&name);
            let value = match (inline, takes_value) {
                (Some(v), _) => Some(v),
                (None, true) => {
                    i += 1;
                    tokens.get(i).cloned()
                }
                (None, false) => None,
            };
            match name {
                "host" => host = value,
                "port" => port = value,
                "username" => user = value,
                "dbname" => dbname = value,
                _ => {} // dropped, value consumed above if it took one
            }
            i += 1;
            continue;
        }

        // ---- short option clusters (`-tAX`, `-dshop`, `-U app`) ------------
        if t.starts_with('-') && t.len() > 1 {
            let chars: Vec<char> = t.chars().skip(1).collect();
            let mut j = 0;
            while j < chars.len() {
                let f = chars[j];
                if PSQL_VALUE_SHORT.contains(&f) {
                    // rest of this token is the value; else the next token is
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if rest.is_empty() {
                        i += 1;
                        tokens.get(i).cloned()
                    } else {
                        Some(rest)
                    };
                    match f {
                        'h' => host = value,
                        'p' => port = value,
                        'U' => user = value,
                        'd' => dbname = value,
                        _ => {} // -c, -f, -o, -L, -v, -F, -P, -R, -T: dropped
                    }
                    break; // value-taking flag ends the cluster
                }
                j += 1; // boolean flag (-t, -A, -X, -q, -1, -w, -W): dropped
            }
            i += 1;
            continue;
        }

        positionals.push(t.clone());
        i += 1;
    }

    // psql takes dbname then username as positionals, after the flags.
    if dbname.is_none() {
        dbname = positionals.first().cloned();
    }
    if user.is_none() {
        user = positionals.get(1).cloned();
    }

    let mut out = Vec::new();
    for (flag, value) in [("-h", host), ("-p", port), ("-U", user), ("-d", dbname)] {
        if let Some(v) = value {
            if !v.is_empty() {
                out.push(flag.to_string());
                out.push(v);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tier 1: static analysis — tokenizer + destructive-statement parser
// ---------------------------------------------------------------------------

/// Split a command line into tokens, respecting single and double quotes.
pub fn shell_tokens(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '\\' if in_double => {
                if let Some(&n) = chars.peek() {
                    cur.push(n);
                    chars.next();
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Pull the SQL string out of psql's -c / --command flag.
fn extract_sql(tokens: &[String]) -> Option<String> {
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == "-c" || tokens[i] == "--command" {
            return tokens.get(i + 1).cloned();
        }
        if let Some(rest) = tokens[i].strip_prefix("--command=") {
            return Some(rest.to_string());
        }
        i += 1;
    }
    None
}

/// Find destructive statements in (possibly multi-statement) SQL.
/// Deliberately conservative: recognizes common shapes, returns nothing
/// when unsure. A missing preview is safe; the policy layer still applies.
pub fn parse_destructive(sql: &str) -> Vec<Destructive> {
    sql.split(';').filter_map(parse_one).collect()
}

fn parse_one(stmt: &str) -> Option<Destructive> {
    let words: Vec<String> = stmt.split_whitespace().map(|w| w.to_string()).collect();
    if words.is_empty() {
        return None;
    }
    let kw = |i: usize| words.get(i).map(|w| w.to_uppercase()).unwrap_or_default();

    if kw(0) == "DROP" && kw(1) == "TABLE" {
        let mut i = 2;
        let mut if_exists = false;
        if kw(i) == "IF" && kw(i + 1) == "EXISTS" {
            if_exists = true;
            i += 2;
        }
        let (tables, after) = read_table_list(&words, i);
        let cascade = words[after..].iter().any(|w| w.to_uppercase() == "CASCADE");
        if tables.is_empty() {
            return None;
        }
        return Some(Destructive::DropTable {
            tables,
            cascade,
            if_exists,
        });
    }

    if kw(0) == "TRUNCATE" {
        let mut i = 1;
        if kw(i) == "TABLE" {
            i += 1;
        }
        if kw(i) == "ONLY" {
            i += 1;
        }
        let (tables, after) = read_table_list(&words, i);
        let cascade = words[after..].iter().any(|w| w.to_uppercase() == "CASCADE");
        if tables.is_empty() {
            return None;
        }
        return Some(Destructive::Truncate { tables, cascade });
    }

    if kw(0) == "DELETE" && kw(1) == "FROM" {
        let mut i = 2;
        if kw(i) == "ONLY" {
            i += 1;
        }
        let table = clean_ident(words.get(i)?)?;
        let has_where = words.iter().any(|w| w.to_uppercase() == "WHERE");
        return Some(Destructive::DeleteFrom { table, has_where });
    }

    None
}

/// Read a comma-separated table list starting at index `i`.
/// Returns (tables, index after the list).
fn read_table_list(words: &[String], mut i: usize) -> (Vec<String>, usize) {
    let mut tables = Vec::new();
    while i < words.len() {
        let w = &words[i];
        let upper = w.to_uppercase();
        if upper == "CASCADE" || upper == "RESTRICT" {
            break;
        }
        let trailing_comma = w.ends_with(',');
        if let Some(t) = clean_ident(w) {
            tables.push(t);
        }
        i += 1;
        if !trailing_comma && !words.get(i).map(|n| n == ",").unwrap_or(false) {
            // no comma continues the list — we're done
            if words.get(i).map(|n| n.starts_with(',')).unwrap_or(false) {
                continue;
            }
            break;
        }
        if words.get(i).map(|n| n == ",").unwrap_or(false) {
            i += 1;
        }
    }
    (tables, i)
}

/// Normalize an identifier: strip commas/quotes, keep schema.name, reject junk.
fn clean_ident(raw: &str) -> Option<String> {
    let t = raw.trim_matches(',').trim_matches('"').trim();
    if t.is_empty() {
        return None;
    }
    let ok = t
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '$');
    if ok {
        Some(t.to_string())
    } else {
        None
    }
}

fn group_thousands(n: i64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_respects_quotes() {
        let t = shell_tokens(r#"psql -h prod -c "DROP TABLE users CASCADE""#);
        assert_eq!(
            t,
            vec!["psql", "-h", "prod", "-c", "DROP TABLE users CASCADE"]
        );
        let t = shell_tokens("psql -c 'DELETE FROM orders'");
        assert_eq!(t[2], "DELETE FROM orders");
    }

    #[test]
    fn extracts_sql_from_variants() {
        let t = shell_tokens("psql -U app --command 'TRUNCATE logs'");
        assert_eq!(extract_sql(&t).unwrap(), "TRUNCATE logs");
        let t = shell_tokens("psql --command='DROP TABLE a'");
        assert_eq!(extract_sql(&t).unwrap(), "DROP TABLE a");
    }

    #[test]
    fn parses_drop_variants() {
        let d = parse_destructive("DROP TABLE users CASCADE");
        assert_eq!(
            d,
            vec![Destructive::DropTable {
                tables: vec!["users".into()],
                cascade: true,
                if_exists: false
            }]
        );
        let d = parse_destructive("drop table if exists a, b");
        assert_eq!(
            d,
            vec![Destructive::DropTable {
                tables: vec!["a".into(), "b".into()],
                cascade: false,
                if_exists: true
            }]
        );
    }

    #[test]
    fn parses_truncate_and_delete() {
        assert_eq!(
            parse_destructive("TRUNCATE TABLE audit_log"),
            vec![Destructive::Truncate {
                tables: vec!["audit_log".into()],
                cascade: false
            }]
        );
        assert_eq!(
            parse_destructive("DELETE FROM users"),
            vec![Destructive::DeleteFrom {
                table: "users".into(),
                has_where: false
            }]
        );
        assert_eq!(
            parse_destructive("DELETE FROM users WHERE id = 5"),
            vec![Destructive::DeleteFrom {
                table: "users".into(),
                has_where: true
            }]
        );
    }

    #[test]
    fn ignores_safe_sql_and_non_psql() {
        assert!(parse_destructive("SELECT * FROM users").is_empty());
        assert!(preview_for("git push origin main", std::path::Path::new("."), true).is_none());
        assert!(preview_for("psql -c 'SELECT 1'", std::path::Path::new("."), true).is_none());
    }

    #[test]
    fn connection_args_keeps_only_connection_parameters() {
        let t = shell_tokens("psql -h db.prod -U app -d shop -c 'DROP TABLE x'");
        assert_eq!(
            connection_args(&t),
            vec!["-h", "db.prod", "-U", "app", "-d", "shop"]
        );
    }

    /// Schipper review, finding 10, confirmed against a live database: psql
    /// honours `-f` and `-c` in one invocation, so passing `-f` through to the
    /// preview's own psql call executed the user's SQL file — including on
    /// commands Termaxa then denied.
    #[test]
    fn file_flag_never_reaches_the_preview_invocation() {
        let t = shell_tokens(r#"psql -d shop -f wipe.sql -c "DROP TABLE users""#);
        assert_eq!(connection_args(&t), vec!["-d", "shop"]);
    }

    /// The same class, one step further out: a denylist would have to grow
    /// forever. `-o` truncates a file, `-L` writes one, `-W` blocks on a
    /// prompt. None of them are connection parameters, so none survive.
    #[test]
    fn side_effecting_flags_are_dropped_not_enumerated() {
        let t = shell_tokens(
            r#"psql -d shop -o /etc/passwd -L audit.log -W -f a.sql -c "TRUNCATE users""#,
        );
        assert_eq!(connection_args(&t), vec!["-d", "shop"]);
    }

    /// The attached short form is one token, so an equality check on `-c`
    /// missed it and the destructive SQL itself was re-executed.
    #[test]
    fn attached_short_forms_are_parsed_not_matched() {
        let t = shell_tokens(r#"psql -dshop "-cTRUNCATE users""#);
        assert_eq!(connection_args(&t), vec!["-d", "shop"]);
    }

    /// A cluster of booleans ending in a value-taking flag, getopt style.
    #[test]
    fn boolean_clusters_are_dropped_without_eating_the_dbname() {
        let t = shell_tokens("psql -tAX -d shop -c 'TRUNCATE users'");
        assert_eq!(connection_args(&t), vec!["-d", "shop"]);
    }

    /// A dropped flag must consume its own value, or `wipe.sql` would be left
    /// looking like the positional dbname.
    #[test]
    fn dropped_flags_consume_their_value() {
        let t = shell_tokens("psql -f wipe.sql shop app -c 'TRUNCATE users'");
        assert_eq!(connection_args(&t), vec!["-U", "app", "-d", "shop"]);
    }

    #[test]
    fn long_forms_both_spellings() {
        let t = shell_tokens("psql --host=db --port 6543 --username=app --dbname shop -c 'x'");
        assert_eq!(
            connection_args(&t),
            vec!["-h", "db", "-p", "6543", "-U", "app", "-d", "shop"]
        );
    }

    #[test]
    fn psql_program_requires_the_exact_binary_name() {
        assert_eq!(
            psql_program(&shell_tokens("/usr/local/pgsql/bin/psql -c 'x'")),
            Some("/usr/local/pgsql/bin/psql".to_string())
        );
        assert_eq!(psql_program(&shell_tokens("evilpsql -c 'x'")), None);
    }

    // All three users are #[cfg(unix)] (they need shell stub binaries), so on
    // Windows this import is unused and -D warnings makes it fatal.
    #[cfg(unix)]
    use crate::testutil::TempTree;

    // -----------------------------------------------------------------------
    // The grammar, at the places it decides how much is destroyed.
    // -----------------------------------------------------------------------

    fn truncate_of(sql: &str) -> (Vec<String>, bool) {
        match parse_destructive(sql).into_iter().next() {
            Some(Destructive::Truncate { tables, cascade }) => (tables, cascade),
            other => panic!("expected a TRUNCATE, got {other:?} for {sql:?}"),
        }
    }

    #[test]
    fn a_table_list_ends_at_cascade_rather_than_swallowing_it() {
        // CASCADE is a modifier, not a table. Reading it as one both invents a
        // table and loses the fact that dependents will be emptied too.
        let (tables, cascade) = truncate_of("TRUNCATE users CASCADE");
        assert_eq!(tables, ["users"]);
        assert!(cascade);

        let (tables, cascade) = truncate_of("TRUNCATE users RESTRICT");
        assert_eq!(tables, ["users"]);
        assert!(!cascade, "RESTRICT is the opposite of CASCADE");
    }

    #[test]
    fn a_comma_separated_list_is_read_in_either_spelling() {
        for sql in ["TRUNCATE a, b", "TRUNCATE a , b", "TRUNCATE TABLE a, b"] {
            let (tables, _) = truncate_of(sql);
            assert_eq!(tables, ["a", "b"], "{sql}");
        }
        // A trailing comma runs the list to the very end of the statement,
        // which is where the loop bound is the only thing left to stop it.
        let (tables, _) = truncate_of("TRUNCATE a, b,");
        assert_eq!(tables, ["a", "b"]);
    }

    /// KNOWN GAP, pinned so a fix flips it deliberately rather than by
    /// accident. A comma with no space after it is valid SQL and this parser
    /// does not read it: `clean_ident` refuses `a,b` because the comma is
    /// interior rather than trailing, so the table list comes back empty and
    /// the statement is classified as nothing.
    ///
    /// The consequence is not a missing preview. `backup::pg_backup_targets`
    /// reads the same parse, so the command runs with NO pg_dump behind it:
    ///
    ///   TRUNCATE a, b   parsed, insurance planned
    ///   TRUNCATE a,b    not parsed, NO insurance
    ///
    /// The intent classifier still sees it (it matches on the text), so policy
    /// and the breaker still gate the command. It is only the safety net that
    /// is decided by whitespace, which is the same class as the v0.14 path bug
    /// in delete.rs: "path syntax must never decide whether a safety net
    /// exists". Here it is comma spacing.
    #[test]
    fn a_comma_without_a_space_is_a_known_gap_with_no_insurance_beneath() {
        assert!(
            parse_destructive("TRUNCATE a,b").is_empty(),
            "if this starts parsing, the gap closed and this test should be \
             inverted rather than deleted"
        );
        assert!(parse_destructive("DROP TABLE a,b").is_empty());

        // The spaced spelling of the same statement is read in full, which is
        // what makes the difference a spelling rather than a limitation.
        assert_eq!(truncate_of("TRUNCATE a, b").0, ["a", "b"]);
    }

    #[test]
    fn only_is_stepped_over_rather_than_taken_as_the_table() {
        let (tables, _) = truncate_of("TRUNCATE ONLY users");
        assert_eq!(tables, ["users"]);

        match parse_destructive("DELETE FROM ONLY users")
            .into_iter()
            .next()
        {
            Some(Destructive::DeleteFrom { table, has_where }) => {
                assert_eq!(table, "users");
                assert!(!has_where);
            }
            other => panic!("expected a DELETE, got {other:?}"),
        }
    }

    #[test]
    fn delete_needs_both_of_its_keywords() {
        // `DELETE ONLY users` is not a statement postgres accepts, and
        // classifying it would be inventing a destruction that cannot happen.
        assert!(parse_destructive("DELETE ONLY users").is_empty());
        assert!(parse_destructive("FROM users").is_empty());
    }

    #[test]
    fn a_malformed_if_exists_does_not_make_a_drop_invisible() {
        // Both halves have to be present for the clause to be consumed. If
        // only `IF` is checked, the parser steps past two words that are not
        // there and loses the table list, and a DROP goes unclassified.
        let found = parse_destructive("DROP TABLE IF users");
        assert!(
            !found.is_empty(),
            "a DROP with a broken IF EXISTS is still a DROP"
        );
    }

    #[test]
    fn an_identifier_may_be_schema_qualified_or_carry_the_allowed_symbols() {
        for (sql, want) in [
            ("TRUNCATE public.users", "public.users"),
            ("TRUNCATE _private", "_private"),
            ("TRUNCATE tab$le", "tab$le"),
            ("TRUNCATE \"users\"", "users"),
        ] {
            let (tables, _) = truncate_of(sql);
            assert_eq!(tables, [want], "{sql}");
        }
        // And junk is refused rather than guessed at.
        assert!(parse_destructive("TRUNCATE (select 1)").is_empty());
    }

    #[test]
    fn the_tokenizer_keeps_each_quote_kind_to_itself() {
        // A `"` inside single quotes is data, and a `'` inside double quotes
        // is data. Reading either as a delimiter re-splits the SQL that
        // follows it, and the statement the gate examines stops being the
        // statement that will run.
        assert_eq!(
            shell_tokens("psql -c 'it\"s fine'"),
            ["psql", "-c", "it\"s fine"]
        );
        assert_eq!(
            shell_tokens("psql -c \"it's fine\""),
            ["psql", "-c", "it's fine"]
        );
    }

    #[test]
    fn a_backslash_escapes_only_inside_double_quotes() {
        // Inside double quotes it protects the next character, so the string
        // does not end early. Outside them psql sees a literal backslash, and
        // consuming the next character there would drop it from the command.
        assert_eq!(
            shell_tokens("psql -c \"a\\\"b\""),
            ["psql", "-c", "a\"b"],
            "the escaped quote belongs to the string, not to its end"
        );
        assert_eq!(shell_tokens("psql a\\b"), ["psql", "a\\b"]);
    }

    #[test]
    fn a_psql_invocation_without_a_statement_has_nothing_to_preview() {
        // extract_sql walks to the end of the token list here, and the bound
        // on that walk is all that separates it from an index panic.
        assert!(preview_for("psql -d shop", std::path::Path::new("."), false).is_none());
        assert!(
            preview_for("psql -d shop -U app -tAX", std::path::Path::new("."), false).is_none()
        );
    }

    #[test]
    fn every_connection_parameter_survives_the_rebuild() {
        // The argv is rebuilt from an allowlist rather than filtered, so a
        // parameter missing from that list is one the preview silently
        // connects without: a port dropped here sends the catalog query to
        // 5432 and reports on whichever database answers there.
        let args = connection_args(&shell_tokens(
            "psql -h db.internal -p 5433 -U app -d shop -c \"TRUNCATE users\"",
        ));
        for pair in [
            ["-h", "db.internal"],
            ["-p", "5433"],
            ["-U", "app"],
            ["-d", "shop"],
        ] {
            assert!(
                args.windows(2).any(|w| w == pair),
                "{pair:?} must survive: {args:?}"
            );
        }
        // And the statement itself must not.
        assert!(!args.iter().any(|a| a.contains("TRUNCATE")), "{args:?}");
    }

    #[test]
    fn a_lone_dash_is_a_positional_not_a_flag_cluster() {
        // `-` on its own carries no flag letters. Treating it as a cluster
        // would silently drop it instead of letting it fall through to the
        // positional handling psql itself applies.
        let args = connection_args(&shell_tokens("psql -"));
        assert!(args.windows(2).any(|w| w == ["-d", "-"]), "{args:?}");
    }

    #[test]
    fn a_table_list_that_reaches_cascade_after_a_comma_still_stops() {
        // The comma keeps the list open, so CASCADE arrives at the top of the
        // loop rather than at its tail. It is a modifier either way.
        let (tables, cascade) = truncate_of("TRUNCATE a, CASCADE");
        assert_eq!(tables, ["a"]);
        assert!(cascade);
    }

    #[test]
    fn two_tables_without_a_comma_are_not_a_list() {
        // `TRUNCATE a b` is not valid SQL, and reading it as two tables would
        // mean insuring, previewing and reporting a table nobody named.
        let (tables, _) = truncate_of("TRUNCATE a b");
        assert_eq!(tables, ["a"]);
    }

    #[test]
    fn thousands_are_grouped_at_every_boundary() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(100), "100");
        assert_eq!(group_thousands(1234567), "1,234,567");
        assert_eq!(group_thousands(-1000), "-1,000");
    }

    #[test]
    fn a_row_count_that_was_never_analyzed_says_so() {
        // -1 is postgres saying "I have never counted", which is a different
        // fact from zero rows and must not be printed as one.
        let unknown = TableInfo {
            rows: -1,
            dependents: vec![],
        };
        assert_eq!(unknown.rows_display(), "unknown (never analyzed)");

        let counted = TableInfo {
            rows: 0,
            dependents: vec![],
        };
        assert_eq!(counted.rows_display(), "0");
    }

    // -----------------------------------------------------------------------
    // Introspection, against a stub psql.
    //
    // The stub is reached by ABSOLUTE PATH, taken from the command itself, so
    // nothing here touches the process environment: psql_program accepts any
    // path whose file stem is psql.
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    fn stub_psql(dir: &std::path::Path, body: &str, code: i32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("psql");
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' \"{body}\"\nexit {code}\n"),
        )
        .expect("stub must be writable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stub must be executable");
        path
    }

    #[cfg(unix)]
    #[test]
    fn introspection_reads_the_row_count_and_the_dependents() {
        let tmp = TempTree::new("pg-introspect");
        // SET lines and blanks are noise from the session setup, not data.
        let psql = stub_psql(tmp.path(), "SET\n\n120000\norders,invoices\n", 0);
        let command = format!("{} -d shop -c \"TRUNCATE users\"", psql.display());

        assert_eq!(
            fk_dependents(&command, "users"),
            ["orders", "invoices"],
            "the dependents decide what a CASCADE would also empty"
        );

        let p = preview_for(&command, std::path::Path::new("."), true)
            .expect("a truncate is previewable");
        assert!(
            p.lines.iter().any(|l| l.contains("120,000")),
            "the row estimate is the blast radius: {:?}",
            p.lines
        );
        assert!(
            p.lines
                .iter()
                .any(|l| l.contains("without CASCADE") && l.contains("orders")),
            "a truncate with dependents and no CASCADE will fail, and saying so \
             is the difference between a preview and a guess: {:?}",
            p.lines
        );
        assert!(
            !p.lines.iter().any(|l| l.contains("database unreachable")),
            "the database answered: {:?}",
            p.lines
        );

        // With CASCADE the dependents are emptied on purpose, so the warning
        // that the statement will FAIL without it must not appear.
        let with_cascade = format!("{} -d shop -c \"TRUNCATE users CASCADE\"", psql.display());
        let p = preview_for(&with_cascade, std::path::Path::new("."), true)
            .expect("a truncate is previewable");
        assert!(
            !p.lines.iter().any(|l| l.contains("without CASCADE")),
            "CASCADE was given: {:?}",
            p.lines
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_empty_dependent_list_is_not_a_dependent() {
        let tmp = TempTree::new("pg-deps");
        let psql = stub_psql(tmp.path(), "SET\n7\norders,,invoices\n", 0);
        let command = format!("{} -d shop -c \"TRUNCATE users\"", psql.display());

        assert_eq!(fk_dependents(&command, "users"), ["orders", "invoices"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_database_that_refuses_degrades_to_static_analysis() {
        // Wrong table, no permission, database down: all the same answer, and
        // it must be a quieter preview rather than a missing one.
        let tmp = TempTree::new("pg-refused");
        let psql = stub_psql(tmp.path(), "FATAL: no", 1);
        let command = format!("{} -d shop -c \"TRUNCATE users\"", psql.display());

        assert!(fk_dependents(&command, "users").is_empty());

        let p = preview_for(&command, std::path::Path::new("."), true)
            .expect("static analysis still applies");
        assert!(
            p.lines.iter().any(|l| l.contains("database unreachable")),
            "{:?}",
            p.lines
        );
        assert!(
            p.lines.iter().any(|l| l.contains("TRUNCATE users")),
            "{:?}",
            p.lines
        );
    }

    #[test]
    fn a_client_that_is_not_psql_is_not_previewed() {
        assert!(preview_for(
            "mysql -e \"DROP TABLE users\"",
            std::path::Path::new("."),
            false
        )
        .is_none());
        assert!(preview_for(
            "psqlx -c \"DROP TABLE users\"",
            std::path::Path::new("."),
            false
        )
        .is_none());
        // An absolute path to the real client still is one.
        assert!(preview_for(
            "/usr/bin/psql -c \"DROP TABLE users\"",
            std::path::Path::new("."),
            false
        )
        .is_some());
    }
}
