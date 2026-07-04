use crate::preview::Preview;
use std::process::Command;

/// Postgres impact analysis.
///
/// Two tiers, degrading gracefully:
///   1. STATIC  — parse the SQL out of a `psql ... -c "..."` command and
///                identify destructive statements (no database needed).
///   2. LIVE    — reuse the command's own connection arguments to run
///                read-only introspection: row estimates + FK dependents.
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

pub fn preview_for(command: &str) -> Option<Preview> {
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
                    let info = introspect(command, t);
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
                    if let Some(info) = introspect(command, t) {
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
                    if let Some(info) = introspect(command, table) {
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

    match crate::backup::plan(command) {
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

/// Take the original psql command, strip its `-c <sql>`, and append our own
/// read-only catalog query — inheriting host/port/user/db/password env verbatim.
fn introspect(original_command: &str, table: &str) -> Option<TableInfo> {
    let esc = table.replace('\'', "''"); // embed safely inside '...'
    let q = format!(
        "SELECT COALESCE((SELECT reltuples::bigint FROM pg_class WHERE oid = '{esc}'::regclass), -1); \
         SELECT COALESCE(string_agg(DISTINCT c.conrelid::regclass::text, ','), '') \
           FROM pg_constraint c WHERE c.contype = 'f' AND c.confrelid = '{esc}'::regclass;"
    );

    let mut args = strip_command_flag(&shell_tokens(original_command));
    args.extend(["-t", "-A", "-X", "-c"].iter().map(|s| s.to_string()));
    args.push(q);

    let out = Command::new(&args[0])
        .args(&args[1..])
        .env("PGCONNECT_TIMEOUT", "3")
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // wrong table, no permissions, db down — degrade to static
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
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

/// Remove `-c/--command <arg>` pairs, keeping every other argument untouched.
pub fn strip_command_flag(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for t in tokens {
        if skip_next {
            skip_next = false;
            continue;
        }
        if t == "-c" || t == "--command" {
            skip_next = true;
            continue;
        }
        if let Some(rest) = t.strip_prefix("--command=") {
            let _ = rest;
            continue;
        }
        out.push(t.clone());
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
    sql.split(';').filter_map(|stmt| parse_one(stmt)).collect()
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
        if i > 0 && (s.len() - i) % 3 == 0 {
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
        assert!(preview_for("git push origin main").is_none());
        assert!(preview_for("psql -c 'SELECT 1'").is_none());
    }

    #[test]
    fn strip_command_flag_keeps_connection_args() {
        let t = shell_tokens("psql -h db.prod -U app -d shop -c 'DROP TABLE x'");
        let stripped = strip_command_flag(&t);
        assert_eq!(
            stripped,
            vec!["psql", "-h", "db.prod", "-U", "app", "-d", "shop"]
        );
    }
}
