use super::*;
mod aliases;
mod materialization;

const STATEMENT_PAIRS: [(&str, &str); 4] = [
    (
        "SELECT id FROM entries WHERE id=?",
        "SELECT id FROM entries WHERE id=7",
    ),
    (
        "INSERT INTO entries (id) VALUES (?)",
        "INSERT INTO entries (id) VALUES (7)",
    ),
    (
        "UPDATE entries SET stamp=? WHERE id=?",
        "UPDATE entries SET stamp='Stable' WHERE id=7",
    ),
    (
        "DELETE FROM entries WHERE id=?",
        "DELETE FROM entries WHERE id=7",
    ),
];

#[test]
fn statement_verb_prefilter_preserves_comments_case_and_whitespace_matching() {
    for (template, sql) in STATEMENT_PAIRS {
        let template = SqlValueTemplate::new(template, &[], &[], None).unwrap();
        let verb = sql.split_ascii_whitespace().next().unwrap();
        for actual in [
            sql.to_string(),
            sql.replacen(verb, &verb.to_ascii_lowercase(), 1),
            format!(" \t\r\n{sql}"),
            format!("/* SELECT INSERT UPDATE DELETE */{sql}"),
            format!("# SELECT UPDATE\n{sql}"),
            format!("-- INSERT DELETE\n{sql}"),
            format!("{}{sql}", " ".repeat(80)),
            sql.replacen(' ', "/**/", 1),
        ] {
            assert!(template.matches(&actual), "{actual}");
        }
    }
}

#[test]
fn statement_verb_prefilter_retains_kind_table_and_unsafe_sql_rejections() {
    for (index, (template, sql)) in STATEMENT_PAIRS.into_iter().enumerate() {
        let template = SqlValueTemplate::new(template, &[], &[], None).unwrap();
        for (other, (_, actual)) in STATEMENT_PAIRS.into_iter().enumerate() {
            if index != other {
                assert!(!template.matches(actual), "{actual}");
            }
        }
        let verb = sql.split_ascii_whitespace().next().unwrap();
        for actual in [
            format!("/*! SELECT */ {sql}"),
            format!("/*+ optimizer_hint */ {sql}"),
            format!("{sql}; DELETE FROM entries"),
            sql.replace("entries", "other_entries"),
            sql.replacen(verb, &format!("{verb}_suffix"), 1),
            format!("'{verb}'{}", &sql[verb.len()..]),
        ] {
            assert!(!template.matches(&actual), "{actual}");
        }
    }
}

fn literal_statement(bytes: usize) -> String {
    let prefix = "UPDATE entries SET payload='";
    let suffix = "', updated_at=? WHERE id=7";
    format!(
        "{prefix}{}{suffix}",
        "x".repeat(bytes - prefix.len() - suffix.len())
    )
}

#[test]
fn sql_value_statements_accept_8_mib_but_templates_retain_64_kib() {
    let template = SqlValueTemplate::new(
        "UPDATE entries SET payload=?, updated_at=? WHERE id=?",
        &[],
        &[],
        None,
    )
    .unwrap();
    for bytes in [
        64 * 1024 + 1,
        267_027,
        1024 * 1024,
        1_314_248,
        8 * 1024 * 1024,
    ] {
        let sql = literal_statement(bytes);
        assert_eq!(sql.len(), bytes);
        assert!(bounded_statement_tokens(&sql).is_some());
        assert!(template.matches(&sql));
        assert!(bounded_tokens(&sql).is_none());
    }
    let oversized = literal_statement(8 * 1024 * 1024 + 1);
    assert!(bounded_statement_tokens(&oversized).is_none());
    assert!(!template.matches(&oversized));

    let mut template = String::from("UPDATE entries SET stamp=?");
    template.push_str(&" ".repeat(64 * 1024 - template.len()));
    assert!(SqlValueTemplate::new(&template, &[], &[], None).is_ok());
    template.push(' ');
    assert!(SqlValueTemplate::new(&template, &[], &[], None).is_err());
}

#[test]
fn larger_sql_value_statements_retain_token_and_statement_safety_bounds() {
    let sql = format!("SELECT {}", vec!["?"; 16_384].join(","));
    assert_eq!(bounded_statement_tokens(&sql).unwrap().len(), 32_768);
    assert_eq!(bounded_tokens(&sql).unwrap().len(), 32_768);
    assert!(bounded_statement_tokens(&format!("{sql},")).is_none());
    assert!(bounded_statement_tokens(&format!("{sql},?")).is_none());

    let large = literal_statement(300_000);
    for sql in [
        format!("{large}; DELETE FROM entries"),
        format!("{large} /*! AND id=8 */"),
        format!("{large} /*+ BKA(entries) */"),
        format!("{large} AND payload='unterminated"),
    ] {
        assert!(bounded_statement_tokens(&sql).is_none());
    }
}

#[test]
fn exact_reserved_marker_names_remain_literal_when_table_families_intersect() {
    let exact = SqlValueTemplate::new(
        "SELECT id FROM __traffic_time_table__ WHERE name=?",
        &[],
        &[],
        None,
    )
    .unwrap();
    assert!(exact.matches("SELECT id FROM __traffic_time_table__ WHERE name='name'"));
    let family = SqlValueTemplate::new(
        "SELECT id FROM {{table}} WHERE name=?",
        &["__traffic_time_table__".into()],
        &[],
        None,
    )
    .unwrap();
    assert!(exact.overlaps(&family));
    assert!(family.overlaps(&exact));
    let other = SqlValueTemplate::new(
        "SELECT id FROM {{table}} WHERE name=?",
        &["items".into()],
        &[],
        None,
    )
    .unwrap();
    assert!(!exact.overlaps(&other));
    assert!(!other.overlaps(&exact));
    let literal = SqlValueTemplate::new(
        "UPDATE items SET name='__traffic_time_table__' WHERE id=?",
        &[],
        &[],
        None,
    )
    .unwrap();
    assert!(literal.matches("UPDATE items SET name='__traffic_time_table__' WHERE id=7"));
    assert!(!literal.matches("UPDATE items SET name='items' WHERE id=7"));
}
