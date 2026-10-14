use super::*;

fn literal_statement(bytes: usize) -> String {
    let prefix = "UPDATE entries SET payload='";
    let suffix = "', updated_at=? WHERE id=7";
    format!(
        "{prefix}{}{suffix}",
        "x".repeat(bytes - prefix.len() - suffix.len())
    )
}

#[test]
fn sql_value_statements_accept_256_kib_but_templates_retain_64_kib() {
    let template = SqlValueTemplate::new(
        "UPDATE entries SET payload=?, updated_at=? WHERE id=?",
        &[],
        &[],
        None,
    )
    .unwrap();
    for bytes in [64 * 1024 + 1, 175_909, 256 * 1024] {
        let sql = literal_statement(bytes);
        assert_eq!(sql.len(), bytes);
        assert!(bounded_statement_tokens(&sql).is_some());
        assert!(template.matches(&sql));
        assert!(bounded_tokens(&sql).is_none());
    }
    let oversized = literal_statement(256 * 1024 + 1);
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
    let sql = format!("SELECT {}", vec!["?"; 4096].join(","));
    assert_eq!(bounded_statement_tokens(&sql).unwrap().len(), 8192);
    assert_eq!(bounded_tokens(&sql).unwrap().len(), 8192);
    assert!(bounded_statement_tokens(&format!("{sql},?")).is_none());

    let large = literal_statement(175_909);
    for sql in [
        format!("{large}; DELETE FROM entries"),
        format!("{large} /*! AND id=8 */"),
        format!("{large} /*+ BKA(entries) */"),
        format!("{large} AND payload='unterminated"),
    ] {
        assert!(bounded_statement_tokens(&sql).is_none());
    }
}
