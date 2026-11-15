//! Derived projection aliases bind to the same bounded physical table everywhere.
use super::*;
use crate::policy::runtime::matcher::mysql_values;
use crate::protocols::replay::mysql::RecordedMysqlValue;
use serde_json::json;

const SQL: &str = "SELECT {{table}}.id AS {{table}}_id, {{table}}.payload AS {{table}}_payload FROM {{table}} WHERE {{table}}.id=? AND {{table}}.status='ASSISTANT'";

fn family(sql: &str, start: u32, end: u32) -> SqlValueTemplate {
    SqlValueTemplate::new(
        sql,
        &[],
        &[],
        Some(&crate::MysqlTableSeries {
            prefix: "subtasks_".into(),
            start,
            end,
            width: 4,
        }),
    )
    .unwrap()
}

fn physical(table: &str) -> String {
    SQL.replace("{{table}}", table).replace("id=?", "id=7")
}

fn assert_paths(template: &SqlValueTemplate, sql: &str, expected: bool) {
    let actual = bounded_statement_tokens(sql).unwrap();
    assert_eq!(template.matches(sql), expected, "{sql}");
    assert_eq!(template.matches_tokens(&actual), expected, "{sql}");
    assert_eq!(
        template
            .bind(&actual)
            .and_then(|bound| extract(&bound, &actual))
            .is_some(),
        expected,
        "{sql}"
    );
}

#[test]
fn derived_projection_aliases_share_physical_table_binding_in_every_match_path() {
    let template = family(SQL, 0, 1023);
    for table in [
        "subtasks_0000",
        "subtasks_0220",
        "subtasks_0438",
        "subtasks_1023",
    ] {
        let sql = physical(table);
        assert_paths(&template, &sql, true);
        let quoted = sql
            .replace(&format!("{table}."), &format!("`{table}`."))
            .replace(&format!("AS {table}_id"), &format!("AS `{table}_id`"))
            .replace(
                &format!("AS {table}_payload"),
                &format!("AS `{table}_payload`"),
            )
            .replace(&format!("FROM {table}"), &format!("FROM `{table}`"));
        assert_paths(&template, &quoted, true);
        let prepared = sql.replace("id=7", "id=?");
        let params = [RecordedMysqlValue {
            kind: "integer".into(),
            value: Some(json!(7)),
            raw: None,
        }];
        assert_eq!(
            mysql_values::template_values(&template, Some(&prepared), Some(&params)).unwrap(),
            mysql_values::template_values(&template, Some(&sql), None).unwrap()
        );
    }
    let source = physical("subtasks_0220");
    let target = physical("subtasks_0438");
    assert!(
        mysql_values::template_pair_values(&template, Some(&source), None, Some(&target), None)
            .is_err()
    );
}

#[test]
fn derived_projection_aliases_keep_columns_predicates_shards_and_aliases_exact() {
    let template = family(SQL, 0, 1023);
    let valid = physical("subtasks_0220");
    for sql in [
        valid.replace("AS subtasks_0220_id", "AS subtasks_0438_id"),
        valid.replace("subtasks_0220.payload", "subtasks_0438.payload"),
        valid.replace("subtasks_0220.id=", "subtasks_0438.id="),
        valid.replace("AS subtasks_0220_payload", "AS other_payload"),
        valid.replace(".payload AS", ".result AS"),
        valid.replace("'ASSISTANT'", "'USER'"),
        physical("subtasks_1024"),
        physical("subtasks_220"),
        physical("other_0220"),
    ] {
        assert_paths(&template, &sql, false);
    }
}

#[test]
fn derived_projection_alias_admission_rejects_other_identifier_fragments_and_positions() {
    for sql in [
        "SELECT '{{table}}_id' FROM {{table}} WHERE id=?",
        "SELECT id AS prefix_{{table}} FROM {{table}} WHERE id=?",
        "SELECT {{table}}_id FROM {{table}} WHERE id=?",
        "SELECT id AS {{table}}_ FROM {{table}} WHERE id=?",
        "SELECT id AS {{table}}_{{table}} FROM {{table}} WHERE id=?",
        "SELECT id AS {{table}}_id.extra FROM {{table}} WHERE id=?",
        "SELECT id FROM {{table}} AS {{table}}_alias WHERE id=?",
        "SELECT id FROM {{table}} WHERE id={{table}}_id",
        "SELECT (SELECT id AS {{table}}_id FROM fixed) FROM {{table}} WHERE id=?",
        "SELECT CAST(id AS {{table}}_id) FROM {{table}} WHERE id=?",
        "UPDATE {{table}} SET id=? AS {{table}}_id WHERE id=?",
    ] {
        assert!(
            SqlValueTemplate::new(sql, &["subtasks_0220".into()], &[], None).is_err(),
            "{sql}"
        );
    }
    let suffix = "a".repeat(242);
    let template = family(
        &format!("SELECT id AS {{{{table}}}}_{suffix} FROM {{{{table}}}} WHERE id=?"),
        0,
        0,
    );
    assert_paths(
        &template,
        &format!("SELECT id AS subtasks_0000_{suffix} FROM subtasks_0000 WHERE id=7"),
        true,
    );
    let suffix = format!("{suffix}a");
    let template = family(
        &format!("SELECT id AS {{{{table}}}}_{suffix} FROM {{{{table}}}} WHERE id=?"),
        0,
        0,
    );
    assert_paths(
        &template,
        &format!("SELECT id AS subtasks_0000_{suffix} FROM subtasks_0000 WHERE id=7"),
        false,
    );
}

#[test]
fn derived_alias_overlap_keeps_whole_ranges_and_literal_table_constraints() {
    let template = family(SQL, 0, 1023);
    for (table, expected) in [("subtasks_0220", true), ("subtasks_1024", false)] {
        let exact = SqlValueTemplate::new(&physical(table), &[], &[], None).unwrap();
        assert_eq!(template.overlaps(&exact), expected);
        assert_eq!(exact.overlaps(&template), expected);
    }
    for (sql, expected) in [
        (SQL.replace("{{table}}_id", "subtasks_0220_id"), true),
        (SQL.replace("{{table}}_id", "subtasks_1024_id"), false),
        (SQL.replace("{{table}}_id", "unrelated_id"), false),
        (SQL.replace("{{table}}_id", "{{table}}_different"), false),
    ] {
        let other = family(&sql, 0, 1023);
        assert_eq!(template.overlaps(&other), expected, "{sql}");
        assert_eq!(other.overlaps(&template), expected, "{sql}");
    }
    let bounded = family(SQL, 0, 219);
    let alias = family(&SQL.replace("{{table}}_id", "subtasks_0220_id"), 0, 1023);
    assert!(!bounded.overlaps(&alias));
    assert!(!alias.overlaps(&bounded));
    let disjoint = family(SQL, 1024, 2047);
    assert!(!template.overlaps(&disjoint));
    assert!(!disjoint.overlaps(&template));
}
