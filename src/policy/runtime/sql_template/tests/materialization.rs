use super::*;
use crate::policy::runtime::matcher::mysql_values;
use crate::protocols::replay::mysql::RecordedMysqlValue;
use crate::protocols::replay::mysql::sql_match::materialize_tokens;
use serde_json::json;

fn assert_equivalent(
    template: &SqlValueTemplate,
    sql: &str,
    params: Option<&[RecordedMysqlValue]>,
) {
    let previous = mysql_values::template_values(template, Some(sql), params).is_ok();
    let optimized = bounded_statement_tokens(sql)
        .and_then(|tokens| materialize_tokens(tokens, params.unwrap_or_default()))
        .is_some_and(|actual| template.matches_tokens(&actual));
    assert_eq!(
        optimized, previous,
        "SQL selector semantic difference: {sql}"
    );
}

#[test]
fn token_selector_preserves_scalar_types_predicates_literals_and_sql_safety() {
    let template = SqlValueTemplate::new(
        "UPDATE entries SET stamp=?, payload=? WHERE id=7 AND stable='fixed'",
        &[],
        &[],
        None,
    )
    .unwrap();
    for sql in [
        "UPDATE entries SET stamp=1000, payload='data' WHERE id=7 AND stable='fixed'",
        "/* comment */ update `entries` set stamp=1e3, payload=0x64617461 where id=7 and stable='fixed'",
        "UPDATE entries SET stamp=NULL, payload='a;b' WHERE id=7 AND stable='fixed'",
        "UPDATE entries SET stamp=-1, payload=true WHERE id=7 AND stable='fixed'",
        "UPDATE entries SET stamp=other_column, payload='data' WHERE id=7 AND stable='fixed'",
        "UPDATE entries SET stamp=1000, payload='data' WHERE id='7' AND stable='fixed'",
        "UPDATE entries SET stamp=1000, payload='data' WHERE id=8 AND stable='fixed'",
        "UPDATE entries SET stamp=1000, payload='data' WHERE stable='fixed' AND id=7",
        "UPDATE entries SET stamp=1000, payload='data' WHERE id=7 AND stable='changed'",
        "UPDATE entries SET stamp=1000, payload='data' WHERE id=7 AND stable='fixed'; DELETE FROM entries",
        "UPDATE entries SET stamp=1000, payload='data' WHERE id=7 AND stable='fixed' /*! AND id=8 */",
        "UPDATE entries SET stamp=1000, payload='data' WHERE id=7 AND stable='fixed' /*+ hint */",
        "UPDATE entries SET stamp='unterminated",
    ] {
        assert_equivalent(&template, sql, None);
    }
    let sql = "UPDATE entries SET stamp=?, payload=? WHERE id=? AND stable=?";
    let p = |kind: &str, value| RecordedMysqlValue {
        kind: kind.into(),
        value: Some(value),
        raw: None,
    };
    for params in [
        vec![
            p("integer", json!(1000)),
            p("string", json!("data")),
            p("integer", json!(7)),
            p("string", json!("fixed")),
        ],
        vec![
            p("integer", json!(1000)),
            p("string", json!("data")),
            p("integer", json!(8)),
            p("string", json!("fixed")),
        ],
        vec![
            p("integer", json!(1000)),
            p("string", json!("data")),
            p("string", json!("7")),
            p("string", json!("fixed")),
        ],
        vec![
            p("unsupported", json!(1000)),
            p("string", json!("data")),
            p("integer", json!(7)),
            p("string", json!("fixed")),
        ],
        vec![p("integer", json!(1000))],
        vec![],
    ] {
        assert_equivalent(&template, sql, Some(&params));
    }
    assert_equivalent(&template, sql, None);
}

#[test]
fn token_selector_preserves_one_physical_table_and_target_pair_binding() {
    let template = SqlValueTemplate::new(
        "UPDATE {{table}} SET {{table}}.stamp=? WHERE {{table}}.id=7",
        &["entries_01".into(), "entries_02".into()],
        &[],
        None,
    )
    .unwrap();
    for sql in [
        "UPDATE entries_01 SET entries_01.stamp=1000 WHERE entries_01.id=7",
        "UPDATE entries_02 SET entries_02.stamp=1000 WHERE entries_02.id=7",
        "UPDATE entries_03 SET entries_03.stamp=1000 WHERE entries_03.id=7",
        "UPDATE entries_01 SET entries_02.stamp=1000 WHERE entries_01.id=7",
        "UPDATE entries_01 SET entries_01.stamp=1000 WHERE entries_02.id=7",
        "UPDATE entries_01 SET entries_01.stamp=1000 WHERE entries_01.id=8",
    ] {
        assert_equivalent(&template, sql, None);
    }
    let source = "UPDATE entries_01 SET entries_01.stamp=1000 WHERE entries_01.id=7";
    let target = "UPDATE entries_02 SET entries_02.stamp=2000 WHERE entries_02.id=7";
    assert!(template.matches(source));
    assert!(template.matches(target));
    assert!(
        mysql_values::template_pair_values(&template, Some(source), None, Some(target), None)
            .is_err()
    );
    assert!(
        mysql_values::template_pair_values(
            &template,
            Some(source),
            None,
            Some(&source.replace("1000", "2000")),
            None
        )
        .is_ok()
    );
}

#[test]
fn verb_rejection_never_changes_full_token_matching() {
    let template =
        SqlValueTemplate::new("UPDATE entries SET stamp=? WHERE id=7", &[], &[], None).unwrap();
    for sql in [
        "UPDATE entries SET stamp=1000 WHERE id=7",
        "UPDATE/**/entries SET stamp=1000 WHERE id=7",
        "/* prefix */UPDATE entries SET stamp=1000 WHERE id=7",
        "# prefix\nUPDATE entries SET stamp=1000 WHERE id=7",
        "-- prefix\nUPDATE entries SET stamp=1000 WHERE id=7",
        "ROLLBACK ",
        "COMMIT ",
        "BEGIN ",
        "SHOW entries",
        "SET stamp=1000",
        "UPDATE_suffix entries SET stamp=1000 WHERE id=7",
        "UPDATE0 entries SET stamp=1000 WHERE id=7",
        "UPDATE`entries` SET stamp=1000 WHERE id=7",
        "'UPDATE' entries SET stamp=1000 WHERE id=7",
        "/*! UPDATE */ entries SET stamp=1000 WHERE id=7",
        "/*+ hint */ UPDATE entries SET stamp=1000 WHERE id=7",
    ] {
        let full = bounded_statement_tokens(sql).is_some_and(|actual| {
            template
                .bind(&actual)
                .is_some_and(|bound| extract(&bound, &actual).is_some())
        });
        assert_eq!(
            template.matches(sql),
            full,
            "verb shortcut changed match: {sql}"
        );
    }
    for sql in [
        "ROLLBACK ",
        "COMMIT ",
        "BEGIN ",
        "SHOW entries",
        "SET stamp=1000",
    ] {
        assert!(!template.could_match(sql));
    }
    assert!(template.could_match("/* prefix */ SELECT stamp FROM entries"));
}
