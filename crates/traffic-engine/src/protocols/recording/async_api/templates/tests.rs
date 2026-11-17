use super::*;
use crate::recorder::capture_body;
use serde_json::json;

fn templates(ends: serde_json::Value) -> Templates {
    Templates::new(&serde_json::from_value(json!({"end": ends})).unwrap())
}

#[test]
fn redis_templates_preserve_literal_bytes_and_one_nonoverlapping_wildcard() {
    let templates = templates(json!([
        {"redis":{"operation":"GET","key":"done.[0-9]+$"}},
        {"redis":{"operation":"GET","key":"ab*bc"}},
        {"redis":{"operation":"GET","key":"*"}}
    ]));
    assert!(templates.key_matches(0, b"done.[0-9]+$"));
    assert!(!templates.key_matches(0, b"done.42"));
    assert!(!templates.key_matches(0, b"DONE.[0-9]+$"));
    assert!(templates.key_matches(1, b"abbc"));
    assert!(templates.key_matches(1, b"ab\xff\0bc"));
    assert!(!templates.key_matches(1, b"abc"));
    assert!(!templates.key_matches(1, b"before-abbc"));
    assert!(!templates.key_matches(1, b"abbc-after"));
    assert!(templates.key_matches(2, b""));
    assert!(templates.key_matches(2, b"\xff\0"));
    assert!(!templates.key_matches(3, b"done"));
}

#[test]
fn sql_templates_preserve_typed_values_identifiers_and_statement_boundaries() {
    let templates = templates(json!([
        {"mysql":{"sql":"UPDATE jobs SET state='Done' WHERE id=?"}},
        {"mysql":{"sql":"UPDATE jobs SET state=? WHERE id=?"}},
        {"mysql":{"sql":"UPDATE jobs SET state='done' WHERE id=?"}},
        {"mysql":{"sql":"SELECT 1; DELETE FROM jobs"}}
    ]));
    let actual = actual_sql("update `jobs` set state = 'Done' where id = 42;", &[]).unwrap();
    assert!(templates.sql_matches(0, &actual));
    assert!(templates.sql_matches(1, &actual));
    assert!(!templates.sql_matches(2, &actual));
    let identifier = actual_sql("UPDATE Jobs SET state='Done' WHERE id=42", &[]).unwrap();
    assert!(!templates.sql_matches(0, &identifier));
    assert!(!templates.sql_matches(3, &actual));
    assert!(!templates.key_matches(0, b"jobs"));
    assert!(actual_sql("SELECT 1; DELETE FROM jobs", &[]).is_none());
    assert!(actual_sql("SELECT /*! executable */ 1", &[]).is_none());
}

#[test]
fn observed_prepared_sql_requires_exact_parameters_and_retains_binary_and_null_values() {
    let templates = templates(json!([
        {"mysql":{"sql":"UPDATE jobs SET payload=X'ff00', marker=NULL WHERE id=?"}},
        {"mysql":{"sql":"UPDATE jobs SET payload=?, marker=? WHERE id=?"}}
    ]));
    let parameters = vec![
        MysqlValue {
            kind: "binary".into(),
            value: None,
            raw: Some(capture_body(b"\xff\0", 1024)),
        },
        MysqlValue {
            kind: "null".into(),
            value: None,
            raw: None,
        },
        MysqlValue {
            kind: "integer".into(),
            value: Some(json!("18446744073709551615")),
            raw: None,
        },
    ];
    let statement = "UPDATE jobs SET payload=?, marker=? WHERE id=?";
    let actual = actual_sql(statement, &parameters).unwrap();
    assert!(templates.sql_matches(0, &actual));
    assert!(templates.sql_matches(1, &actual));
    assert!(actual.contains(&Token::Number("18446744073709551615".into())));
    assert!(actual_sql(statement, &parameters[..2]).is_none());
    assert!(actual_sql("SELECT 1", &parameters).is_none());
    let mut truncated = parameters.clone();
    truncated[0].raw.as_mut().unwrap().truncated = true;
    assert!(actual_sql(statement, &truncated).is_none());
}
