//! Correlate text and prepared calls without interpolating or executing SQL.
use super::*;
use crate::mysql::sql::{Token, number, tokens};

pub(super) mod cache;
mod predicate;
mod query_in;

pub(in crate::replay) fn materialize(
    sql: &str,
    params: &[RecordedMysqlValue],
) -> Option<Vec<Token>> {
    let mut tokens = tokens(sql)?;
    let mut values = params.iter();
    for token in &mut tokens {
        if *token == Token::Placeholder {
            *token = bound_value(values.next()?)?;
        }
    }
    if values.next().is_some() {
        return None;
    }
    Some(tokens)
}

pub(super) fn cross_protocol_matches(
    recorded: &RecordedMysqlExchange,
    command: &str,
    sql: &str,
    params: Option<&[RecordedMysqlValue]>,
) -> bool {
    let Some(recorded_sql) = &recorded.sql else {
        return false;
    };
    let forms = match (recorded.command.as_str(), command) {
        ("COM_QUERY", "COM_STMT_EXECUTE") => {
            params.and_then(|params| Some((tokens(recorded_sql)?, materialize(sql, params)?)))
        }
        ("COM_STMT_EXECUTE", "COM_QUERY") => recorded
            .params
            .as_deref()
            .and_then(|params| Some((materialize(recorded_sql, params)?, tokens(sql)?))),
        _ => None,
    };
    forms.is_some_and(|(recorded, actual)| recorded == actual)
}

/// Prepared statements can put equal scalar values in different placeholder
/// positions. This is exact token equality after binding, including subqueries;
/// it authorizes no predicate, scalar-category or value changes.
pub(super) fn prepared_values_match(
    recorded: &RecordedMysqlExchange,
    command: &str,
    sql: &str,
    params: Option<&[RecordedMysqlValue]>,
) -> bool {
    if recorded.command != "COM_STMT_EXECUTE" || command != "COM_STMT_EXECUTE" {
        return false;
    }
    let forms = recorded.sql.as_deref().and_then(|recorded_sql| {
        Some((
            materialize(recorded_sql, recorded.params.as_deref().unwrap_or_default())?,
            materialize(sql, params.unwrap_or_default())?,
        ))
    });
    forms.is_some_and(|(recorded, actual)| recorded == actual)
}

/// Only actual parameter positions are wildcards. Constants, table names,
/// predicates, projections and LIMIT clauses must still match.
pub(super) fn metadata_matches(template: &str, recorded: &str) -> bool {
    let (Some(template), Some(recorded)) = (tokens(template), tokens(recorded)) else {
        return false;
    };
    template.len() == recorded.len()
        && template
            .iter()
            .zip(&recorded)
            .all(|(t, r)| t == r || (*t == Token::Placeholder && r.is_value()))
}

pub(super) fn prepared_metadata_matches(recorded: &RecordedMysqlExchange, sql: &str) -> bool {
    let forms = recorded.sql.as_deref().and_then(|source| {
        Some((
            materialize(source, recorded.params.as_deref().unwrap_or_default())?,
            tokens(sql)?,
        ))
    });
    forms.is_some_and(|(source, actual)| {
        source.len() == actual.len()
            && actual.iter().zip(&source).all(|(actual, source)| {
                actual == source || (*actual == Token::Placeholder && source.is_value())
            })
    })
}

fn bound_value(value: &RecordedMysqlValue) -> Option<Token> {
    if value.kind == "null" {
        return Some(Token::Null);
    }
    match value.kind.as_str() {
        "integer" | "float" | "decimal" => {
            let text = match value.value.as_ref()? {
                Value::Number(v) => v.to_string(),
                Value::String(v) => v.to_owned(),
                _ => return None,
            };
            Some(Token::Number(number(&text)?))
        }
        "boolean" | "bool" => value
            .value
            .as_ref()?
            .as_bool()
            .map(|v| Token::Number(u8::from(v).to_string())),
        "string" | "bytes" | "binary" | "date" | "datetime" | "time" | "json" => {
            Some(Token::Bytes(mysql_value_bytes(value).ok()?))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preserves_values_types_and_placeholder_positions() {
        let p = |kind, value| mysql_json(kind, value);
        let params = vec![
            p("string", json!("AbC  ? O'Brien\\\n")),
            mysql_null(),
            p("integer", json!(u64::MAX)),
            p("decimal", json!("12.3400")),
            mysql_bytes_or_utf8(&[0, 255], true),
        ];
        let actual = materialize(
            "SELECT '?' FROM tasks_0509 WHERE a=? AND b <=> ? AND c=? AND d=? AND e=? /* ? */",
            &params,
        );
        assert_eq!(
            actual,
            tokens(
                "SELECT '?' FROM tasks_0509 WHERE a='AbC  ? O''Brien\\\\\\n' AND b <=> NULL AND c=18446744073709551615 AND d=12.34 AND e=X'00ff'"
            )
        );
        assert!(actual.is_some());
        assert_ne!(
            materialize("SELECT ?", &[p("string", json!("AbC"))]),
            tokens("SELECT 'abc'")
        );
        assert_ne!(
            materialize("SELECT ?", &[p("string", json!("1"))]),
            tokens("SELECT 1")
        );
        assert!(materialize("SELECT '?'", &[p("integer", json!(1))]).is_none());
        assert!(materialize("SELECT ?", &[]).is_none());
    }

    #[test]
    fn metadata_keeps_all_non_parameter_sql_exact() {
        assert!(metadata_matches(
            "SELECT id FROM tasks_0509 WHERE uid=? LIMIT 1",
            "select id from `tasks_0509` where uid=42 limit 1"
        ));
        assert!(!metadata_matches(
            "SELECT id FROM tasks_0509 WHERE uid=? LIMIT 1",
            "select id from tasks_0509 where uid=42 limit 2"
        ));
        assert!(!metadata_matches(
            "SELECT id FROM tasks_0509 WHERE uid=?",
            "select id from tasks_0510 where uid=42"
        ));
        assert!(!metadata_matches(
            "SELECT id FROM users WHERE uid=?",
            "select id, name from users where uid=42"
        ));
    }
    #[test]
    fn matches_both_driver_directions_but_rejects_changed_values() {
        let recorded: RecordedMysqlExchange = serde_json::from_value(json!({
            "command":"COM_STMT_EXECUTE", "sql":"SELECT id FROM users WHERE name=?",
            "params":[{"kind":"string","value":"AbC"}], "response":{"status":"resultset"}
        }))
        .unwrap();
        assert!(cross_protocol_matches(
            &recorded,
            "COM_QUERY",
            "select id from users where name='AbC'",
            None
        ));
        assert!(!cross_protocol_matches(
            &recorded,
            "COM_QUERY",
            "select id from users where name='abc'",
            None
        ));
        let recorded: RecordedMysqlExchange = serde_json::from_value(json!({
            "command":"COM_QUERY", "sql":"SELECT id FROM users WHERE name='AbC'",
            "response":{"status":"resultset"}
        }))
        .unwrap();
        assert!(cross_protocol_matches(
            &recorded,
            "COM_STMT_EXECUTE",
            "SELECT id FROM users WHERE name=?",
            Some(&[mysql_json("string", json!("AbC"))])
        ));
        assert!(!cross_protocol_matches(
            &recorded,
            "COM_STMT_EXECUTE",
            "SELECT id FROM users WHERE name=?",
            Some(&[mysql_json("string", json!("abc"))])
        ));
    }
}
