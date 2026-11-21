//! Correlate text and prepared calls without interpolating or executing SQL.
use crate::model::MysqlValue as RecordedMysqlValue;
use crate::sql::{Token, tokens_shared};
use traffic_protocol_mysql_sql::binding::bound_value;
pub use traffic_protocol_mysql_sql::binding::{materialize, materialize_tokens};

pub mod cache;
mod predicate;
mod query_in;

pub trait SqlRequest {
    fn command(&self) -> &str;
    fn sql(&self) -> Option<&str>;
    fn params(&self) -> Option<&[RecordedMysqlValue]>;
}

pub const MAX_SQL_TOKENS: usize = crate::sql::bounds::MAX_TOKENS;

pub fn cross_protocol_matches(
    recorded: &impl SqlRequest,
    command: &str,
    sql: &str,
    params: Option<&[RecordedMysqlValue]>,
) -> bool {
    let Some(recorded_sql) = recorded.sql() else {
        return false;
    };
    let (text, template, values) = match (recorded.command(), command) {
        ("COM_QUERY", "COM_STMT_EXECUTE") => (recorded_sql, sql, params),
        ("COM_STMT_EXECUTE", "COM_QUERY") => (sql, recorded_sql, recorded.params()),
        _ => return false,
    };
    let (Some(values), Some(text), Some(template)) =
        (values, tokens_shared(text), tokens_shared(template))
    else {
        return false;
    };
    let mut values = values.iter();
    text.len() == template.len()
        && text.iter().zip(template.iter()).all(|(text, template)| {
            if *template == Token::Placeholder {
                values.next().and_then(bound_value).as_ref() == Some(text)
            } else {
                text == template
            }
        })
        && values.next().is_none()
}

/// Prepared statements can put equal scalar values in different placeholder
/// positions. This is exact token equality after binding, including subqueries;
/// it authorizes no predicate, scalar-category or value changes.
pub fn prepared_values_match(
    recorded: &impl SqlRequest,
    command: &str,
    sql: &str,
    params: Option<&[RecordedMysqlValue]>,
) -> bool {
    if recorded.command() != "COM_STMT_EXECUTE" || command != "COM_STMT_EXECUTE" {
        return false;
    }
    let forms = recorded.sql().and_then(|recorded_sql| {
        Some((
            materialize(recorded_sql, recorded.params().unwrap_or_default())?,
            materialize(sql, params.unwrap_or_default())?,
        ))
    });
    forms.is_some_and(|(recorded, actual)| recorded == actual)
}

/// Only actual parameter positions are wildcards. Constants, table names,
/// predicates, projections and LIMIT clauses must still match.
pub fn metadata_matches(template: &str, recorded: &str) -> bool {
    let (Some(template), Some(recorded)) = (tokens_shared(template), tokens_shared(recorded))
    else {
        return false;
    };
    template.len() == recorded.len()
        && template
            .iter()
            .zip(recorded.iter())
            .all(|(t, r)| t == r || (*t == Token::Placeholder && r.is_value()))
}

pub fn prepared_metadata_matches(recorded: &impl SqlRequest, sql: &str) -> bool {
    let forms = recorded.sql().and_then(|source| {
        Some((
            materialize(source, recorded.params().unwrap_or_default())?,
            tokens_shared(sql)?,
        ))
    });
    forms.is_some_and(|(source, actual)| {
        source.len() == actual.len()
            && actual.iter().zip(&source).all(|(actual, source)| {
                actual == source || (*actual == Token::Placeholder && source.is_value())
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::tokens;
    use crate::values::{mysql_bytes_or_utf8, mysql_json, mysql_null};
    use serde_json::json;
    #[derive(serde::Deserialize)]
    struct RecordedMysqlExchange {
        command: String,
        sql: Option<String>,
        params: Option<Vec<RecordedMysqlValue>>,
    }
    impl SqlRequest for RecordedMysqlExchange {
        fn command(&self) -> &str {
            &self.command
        }
        fn sql(&self) -> Option<&str> {
            self.sql.as_deref()
        }
        fn params(&self) -> Option<&[RecordedMysqlValue]> {
            self.params.as_deref()
        }
    }

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
