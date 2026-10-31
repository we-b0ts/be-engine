//! Narrow recognition of driver-owned session initialization, never business SQL.
use crate::mysql::sql::{Token, tokens};

/// Retained driver observations keep their native builtin owner. They neither
/// create finite SQL obligations nor invalidate later proven transactions.
pub(in crate::replay) fn is_nonsemantic_session_setup(
    record: &super::RecordedMysqlExchange,
) -> bool {
    record
        .capture
        .as_ref()
        .is_some_and(|capture| !capture.semantic_required)
        && !record.lifecycle_cleanup
        && record
            .sql
            .as_deref()
            .is_some_and(is_mysql_session_setup_sql)
        && super::optional_session::successful_control(record)
        && record.response.server_status.is_some_and(|after| {
            record
                .server_status_before
                .map_or(record.query_sequence == Some(1), |before| {
                    before & 0x200b == after & 0x200b
                })
        })
}

pub(super) fn is_mysql_session_setup_sql(sql: &str) -> bool {
    let Some(tokens) = tokens(sql) else {
        return false;
    };
    let Some((first, rest)) = tokens.split_first() else {
        return false;
    };
    if !first.is("set") || rest.is_empty() {
        return false;
    }
    let mut depth = 0usize;
    let mut start = 0;
    for (i, token) in rest.iter().enumerate() {
        if token.is("(") {
            depth += 1;
        }
        if token.is(")") {
            let Some(next) = depth.checked_sub(1) else {
                return false;
            };
            depth = next;
        }
        if token.is(",") && depth == 0 {
            if !assignment(&rest[start..i]) {
                return false;
            }
            start = i + 1;
        }
    }
    depth == 0 && assignment(&rest[start..])
}

fn assignment(mut tokens: &[Token]) -> bool {
    if tokens
        .first()
        .is_some_and(|t| t.is("session") || t.is("local"))
    {
        tokens = &tokens[1..];
    }
    if tokens.first().is_some_and(|t| t.is("names")) {
        return match &tokens[1..] {
            [charset] => name(charset),
            [charset, collate, collation] => {
                name(charset) && collate.is("collate") && name(collation)
            }
            _ => false,
        };
    }
    if tokens.first().is_some_and(|t| t.is("character")) {
        return matches!(&tokens[1..], [set, charset] if set.is("set") && name(charset));
    }
    if tokens.first().is_some_and(|t| t.is("@@")) {
        tokens = &tokens[1..];
        if tokens
            .first()
            .is_some_and(|t| t.is("session") || t.is("local"))
        {
            if !tokens.get(1).is_some_and(|t| t.is(".")) {
                return false;
            }
            tokens = &tokens[2..];
        }
    }
    let [variable, equals, value @ ..] = tokens else {
        return false;
    };
    if !equals.is("=") {
        return false;
    }
    if variable.is("sql_mode") {
        return sql_mode(value);
    }
    if variable.is("time_zone") {
        return matches!(value, [Token::Bytes(value)] if !value.is_empty());
    }
    [
        "character_set_client",
        "character_set_connection",
        "character_set_results",
        "collation_connection",
    ]
    .iter()
    .any(|v| variable.is(v))
        && matches!(value, [value] if name(value) || *value == Token::Null)
}

fn name(token: &Token) -> bool {
    let bytes = match token {
        Token::Word(value) => value.as_bytes(),
        Token::Bytes(value) => value,
        _ => return false,
    };
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn sql_mode(tokens: &[Token]) -> bool {
    if let [Token::Bytes(value)] = tokens {
        return supported_modes(value);
    }
    // SQLx appends flags to the current mode. This exact expression reads no
    // tables and has no side effects beyond the selected session variable.
    let Some(inner) = strip(tokens, "(", ")") else {
        return false;
    };
    let Some((select, rest)) = inner.split_first() else {
        return false;
    };
    if !select.is("select") {
        return false;
    }
    let Some((concat, rest)) = rest.split_first() else {
        return false;
    };
    if !concat.is("concat") {
        return false;
    }
    let Some(args) = strip(rest, "(", ")") else {
        return false;
    };
    matches!(args, [at, mode, comma, Token::Bytes(value)]
        if at.is("@@") && mode.is("sql_mode") && comma.is(",") && supported_modes(value))
}

fn strip<'a>(tokens: &'a [Token], first: &str, last: &str) -> Option<&'a [Token]> {
    (tokens.len() >= 2 && tokens[0].is(first) && tokens[tokens.len() - 1].is(last))
        .then(|| &tokens[1..tokens.len() - 1])
}

fn supported_modes(value: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    value.split(',').all(|mode| {
        matches!(
            mode.trim().to_ascii_uppercase().as_str(),
            "" | "PIPES_AS_CONCAT"
                | "NO_ENGINE_SUBSTITUTION"
                | "STRICT_TRANS_TABLES"
                | "STRICT_ALL_TABLES"
                | "ONLY_FULL_GROUP_BY"
                | "NO_ZERO_IN_DATE"
                | "NO_ZERO_DATE"
                | "ERROR_FOR_DIVISION_BY_ZERO"
                | "NO_AUTO_CREATE_USER"
                | "NO_AUTO_VALUE_ON_ZERO"
                | "IGNORE_SPACE"
                | "NO_UNSIGNED_SUBTRACTION"
                | "PAD_CHAR_TO_FULL_LENGTH"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_setup_observations_require_native_success_and_no_transaction_effect() {
        let mut capture = crate::dependency::observation::fixture_capture("case");
        capture.semantic_required = false;
        let value = serde_json::json!({
            "capture":capture, "command":"COM_QUERY", "sql":"SET NAMES utf8mb4",
            "query_sequence":1, "server_status_before":null,
            "response":{"status":"ok", "server_status":2, "affected_rows":0,
                        "last_insert_id":0}
        });
        let parse =
            |value| serde_json::from_value::<super::super::RecordedMysqlExchange>(value).unwrap();
        assert!(is_nonsemantic_session_setup(&parse(value.clone())));
        for (pointer, replacement) in [
            ("/capture/semantic_required", serde_json::json!(true)),
            ("/capture", serde_json::Value::Null),
            ("/sql", serde_json::json!("SET AUTOCOMMIT = 0")),
            ("/sql", serde_json::json!("SET @business = 1")),
            ("/response/status", serde_json::json!("error")),
            ("/response/affected_rows", serde_json::json!(1)),
            ("/server_status_before", serde_json::json!(1)),
            ("/query_sequence", serde_json::json!(2)),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(!is_nonsemantic_session_setup(&parse(changed)), "{pointer}");
        }
    }

    #[test]
    fn accepts_default_sqlx_and_pymysql_initialization() {
        for sql in [
            "SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION')),NAMES utf8mb4 COLLATE utf8mb4_unicode_ci;",
            "SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION')),time_zone='+08:00',NAMES utf8mb4 COLLATE utf8mb4_unicode_ci;",
            "SET NAMES 'utf8mb4' COLLATE 'utf8mb4_unicode_ci'",
            "SET @@session.time_zone = '+08:00'",
            "SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'",
            "SET character_set_results = NULL",
        ] {
            assert!(is_mysql_session_setup_sql(sql), "{sql}");
        }
    }

    #[test]
    fn rejects_business_assignments_multiple_statements_and_unsupported_modes() {
        for sql in [
            "SET sql_mode='',autocommit=0",
            "SET NAMES utf8mb4; DELETE FROM users",
            "SET sql_mode=(SELECT password FROM users LIMIT 1)",
            "SET time_zone=(SELECT SLEEP(10))",
            "SET GLOBAL sql_mode=''",
            "SET sql_mode='NO_BACKSLASH_ESCAPES'",
            "SET sql_mode='ANSI_QUOTES'",
            "SET NAMES utf8mb4, sql_mode='ANSI'",
            "SET sql_mode='unterminated",
            "SET character_set_results=NULL,",
            "SET sql_mode='',@business=1",
        ] {
            assert!(!is_mysql_session_setup_sql(sql), "{sql}");
        }
    }
}
