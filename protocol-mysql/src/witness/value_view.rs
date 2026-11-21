//! Read-only scalar views reuse Replay's bounded SQL decoding and field origins.
use super::RequestEnvelope;
use crate::sql::{Token, bounds, field_bindings};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use serde_json::json;
use traffic_protocol::evidence::MessageSide;

/// Called only after the evidence owner authenticates the complete witness.
/// Token positions describe each statement independently, not a successful pair.
pub fn sql_value(
    raw: &[u8],
    surface: MessageSide,
    database: Option<&str>,
    token_index: usize,
) -> Result<Option<Value>> {
    ensure!(raw.len() <= 4 * 1024 * 1024, "SQL witness exceeds 4 MiB");
    let request = match surface {
        MessageSide::Request => serde_json::from_slice::<RequestEnvelope>(raw)?,
        MessageSide::Response => serde_json::from_value::<RequestEnvelope>(
            serde_json::from_slice::<Value>(raw)?["request"].clone(),
        )?,
    };
    let sql = request.sql.as_deref().context("SQL statement is absent")?;
    let tokens = bounds::statement(sql).context("SQL value view requires one bounded statement")?;
    let tokens =
        crate::sql_match::materialize_tokens(tokens, request.params.as_deref().unwrap_or_default())
            .context("SQL value view requires complete native parameter bindings")?;
    let Some(token) = tokens.get(token_index) else {
        return Ok(None);
    };
    let mut value = match token {
        // Keep exact normalized SQL decimal text, including values JSON cannot
        // represent exactly. The enclosing native witness remains unchanged.
        Token::Number(text) => json!({"kind":"number","value":text}),
        Token::Null => json!({"kind":"null","value":null}),
        Token::Bytes(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => json!({"kind":"string","value":text}),
            Err(_) => json!({"kind":"bytes","base64":STANDARD.encode(bytes)}),
        },
        _ => return Ok(None),
    };
    value["token_index"] = json!(token_index);
    if let Some(analysis) = field_bindings::analyze(&tokens, database)
        && let Some(field) = analysis.at_token(token_index)
    {
        value["field"] =
            json!({"database":field.database,"table":field.table,"column":field.column});
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(sql: &str, params: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"command":"COM_STMT_EXECUTE","request_started_at":null,"sql":sql,"params":params})).unwrap()
    }

    #[test]
    fn literal_and_bound_values_preserve_native_types_and_exact_decimal_text() {
        let sql = "INSERT INTO tasks(id,payload,nullable,bytes) VALUES(?, ?, ?, ?)";
        let raw = request(
            sql,
            json!([
                {"kind":"decimal","value":"12345678901234567890.123456789"},
                {"kind":"string","value":"{\"name\":\"O'Brien\",\"nullable\":null}"},
                {"kind":"null"},
                {"kind":"binary","raw":{"encoding":"base64","data":"AP8=","truncated":false}}
            ]),
        );
        let tokens = bounds::statement(sql).unwrap();
        let positions = tokens
            .iter()
            .enumerate()
            .filter_map(|(index, token)| (*token == Token::Placeholder).then_some(index))
            .collect::<Vec<_>>();
        let select = |index| {
            sql_value(&raw, MessageSide::Request, Some("app"), index)
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            select(positions[0])["value"],
            "12345678901234567890123456789e-9"
        );
        assert_eq!(
            select(positions[1])["value"],
            r#"{"name":"O'Brien","nullable":null}"#
        );
        assert_eq!(
            select(positions[1])["field"],
            json!({"database":"app","table":"tasks","column":"payload"})
        );
        assert_eq!(select(positions[2])["kind"], "null");
        assert_eq!(select(positions[3])["base64"], "AP8=");
        assert!(
            sql_value(&raw, MessageSide::Request, None, 0)
                .unwrap()
                .is_none()
        );
        assert!(
            sql_value(&raw, MessageSide::Request, None, usize::MAX)
                .unwrap()
                .is_none()
        );
        let text = request(
            "INSERT INTO tasks(payload) VALUES('{\"name\":\"O''Brien\"}')",
            Value::Null,
        );
        let position = bounds::statement("INSERT INTO tasks(payload) VALUES(?)")
            .unwrap()
            .iter()
            .position(|token| *token == Token::Placeholder)
            .unwrap();
        assert_eq!(
            sql_value(&text, MessageSide::Request, None, position)
                .unwrap()
                .unwrap()["value"],
            r#"{"name":"O'Brien"}"#
        );
    }

    #[test]
    fn invalid_or_unbound_statements_do_not_invent_values() {
        for (sql, params) in [
            ("SELECT ?", Value::Null),
            ("SELECT 1", json!([{"kind":"integer","value":2}])),
            ("SELECT 1; SELECT 2", Value::Null),
        ] {
            assert!(sql_value(&request(sql, params), MessageSide::Request, None, 1).is_err());
        }
        assert!(
            sql_value(
                &vec![b' '; 4 * 1024 * 1024 + 1],
                MessageSide::Request,
                None,
                1
            )
            .is_err()
        );
    }
}
