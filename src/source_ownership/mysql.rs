//! Exact SQL scalar bindings and successful native MySQL facts.
use super::projection::complete;
use crate::mysql::sql::{self, Token};
use crate::policy::AsyncOwnershipRequest;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MARKER: &str = "__async_ownership_table__";
pub(super) mod prepared;

pub(super) fn successful(event: &Value) -> bool {
    complete(event)
        && event["outcome"] == "response"
        && event["response"]["error_code"].is_null()
        && matches!(
            event["response"]["status"].as_str(),
            Some("ok" | "resultset")
        )
        && event["parse_warnings"].as_array().is_none_or(Vec::is_empty)
}

pub(super) fn tokens(event: &Value) -> Option<Vec<Token>> {
    if !matches!(
        event["command"].as_str(),
        Some("COM_QUERY" | "COM_STMT_EXECUTE")
    ) {
        return None;
    }
    let mut tokens = sql::bounds::statement(event["sql"].as_str()?)?;
    let empty = Vec::new();
    let mut params = event["params"].as_array().unwrap_or(&empty).iter();
    for token in &mut tokens {
        if *token == Token::Placeholder {
            *token = parameter(params.next()?)?;
        }
    }
    params.next().is_none().then_some(tokens)
}

fn parameter(value: &Value) -> Option<Token> {
    match value["kind"].as_str()? {
        "null" => Some(Token::Null),
        "integer" | "float" | "decimal" => sql::number(
            value["value"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value["value"].to_string())
                .as_str(),
        )
        .map(Token::Number),
        "boolean" | "bool" => value["value"]
            .as_bool()
            .map(|value| Token::Number(u8::from(value).to_string())),
        "string" | "bytes" | "binary" | "date" | "datetime" | "time" | "json" => {
            let bytes = if value["raw"].is_object() {
                decode(&value["raw"])?
            } else {
                value["value"].as_str()?.as_bytes().to_vec()
            };
            Some(Token::Bytes(bytes))
        }
        _ => None,
    }
}

pub(super) fn decode(value: &Value) -> Option<Vec<u8>> {
    if value["truncated"] == true {
        return None;
    }
    let data = value["data"].as_str()?;
    if data.len() > crate::value_limits::MAX_VALUE_BYTES {
        return None;
    }
    match value["encoding"].as_str()? {
        "utf8" => Some(data.as_bytes().to_vec()),
        "base64" => STANDARD.decode(data).ok(),
        _ => None,
    }
}

pub(super) fn positive(token: &Token) -> Option<u64> {
    if let Token::Number(value) = token {
        sql::positive_integer(value)?.parse().ok()
    } else {
        None
    }
}

pub(super) fn row_tokens(tokens: &[Token]) -> Option<(String, BTreeMap<String, Token>)> {
    let mut values = tokens.iter();
    if !values.next()?.is("insert") || !values.next()?.is("into") {
        return None;
    }
    let name = |token: &Token| match token {
        Token::Word(name) | Token::Identifier(name) => Some(name.clone()),
        _ => None,
    };
    let table = name(values.next()?)?;
    if !values.next()?.is("(") {
        return None;
    }
    let mut columns = Vec::new();
    loop {
        columns.push(name(values.next()?)?);
        let separator = values.next()?;
        if separator.is(")") {
            break;
        }
        if !separator.is(",") || columns.len() > 128 {
            return None;
        }
    }
    if !values.next()?.is("values") || !values.next()?.is("(") {
        return None;
    }
    let mut row = Vec::new();
    loop {
        let token = values.next()?;
        row.push(if token.is_value() {
            Some(token.clone())
        } else if (token.is("now") || token.is("current_timestamp"))
            && values.next()?.is("(")
            && values.next()?.is(")")
        {
            None
        } else {
            return None;
        });
        let separator = values.next()?;
        if separator.is(")") {
            break;
        }
        if !separator.is(",") || row.len() > 128 {
            return None;
        }
    }
    if values.next().is_some() || row.len() != columns.len() {
        return None;
    }
    if columns.iter().collect::<BTreeSet<_>>().len() != columns.len() {
        return None;
    }
    let mut result = BTreeMap::new();
    for (column, value) in columns.into_iter().zip(row) {
        if let Some(value) = value
            && result.insert(column, value).is_some()
        {
            return None;
        }
    }
    Some((table, result))
}

pub(super) fn selector(
    request: &AsyncOwnershipRequest,
    event: &Value,
) -> Option<(BTreeMap<String, u64>, bool)> {
    if !successful(event) {
        return None;
    }
    let pattern = prepared::Pattern::new(request)?;
    let actual = tokens(event)?;
    pattern.matches(event, &actual)
}

pub(super) fn boundary(event: &Value) -> Option<&'static str> {
    let tokens = tokens(event)?;
    boundary_tokens(&tokens)
}

pub(super) fn boundary_tokens(tokens: &[Token]) -> Option<&'static str> {
    match tokens {
        [token] if token.is("commit") => Some("commit"),
        [token] if token.is("rollback") => Some("rollback"),
        [token] if token.is("begin") => Some("begin"),
        [first, second] if first.is("start") && second.is("transaction") => Some("begin"),
        _ => None,
    }
}
