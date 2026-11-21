//! Typed scalar binding for authored selectors and native prepared statements.
use crate::sql::{Token, number, tokens};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MysqlValue {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<ValueCapture>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ValueCapture {
    pub encoding: String,
    pub data: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

pub fn materialize(sql: &str, params: &[MysqlValue]) -> Option<Vec<Token>> {
    materialize_tokens(tokens(sql)?, params)
}

pub fn materialize_tokens(mut tokens: Vec<Token>, params: &[MysqlValue]) -> Option<Vec<Token>> {
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

pub fn bound_value(value: &MysqlValue) -> Option<Token> {
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

pub fn mysql_value_bytes(value: &MysqlValue) -> Result<Vec<u8>> {
    if let Some(raw) = &value.raw {
        return match raw.encoding.as_str() {
            "base64" => STANDARD
                .decode(&raw.data)
                .context("failed to decode recorded MySQL raw base64 value"),
            "utf8" => Ok(raw.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported recorded raw value encoding {other}")),
        };
    }
    let Some(value) = &value.value else {
        return Ok(Vec::new());
    };
    Ok(match value {
        Value::String(value) => value.as_bytes().to_vec(),
        Value::Number(value) => value.to_string().into_bytes(),
        Value::Bool(value) => {
            if *value {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            }
        }
        other => {
            serde_json::to_vec(other).context("failed to serialize recorded MySQL JSON value")?
        }
    })
}
