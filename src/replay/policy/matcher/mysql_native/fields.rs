//! Physical field selection shared by live SQL matching and immutable evidence.
use super::*;

pub(in crate::replay) fn scalar(token: &Token) -> Result<Value> {
    match token {
        Token::Bytes(bytes) => Ok(Value::String(
            String::from_utf8(bytes.clone())
                .context("SQL scalar must retain UTF-8 string identity")?,
        )),
        Token::Number(number) => {
            crate::json_value::parse(number.as_bytes()).context("invalid SQL native number")
        }
        Token::Null => Ok(Value::Null),
        _ => anyhow::bail!("selected SQL scalar is not a complete native value"),
    }
}
