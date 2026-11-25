//! Project logical values into the compatibility JSON view and restore edited scalar types.
use anyhow::{Context, Result, ensure};
use serde::ser::Error as _;
use traffic_value::{Number, Value};

pub(crate) fn project(value: &Value) -> serde_json::Result<serde_json::Value> {
    use serde_json::{Number as JsonNumber, Value as Json};

    Ok(match value {
        Value::Null => Json::Null,
        Value::Bool(value) => Json::Bool(*value),
        Value::Number(Number::Signed(value)) => Json::Number((*value).into()),
        Value::Number(Number::Unsigned(value)) => Json::Number((*value).into()),
        Value::Number(Number::Float(value)) => Json::Number(
            JsonNumber::from_f64(*value)
                .ok_or_else(|| serde_json::Error::custom("nonfinite logical number"))?,
        ),
        Value::String(value) => Json::String(value.clone()),
        Value::Array(values) => {
            let mut projected = Vec::with_capacity(values.len());
            for value in values {
                projected.push(project(value)?);
            }
            Json::Array(projected)
        }
        Value::Object(values) => {
            let mut projected = serde_json::Map::new();
            for (key, value) in values {
                projected.insert(key.clone(), project(value)?);
            }
            Json::Object(projected)
        }
        Value::Bytes(values) => Json::Array(
            values
                .iter()
                .map(|&value| Json::Number(value.into()))
                .collect(),
        ),
    })
}

/// Restore scalar categories from a codec's original value after a projected edit.
pub fn restore(original: &Value, projected: &serde_json::Value) -> Result<Value> {
    Ok(match original {
        Value::Bytes(_) => Value::Bytes(
            serde_json::from_value(projected.clone())
                .context("byte scalar projection requires byte values")?,
        ),
        Value::Number(Number::Signed(_)) => Value::Number(Number::Signed(
            projected
                .as_i64()
                .context("signed scalar projection changed type")?,
        )),
        Value::Number(Number::Unsigned(_)) => Value::Number(Number::Unsigned(
            projected
                .as_u64()
                .context("unsigned scalar projection changed type")?,
        )),
        Value::Number(Number::Float(_)) => {
            ensure!(
                projected.is_f64(),
                "floating scalar projection changed type"
            );
            Value::Number(Number::Float(
                projected.as_f64().context("invalid floating scalar")?,
            ))
        }
        Value::Object(fields) => {
            let projected = projected
                .as_object()
                .context("object projection changed type")?;
            ensure!(
                fields.keys().eq(projected.keys()),
                "delivery changes field presence"
            );
            Value::Object(
                fields
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), restore(value, &projected[key])?)))
                    .collect::<Result<_>>()?,
            )
        }
        Value::Array(values) => {
            let projected = projected
                .as_array()
                .context("array projection changed type")?;
            ensure!(
                values.len() == projected.len(),
                "delivery changes array cardinality"
            );
            Value::Array(
                values
                    .iter()
                    .zip(projected)
                    .map(|(value, projection)| restore(value, projection))
                    .collect::<Result<_>>()?,
            )
        }
        _ => serde_json::from_value(projected.clone())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_preserves_serde_scalar_representations() {
        let value = Value::Object(
            [(
                "values".into(),
                Value::Array(vec![
                    Value::Null,
                    Value::Bool(false),
                    Value::Number(Number::Signed(i64::MIN)),
                    Value::Number(Number::Signed(1)),
                    Value::Number(Number::Unsigned(u64::MAX)),
                    Value::Number(Number::Float(-0.0)),
                    Value::String("x\"~".into()),
                    Value::Bytes(vec![0, 255]),
                ]),
            )]
            .into(),
        );
        let projected = project(&value).unwrap();
        assert_eq!(projected, serde_json::to_value(&value).unwrap());
        assert!(projected["values"][5].as_f64().unwrap().is_sign_negative());
        assert!(project(&Value::Number(Number::Float(f64::INFINITY))).is_err());
    }
}
