//! Preserve codec scalar categories across the legacy JSON-shaped value interface.
use anyhow::{Context, Result, ensure};
use traffic_value::{Number, Value};

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
