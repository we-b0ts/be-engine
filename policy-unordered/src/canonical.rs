//! Typed keys preserve logical equality without selecting a serialization format.
use anyhow::{Result, ensure};
use traffic_value::{Number, Value};

pub(super) fn key(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    append(value, &mut output, 0)?;
    Ok(output)
}

fn bytes(value: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn append(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<()> {
    ensure!(
        depth <= 128,
        "logical value exceeds the collection nesting budget"
    );
    match value {
        Value::Null => output.push(0),
        Value::Bool(value) => output.extend_from_slice(&[1, u8::from(*value)]),
        Value::Number(Number::Signed(value)) => {
            output.push(2);
            output.extend_from_slice(&value.to_le_bytes());
        }
        Value::Number(Number::Unsigned(value)) => {
            output.push(3);
            output.extend_from_slice(&value.to_le_bytes());
        }
        Value::Number(Number::Float(value)) => {
            ensure!(value.is_finite(), "nonfinite collection number");
            output.push(4);
            let value = if *value == 0.0 { 0.0 } else { *value };
            output.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        Value::String(value) => {
            output.push(5);
            bytes(value.as_bytes(), output);
        }
        Value::Bytes(value) => {
            output.push(6);
            bytes(value, output);
        }
        Value::Array(values) => {
            output.push(7);
            output.extend_from_slice(&(values.len() as u64).to_le_bytes());
            for value in values {
                append(value, output, depth + 1)?;
            }
        }
        Value::Object(fields) => {
            output.push(8);
            output.extend_from_slice(&(fields.len() as u64).to_le_bytes());
            for (key, value) in fields {
                bytes(key.as_bytes(), output);
                append(value, output, depth + 1)?;
            }
        }
    }
    ensure!(
        output.len() <= traffic_value::MAX_VALUE_BYTES,
        "collection key exceeds 64 MiB"
    );
    Ok(())
}
