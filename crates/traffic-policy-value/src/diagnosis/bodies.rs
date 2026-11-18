//! Original-body diagnosis uses the same installed codec recognition contract as value execution.
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::sync::Arc;
use traffic_contract::compare::diagnosis as logical;
use traffic_value::codec::{CodecRegistry, ValueDocument};
type Documents = (String, Arc<dyn ValueDocument>, Arc<dyn ValueDocument>);

fn decode(codecs: &CodecRegistry, source: &[u8], target: &[u8]) -> Result<Option<Documents>> {
    let Some(codec) = codecs.try_recognize(source, &traffic_value::Value::Null)? else {
        return Ok(None);
    };
    let source = codec
        .decode(source)
        .context("recognized Source payload is invalid")?;
    let target = codec
        .decode(target)
        .context("Target violates the recognized Source codec")?;
    Ok(Some((codec.descriptor().id.into(), source, target)))
}

pub fn at_pointer(codecs: &CodecRegistry, source: &[u8], target: &[u8], pointer: &str) -> Value {
    match decode(codecs, source, target) {
        Ok(Some((codec, source, target))) => {
            let mut value = logical::at_pointer(source.value(), target.value(), pointer);
            value["codec"] = codec.into();
            value
        }
        Ok(None) => json!({"pointer":pointer,"presence":"unavailable",
            "reason":"no installed codec recognizes the Source body"}),
        Err(error) => {
            json!({"pointer":pointer,"presence":"unavailable","reason":error.to_string()})
        }
    }
}

pub fn differences(codecs: &CodecRegistry, source: &[u8], target: &[u8], offset: usize) -> Value {
    match decode(codecs, source, target) {
        Ok(Some((codec, source, target))) => {
            logical::differences(source.value(), target.value(), &codec, offset)
        }
        Ok(None) => logical::byte_differences(source, target, "bytes", offset),
        Err(error) => json!({"offset":offset,"analysis_complete":false,"presence":"unavailable",
            "reason":error.to_string()}),
    }
}

#[cfg(test)]
mod tests;
