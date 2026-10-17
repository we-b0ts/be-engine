//! Bounded payload decoding with typed values and lossless protocol remainders.
mod protobuf;

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::policy::Codec;

pub(crate) struct CodecView;

#[derive(Debug, Clone)]
pub(crate) struct DecodedValue {
    pub(crate) logical: Value,
    original: Vec<u8>,
    protobuf: Option<protobuf::Document>,
}

impl CodecView {
    pub(crate) fn decode(codec: &Codec, bytes: &[u8]) -> Result<DecodedValue> {
        ensure!(
            bytes.len() <= 1024 * 1024,
            "payload exceeds the 1 MiB codec limit"
        );
        let (logical, protobuf) = match codec {
            Codec::Json => (
                crate::json_value::parse(bytes)
                    .context("payload requires complete JSON without duplicate members")?,
                None,
            ),
            Codec::Protobuf(codec) => {
                let document = protobuf::Document::decode(codec, bytes)?;
                (document.logical.clone(), Some(document))
            }
        };
        Ok(DecodedValue {
            logical,
            original: bytes.to_vec(),
            protobuf,
        })
    }
}

impl DecodedValue {
    /// Codec declarations describe types, not permission to ignore encoded data.
    /// Only actual contract locations lose their corresponding raw identity.
    pub(crate) fn comparison_value(&self, contract_paths: &[String]) -> Value {
        let mut logical = self.logical.clone();
        if self.protobuf.is_some() {
            protobuf::prepare_comparison(&mut logical, "", contract_paths);
        }
        logical
    }

    /// The caller supplies the same rule's authorized delivery selectors. Shape,
    /// unknown data, and every other logical field remain immutable.
    pub(crate) fn encode(&self, logical: &Value, allowed_paths: &[String]) -> Result<Vec<u8>> {
        validate_changes(&self.logical, logical, "", allowed_paths)?;
        if logical == &self.logical {
            return Ok(self.original.clone());
        }
        let output = match &self.protobuf {
            Some(document) => document.encode(logical),
            None => Ok(serde_json::to_vec(logical)?),
        }?;
        ensure!(
            output.len() <= 1024 * 1024,
            "derived payload exceeds the 1 MiB codec limit"
        );
        Ok(output)
    }
}

fn validate_changes(
    before: &Value,
    after: &Value,
    pointer: &str,
    allowed: &[String],
) -> Result<()> {
    if before == after {
        return Ok(());
    }
    match (before, after) {
        (Value::Object(before), Value::Object(after)) => {
            ensure!(
                before.keys().eq(after.keys()),
                "delivery cannot change field presence at {pointer:?}"
            );
            for (key, value) in before {
                let after = &after[key];
                if key == protobuf::INTERNAL_KEY {
                    ensure!(
                        value == after,
                        "delivery cannot change the Protobuf remainder"
                    );
                } else {
                    validate_changes(value, after, &format!("{pointer}/{}", escape(key)), allowed)?;
                }
            }
        }
        (Value::Array(before), Value::Array(after)) => {
            ensure!(
                before.len() == after.len(),
                "delivery cannot change array cardinality at {pointer:?}"
            );
            for (index, (before, after)) in before.iter().zip(after).enumerate() {
                validate_changes(before, after, &format!("{pointer}/{index}"), allowed)?;
            }
        }
        _ => {
            ensure!(
                !before.is_array()
                    && !before.is_object()
                    && !after.is_array()
                    && !after.is_object(),
                "delivery cannot change the structure at {pointer:?}"
            );
            let same_type = match (before, after) {
                (Value::Null, Value::Null)
                | (Value::Bool(_), Value::Bool(_))
                | (Value::String(_), Value::String(_)) => true,
                (Value::Number(_), Value::Number(_)) => {
                    before.is_i64() == after.is_i64() && before.is_u64() == after.is_u64()
                }
                _ => false,
            };
            ensure!(
                same_type,
                "delivery cannot change scalar type at {pointer:?}"
            );
            ensure!(
                allowed
                    .iter()
                    .any(|pattern| pointer_matches(pattern, pointer)),
                "delivery changed an unauthorized field at {pointer:?}"
            );
        }
    }
    Ok(())
}

pub(super) fn pointer_matches(pattern: &str, pointer: &str) -> bool {
    let pattern = pattern.split('/').collect::<Vec<_>>();
    let pointer = pointer.split('/').collect::<Vec<_>>();
    pattern.len() == pointer.len()
        && pattern.iter().zip(pointer).all(|(expected, actual)| {
            *expected == actual
                || *expected == "*"
                    && actual.parse::<usize>().is_ok()
                    && (actual == "0" || !actual.starts_with('0'))
        })
}

pub(super) fn escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests;
