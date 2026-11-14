//! Bounded payload decoding with typed values and lossless protocol remainders.
mod protobuf;
mod providers;
mod view;

mod schema;
use anyhow::{Result, ensure};
#[cfg(any(test, feature = "test-support"))]
pub use providers::measured_compiles;
pub use providers::{CodecKind, CodecPlan, ValueCodec};
pub use schema::{Codec, ProtobufCodec, ProtobufField, ProtobufType, unique_map};
use serde_json::Value;
use std::borrow::Cow;
#[cfg(any(test, feature = "test-support"))]
pub use view::Presence;
pub use view::ValueView;

/// Reserved codec metadata carrying unselected Protobuf wire data.
pub const PROTOBUF_REMAINDER_KEY: &str = protobuf::INTERNAL_KEY;

pub struct CodecView;

/// One decoded payload, never an entire native protocol message. Protocol
/// adapters retain their framing, physical scalar types and immutable slots.
#[derive(Debug, Clone)]
pub struct DecodedDocument {
    pub logical: Value,
    original: Vec<u8>,
    protobuf: Option<protobuf::Document>,
    kind: CodecKind,
}

pub type DecodedValue = DecodedDocument;

/// Constructed only after the common document authorization check. Providers
/// encode a validated logical edit; callers cannot bypass that check.
pub struct AuthorizedPatch<'a> {
    logical: &'a Value,
}
impl AuthorizedPatch<'_> {
    pub fn logical(&self) -> &Value {
        self.logical
    }
}

impl CodecView {
    pub fn decode(codec: &Codec, bytes: &[u8]) -> Result<DecodedDocument> {
        CodecPlan::compile(codec)?.decode(bytes)
    }
}

impl DecodedDocument {
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    pub fn view(&self) -> ValueView<'_> {
        ValueView::new(self.kind, &self.logical)
    }

    /// Codec declarations describe types, not permission to ignore encoded data.
    /// Only actual contract locations lose their corresponding raw identity.
    pub fn comparison_value(&self, contract_paths: &[String]) -> Value {
        self.comparison_view(contract_paths).into_owned()
    }

    pub fn comparison_view(&self, contract_paths: &[String]) -> Cow<'_, Value> {
        <CodecPlan as providers::ValueCodec>::comparison_view(self, contract_paths)
    }

    /// The caller supplies the same rule's authorized delivery selectors. Shape,
    /// unknown data, and every other logical field remain immutable.
    pub fn encode(&self, logical: &Value, allowed_paths: &[String]) -> Result<Vec<u8>> {
        validate_changes(&self.logical, logical, "", allowed_paths)?;
        if logical == &self.logical {
            return Ok(self.original.clone());
        }
        let patch = AuthorizedPatch { logical };
        let output = <CodecPlan as providers::ValueCodec>::encode(self, &patch)?;
        ensure!(
            output.len() <= crate::MAX_VALUE_BYTES,
            "derived payload exceeds the 64 MiB codec limit"
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

pub fn pointer_matches(pattern: &str, pointer: &str) -> bool {
    pattern.split('/').count() == pointer.split('/').count()
        && pattern
            .split('/')
            .zip(pointer.split('/'))
            .all(|(expected, actual)| {
                expected == actual
                    || expected == "*"
                        && actual.parse::<usize>().is_ok()
                        && (actual == "0" || !actual.starts_with('0'))
            })
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static DECODE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn measured_decodes<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let before = DECODE_CALLS.with(std::cell::Cell::get);
    let result = operation();
    (result, DECODE_CALLS.with(std::cell::Cell::get) - before)
}

pub(super) fn escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
