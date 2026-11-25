//! Bounded payload decoding with typed values and lossless protocol remainders.
mod projection;
pub(crate) use projection::project as project_value;
pub use projection::restore as restore_projection;
mod providers;
mod view;

mod schema;
use anyhow::{Result, ensure};
#[cfg(any(test, feature = "test-support"))]
pub use providers::measured_compiles;
pub use providers::{CodecKind, CodecPlan, ValueCodec};
pub use schema::{Codec, unique_map};
use serde_json::Value;
use std::borrow::Cow;
#[cfg(any(test, feature = "test-support"))]
pub use view::Presence;
pub use view::ValueView;

pub struct CodecView;

/// One decoded payload, never an entire native protocol message. Protocol
/// adapters retain their framing, physical scalar types and immutable slots.
#[derive(Clone)]
pub struct DecodedDocument {
    pub logical: Value,
    document: std::sync::Arc<dyn traffic_value::codec::ValueDocument>,
    kind: CodecKind,
}

impl std::fmt::Debug for DecodedDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecodedDocument")
            .field("kind", &self.kind)
            .field("bytes", &self.original_bytes().len())
            .finish()
    }
}

pub type DecodedValue = DecodedDocument;

/// Constructed only after the common document authorization check. Providers
/// encode a validated logical edit; callers cannot bypass that check.
pub struct AuthorizedPatch<'a> {
    logical: &'a traffic_value::Value,
    allowed: &'a [String],
}
impl AuthorizedPatch<'_> {
    pub fn logical(&self) -> &traffic_value::Value {
        self.logical
    }
}

impl CodecView {
    pub fn decode(
        codec: &Codec,
        bytes: &[u8],
        registry: &traffic_value::codec::CodecRegistry,
    ) -> Result<DecodedDocument> {
        CodecPlan::compile(codec, registry)?.decode(bytes)
    }
}

impl DecodedDocument {
    pub fn value(&self) -> &traffic_value::Value {
        self.document.value()
    }

    pub fn logical_comparison_view(&self, paths: &[String]) -> Cow<'_, traffic_value::Value> {
        self.document.comparison_view(paths)
    }

    /// Borrow the projection of the full decoded value.
    pub fn projection(&self) -> crate::compare::LogicalProjection<'_> {
        crate::compare::LogicalProjection::borrowed(self.value(), &self.logical)
    }

    pub fn original_bytes(&self) -> &[u8] {
        self.document.original_bytes()
    }

    pub fn view(&self) -> ValueView<'_> {
        ValueView::new(self.kind.clone(), &self.logical)
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
        let logical = projection::restore(self.document.value(), logical)?;
        self.encode_value(&logical, allowed_paths)
    }

    pub fn encode_value(
        &self,
        logical: &traffic_value::Value,
        allowed_paths: &[String],
    ) -> Result<Vec<u8>> {
        traffic_value::validate_patch(self.document.value(), logical, allowed_paths)?;
        if logical == self.document.value() {
            return Ok(self.original_bytes().to_vec());
        }
        let patch = AuthorizedPatch {
            logical,
            allowed: allowed_paths,
        };
        let output = <CodecPlan as providers::ValueCodec>::encode(self, &patch)?;
        ensure!(
            output.len() <= crate::MAX_VALUE_BYTES,
            "derived payload exceeds the 64 MiB codec limit"
        );
        Ok(output)
    }
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
