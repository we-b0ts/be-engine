//! Compatibility bindings delegate decoding and rendering to registered codecs.
use super::{AuthorizedPatch, Codec, DecodedDocument};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;
use traffic_value::codec::{CodecRegistry, PreparedCodec, ValueDocument};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodecKind(std::borrow::Cow<'static, str>);
impl CodecKind {
    #[allow(non_upper_case_globals)]
    pub const Json: Self = Self(std::borrow::Cow::Borrowed("json"));
    #[allow(non_upper_case_globals)]
    pub const Scalar: Self = Self(std::borrow::Cow::Borrowed("scalar"));
    #[allow(non_upper_case_globals)]
    pub const Protobuf: Self = Self(std::borrow::Cow::Borrowed("protobuf"));
    pub fn of(codec: &Codec) -> Self {
        Self(std::borrow::Cow::Owned(codec.id().into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub trait ValueCodec {
    fn kind(&self) -> CodecKind;
    fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument>;
    fn comparison_view<'a>(document: &'a DecodedDocument, paths: &[String]) -> Cow<'a, Value>;
    fn encode(document: &DecodedDocument, patch: &AuthorizedPatch<'_>) -> Result<Vec<u8>>;
}

#[derive(Clone)]
pub struct CodecPlan {
    kind: CodecKind,
    codec: PreparedCodec,
}
impl std::fmt::Debug for CodecPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodecPlan")
            .field("kind", &self.kind)
            .finish()
    }
}
impl CodecPlan {
    pub fn recognize(
        source: &[u8],
        metadata: &traffic_value::Value,
        registry: &CodecRegistry,
    ) -> Result<Self> {
        let codec = registry.recognize(source, metadata)?;
        Ok(Self {
            kind: CodecKind(std::borrow::Cow::Owned(codec.descriptor().id.into())),
            codec,
        })
    }
    pub fn try_recognize(
        source: &[u8],
        metadata: &traffic_value::Value,
        registry: &CodecRegistry,
    ) -> Result<Option<Self>> {
        Ok(registry.try_recognize(source, metadata)?.map(|codec| Self {
            kind: CodecKind(std::borrow::Cow::Owned(codec.descriptor().id.into())),
            codec,
        }))
    }
    pub fn try_recognize_source(
        source: &[u8],
        metadata: &traffic_value::Value,
        registry: &CodecRegistry,
    ) -> Result<Option<(Self, Option<DecodedDocument>)>> {
        let Some(selected) = registry.try_recognize_source(source, metadata)? else {
            return Ok(None);
        };
        let plan = Self {
            kind: CodecKind(Cow::Borrowed(selected.codec.descriptor().id)),
            codec: selected.codec,
        };
        let document = selected
            .document
            .map(|document| plan.decoded(document))
            .transpose()?;
        Ok(Some((plan, document)))
    }
    pub fn declaration(&self) -> Result<Codec> {
        Codec::registered(
            self.codec.descriptor().id,
            serde_json::to_value(self.codec.configuration())?,
        )
    }
    pub fn compile(codec: &Codec, registry: &CodecRegistry) -> Result<Self> {
        #[cfg(any(test, feature = "test-support"))]
        COMPILE_CALLS.with(|calls| calls.set(calls.get() + 1));
        let configuration = serde_json::from_value(codec.configuration().clone())?;
        let prepared = registry.prepare(codec.id(), &configuration)?;
        Ok(Self {
            kind: CodecKind::of(codec),
            codec: prepared,
        })
    }
    pub fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument> {
        ValueCodec::decode(self, bytes)
    }

    fn decoded(&self, document: Arc<dyn ValueDocument>) -> Result<DecodedDocument> {
        let logical = serde_json::to_value(document.value())?;
        Ok(DecodedDocument {
            logical,
            document,
            kind: self.kind.clone(),
        })
    }
}

impl ValueCodec for CodecPlan {
    fn comparison_view<'a>(document: &'a DecodedDocument, paths: &[String]) -> Cow<'a, Value> {
        let view = document.document.comparison_view(paths);
        if std::ptr::eq(view.as_ref(), document.document.value()) {
            Cow::Borrowed(&document.logical)
        } else {
            Cow::Owned(serde_json::to_value(view).expect("decoded content is serializable"))
        }
    }
    fn encode(document: &DecodedDocument, patch: &AuthorizedPatch<'_>) -> Result<Vec<u8>> {
        document.document.encode(patch.logical, patch.allowed)
    }
    fn kind(&self) -> CodecKind {
        self.kind.clone()
    }
    fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument> {
        #[cfg(any(test, feature = "test-support"))]
        super::DECODE_CALLS.with(|calls| calls.set(calls.get() + 1));
        self.decoded(self.codec.decode(bytes)?)
    }
}

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
thread_local! { static COMPILE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(any(test, feature = "test-support"))]
pub fn measured_compiles<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let before = COMPILE_CALLS.with(std::cell::Cell::get);
    let result = operation();
    (result, COMPILE_CALLS.with(std::cell::Cell::get) - before)
}
