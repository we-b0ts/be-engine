//! Closed codec providers share one result type and dispatch without a vtable.
use super::{AuthorizedPatch, DecodedDocument, protobuf};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodecKind {
    Scalar,
    Json,
    Protobuf,
}
impl CodecKind {
    pub fn of(codec: &crate::codec::Codec) -> Self {
        match codec {
            crate::codec::Codec::Scalar => Self::Scalar,
            crate::codec::Codec::Json => Self::Json,
            crate::codec::Codec::Protobuf(_) => Self::Protobuf,
        }
    }
}

pub trait ValueCodec {
    fn kind(&self) -> CodecKind;
    fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument>;
    fn comparison_view<'a>(document: &'a DecodedDocument, paths: &[String]) -> Cow<'a, Value>;
    fn encode(document: &DecodedDocument, patch: &AuthorizedPatch<'_>) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone, Copy)]
pub struct ScalarCodec;
#[derive(Debug, Clone, Copy)]
pub struct JsonCodec;
#[derive(Debug, Clone)]
pub struct ProtobufCodec {
    schema: Arc<protobuf::Schema>,
}

/// Contains immutable schema preparation only. Permissions, clocks, bindings
/// and decoded payloads never enter a reusable codec plan.
#[derive(Debug, Clone)]
pub enum CodecPlan {
    Scalar(ScalarCodec),
    Json(JsonCodec),
    Protobuf(ProtobufCodec),
}
impl CodecPlan {
    pub fn compile(codec: &crate::codec::Codec) -> Result<Self> {
        #[cfg(any(test, feature = "test-support"))]
        COMPILE_CALLS.with(|calls| calls.set(calls.get() + 1));
        Ok(match codec {
            crate::codec::Codec::Scalar => Self::Scalar(ScalarCodec),
            crate::codec::Codec::Json => Self::Json(JsonCodec),
            crate::codec::Codec::Protobuf(codec) => Self::Protobuf(ProtobufCodec {
                schema: protobuf::schema(codec)?,
            }),
        })
    }
    pub fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument> {
        ValueCodec::decode(self, bytes)
    }
}
impl ValueCodec for CodecPlan {
    fn comparison_view<'a>(document: &'a DecodedDocument, paths: &[String]) -> Cow<'a, Value> {
        match document.kind {
            CodecKind::Scalar => ScalarCodec::comparison_view(document, paths),
            CodecKind::Json => JsonCodec::comparison_view(document, paths),
            CodecKind::Protobuf => ProtobufCodec::comparison_view(document, paths),
        }
    }
    fn encode(document: &DecodedDocument, patch: &AuthorizedPatch<'_>) -> Result<Vec<u8>> {
        match document.kind {
            CodecKind::Scalar => ScalarCodec::encode(document, patch),
            CodecKind::Json => JsonCodec::encode(document, patch),
            CodecKind::Protobuf => ProtobufCodec::encode(document, patch),
        }
    }
    fn kind(&self) -> CodecKind {
        match self {
            Self::Scalar(codec) => codec.kind(),
            Self::Json(codec) => codec.kind(),
            Self::Protobuf(codec) => codec.kind(),
        }
    }
    fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument> {
        match self {
            Self::Scalar(codec) => codec.decode(bytes),
            Self::Json(codec) => codec.decode(bytes),
            Self::Protobuf(codec) => codec.decode(bytes),
        }
    }
}
fn validate_payload(bytes: &[u8]) -> Result<()> {
    #[cfg(any(test, feature = "test-support"))]
    super::DECODE_CALLS.with(|calls| calls.set(calls.get() + 1));
    ensure!(
        bytes.len() <= crate::MAX_VALUE_BYTES,
        "payload exceeds the 64 MiB codec limit"
    );
    Ok(())
}
fn json(bytes: &[u8], kind: CodecKind) -> Result<DecodedDocument> {
    validate_payload(bytes)?;
    let logical = crate::json::parse(bytes)
        .context("payload requires complete JSON without duplicate members")?;
    ensure!(
        kind != CodecKind::Scalar || (!logical.is_array() && !logical.is_object()),
        "native scalar codec rejects structured payloads"
    );
    Ok(DecodedDocument {
        logical,
        original: bytes.to_vec(),
        protobuf: None,
        kind,
    })
}
impl ValueCodec for ScalarCodec {
    fn comparison_view<'a>(document: &'a DecodedDocument, _paths: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&document.logical)
    }
    fn encode(document: &DecodedDocument, patch: &AuthorizedPatch<'_>) -> Result<Vec<u8>> {
        ensure!(
            document.kind == CodecKind::Scalar,
            "codec provider does not own this document"
        );
        crate::json::render::derived(&document.original, patch.logical())
    }
    fn kind(&self) -> CodecKind {
        CodecKind::Scalar
    }
    fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument> {
        json(bytes, self.kind())
    }
}
impl ValueCodec for JsonCodec {
    fn comparison_view<'a>(document: &'a DecodedDocument, _paths: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&document.logical)
    }
    fn encode(document: &DecodedDocument, patch: &AuthorizedPatch<'_>) -> Result<Vec<u8>> {
        ensure!(
            document.kind == CodecKind::Json,
            "codec provider does not own this document"
        );
        crate::json::render::derived(&document.original, patch.logical())
    }
    fn kind(&self) -> CodecKind {
        CodecKind::Json
    }
    fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument> {
        json(bytes, self.kind())
    }
}
impl ValueCodec for ProtobufCodec {
    fn comparison_view<'a>(document: &'a DecodedDocument, paths: &[String]) -> Cow<'a, Value> {
        if paths.is_empty() {
            return Cow::Borrowed(&document.logical);
        }
        let mut logical = document.logical.clone();
        protobuf::prepare_comparison(&mut logical, "", paths);
        Cow::Owned(logical)
    }
    fn encode(document: &DecodedDocument, patch: &AuthorizedPatch<'_>) -> Result<Vec<u8>> {
        ensure!(
            document.kind == CodecKind::Protobuf,
            "codec provider does not own this document"
        );
        document
            .protobuf
            .as_ref()
            .context("Protobuf document lacks its original wire remainder")?
            .encode(patch.logical())
    }
    fn kind(&self) -> CodecKind {
        CodecKind::Protobuf
    }
    fn decode(&self, bytes: &[u8]) -> Result<DecodedDocument> {
        validate_payload(bytes)?;
        let (document, logical) = self.schema.decode(bytes)?;
        Ok(DecodedDocument {
            logical,
            original: bytes.to_vec(),
            protobuf: Some(document),
            kind: self.kind(),
        })
    }
}
#[cfg(any(test, feature = "test-support"))]
thread_local! { static COMPILE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(any(test, feature = "test-support"))]
pub fn measured_compiles<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let before = COMPILE_CALLS.with(std::cell::Cell::get);
    let result = operation();
    (result, COMPILE_CALLS.with(std::cell::Cell::get) - before)
}
