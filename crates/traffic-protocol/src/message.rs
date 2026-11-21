//! Physical value locations projected by a native protocol implementation.
use std::collections::BTreeMap;

use anyhow::Result;
use bytes::Bytes;
use serde_json::Value;

/// Native structure contains every invariant outside the projected values.
/// Slot identities retain the complete shape and multiplicity of those values.
pub struct ProjectedMessage {
    pub structure: Value,
    pub values: BTreeMap<String, ProjectedValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarEncoding {
    Utf8,
    Json,
}

#[derive(Clone)]
pub struct ProjectedValue {
    pub bytes: Bytes,
    pub scalar_encoding: ScalarEncoding,
}

impl ProjectedValue {
    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            scalar_encoding: ScalarEncoding::Utf8,
        }
    }

    pub fn json(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            scalar_encoding: ScalarEncoding::Json,
        }
    }
}

/// A protocol supplies locations, intrinsic structure and native encoding. The
/// framework applies codecs and field rules to the projected byte values.
pub trait ProtocolMessage: Send + Sync {
    fn command_name(&self) -> Option<&str> {
        None
    }

    fn project(&self) -> Result<ProjectedMessage>;
    fn locate(&self, selector: &Value) -> Result<Vec<String>>;
    fn evidence(&self, query: &Value) -> Result<Value>;
}

pub trait MessageEncoder: ProtocolMessage {
    fn stored(&self) -> Option<&dyn StoredMessage> {
        None
    }

    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes>;

    fn output(
        &self,
        values: &BTreeMap<String, Bytes>,
    ) -> Result<Box<dyn crate::output::OutputStream>> {
        Ok(Box::new(crate::output::SingleOutput::new(
            self.encode(values)?,
        )))
    }
}

/// An immutable response whose native payload is read only at delivery.
pub trait StoredMessage: Send + Sync {
    fn load(&self) -> Result<std::sync::Arc<dyn MessageEncoder>>;

    fn source_structure(&self) -> Option<&serde_json::Value> {
        None
    }
}
