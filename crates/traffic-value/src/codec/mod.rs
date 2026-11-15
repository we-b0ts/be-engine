//! Open content recognition, preparation and lossless document access.
use std::{borrow::Cow, sync::Arc};

use anyhow::Result;

use crate::Value;

mod registry;
pub use registry::{CodecProbe, CodecRegistry, PreparedCodec};

#[derive(Debug, Clone, serde::Serialize)]
pub struct CodecDescriptor {
    pub id: &'static str,
    pub version: u32,
}

/// Recognition is based on Source bytes and available format metadata. A
/// candidate can request metadata without claiming a definite decoding plan.
#[derive(Debug, Clone)]
pub enum Recognition {
    Unrecognized,
    Candidate {
        reason: String,
    },
    Recognized {
        confidence: u16,
        configuration: Value,
    },
}

pub trait CodecProvider: Send + Sync {
    fn descriptor(&self) -> CodecDescriptor;
    fn recognize(&self, source: &[u8], metadata: &Value) -> Result<Recognition>;
    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>>;
    fn fields_overlap(
        &self,
        _left_configuration: &Value,
        left_path: &str,
        _right_configuration: &Value,
        right_path: &str,
    ) -> Result<bool> {
        Ok(crate::path::overlaps(left_path, right_path))
    }
    fn merge(&self, configurations: &[&Value]) -> Result<Value> {
        let first = configurations
            .first()
            .ok_or_else(|| anyhow::anyhow!("codec merge has no configurations"))?;
        anyhow::ensure!(
            configurations
                .iter()
                .all(|configuration| configuration == first),
            "selected rules disagree on codec configuration"
        );
        Ok((*first).clone())
    }
}

pub trait ValueCodec: Send + Sync {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>>;
}

/// Codecs keep native wire details behind this interface. An execution caller
/// observes logical fields and delegates derived encoding to the same owner.
pub trait ValueDocument: Send + Sync {
    fn value(&self) -> &Value;
    fn original_bytes(&self) -> &[u8];
    fn comparison_view<'a>(&'a self, selected: &[String]) -> Cow<'a, Value>;
    fn encode(&self, logical: &Value, allowed: &[String]) -> Result<Vec<u8>>;
}
