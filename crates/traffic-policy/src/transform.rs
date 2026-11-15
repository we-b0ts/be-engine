//! Transformation plans request host capabilities before materializing a value.
use anyhow::Result;
use std::collections::BTreeMap;
use traffic_value::Value;

pub struct TransformInput<'a> {
    pub bytes: &'a [u8],
    pub context: &'a Value,
}

/// Parameters can contain private process inputs. They have no Debug or
/// serialization implementation on the execution request itself.
pub struct ResourceRequest {
    pub id: String,
    pub capability: String,
    pub parameters: Value,
}

pub struct TransformedValue {
    pub bytes: Vec<u8>,
}

pub trait TransformPolicy: Send + Sync {
    fn inspect(&self, input: &TransformInput<'_>) -> Result<Option<Box<dyn TransformPlan>>>;
}

pub trait TransformPlan: Send + Sync {
    fn requests(&self) -> &[ResourceRequest];
    fn materialize(
        self: Box<Self>,
        resources: &BTreeMap<String, Value>,
    ) -> Result<TransformedValue>;
}
