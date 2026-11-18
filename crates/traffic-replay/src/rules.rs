//! Content execution ports. Application composition supplies actual rule owners.
use anyhow::Result;
use serde_json::Value;
use traffic_protocol::message::{ProjectedMessage, ProtocolMessage};

pub trait RuleRuntime: Send + Sync + 'static {
    type Bindings: Default;
    type Delivery: Default;
    type Context;
    type Metadata: ?Sized;
    type Comparison;
    type Prepared: Send + Sync;

    fn prepare(message: &dyn ProtocolMessage, bindings: &Self::Bindings) -> Result<Self::Prepared>;
    fn structure(prepared: &Self::Prepared) -> &Value;
    fn compare(
        prepared: &Self::Prepared,
        actual: &dyn ProtocolMessage,
        context: Self::Context,
        metadata: &Self::Metadata,
    ) -> Result<Self::Comparison>;
    fn passed(comparison: &Self::Comparison) -> bool;
}

/// The default execution port checks exact native facts and projected bytes.
/// Applications install content extensions through another RuleRuntime.
pub struct ExactRules;

impl RuleRuntime for ExactRules {
    type Bindings = ();
    type Delivery = ();
    type Context = ();
    type Metadata = ();
    type Comparison = bool;
    type Prepared = ProjectedMessage;

    fn prepare(message: &dyn ProtocolMessage, _bindings: &()) -> Result<ProjectedMessage> {
        message.project()
    }
    fn structure(prepared: &ProjectedMessage) -> &Value {
        &prepared.structure
    }
    fn compare(
        prepared: &ProjectedMessage,
        actual: &dyn ProtocolMessage,
        _context: (),
        _metadata: &(),
    ) -> Result<bool> {
        let actual = actual.project()?;
        Ok(prepared.structure == actual.structure
            && prepared.values.keys().eq(actual.values.keys())
            && prepared.values.iter().all(|(location, source)| {
                let target = &actual.values[location];
                source.scalar_encoding == target.scalar_encoding && source.bytes == target.bytes
            }))
    }
    fn passed(comparison: &bool) -> bool {
        *comparison
    }
}
