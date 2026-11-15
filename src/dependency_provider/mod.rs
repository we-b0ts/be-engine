//! Application exports for native resource admission contracts.
#[cfg(test)]
use crate::{
    policy::Surface,
    protocol_contract::{NativeProtocolVersion, ProtocolKind, ProtocolRole},
    value_contract::plan::SlotKind,
};
pub(crate) use traffic_policy_compiler::resource::*;
#[cfg(test)]
mod tests;
