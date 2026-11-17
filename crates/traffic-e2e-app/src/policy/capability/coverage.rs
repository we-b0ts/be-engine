//! Integrated carrier capability regressions exercise application composition.
use super::*;
use crate::{
    policy::{NativeEffect, NativeRule, Rule, Surface},
    protocol_contract::{ProtocolKind, ProtocolRole},
    value_codec::CodecKind,
    value_contract::plan::*,
};
use traffic_policy_compiler::capability::{ValueCoordinate, value_capability_support};
mod tests;

use traffic_policy_compiler::capability::coverage::native_kind_owner;
