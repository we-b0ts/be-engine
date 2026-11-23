//! Pure rule requirements shared by preparation, execution indexes and evidence.
use crate::{
    CapabilityId, CodecKind, Slot, Surface,
    protocol_contract::{ProtocolKind, ProtocolRole},
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Value,
    Identity,
    RedisSequence,
    ResponseJwt,
    ResponseHeaderDate,
    ResponseGenerated,
    ResponseBody,
    HttpRequest,
    MysqlValues,
    InputJwt,
    InputSignedTimestamp,
    CaptureHttp,
    CaptureHttpResponse,
    ProcessOwned,
    FiniteSharing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOwner {
    ValueKernel,
    IdentityState,
    RedisState,
    ResponseDelivery,
    PrimaryInput,
    Capture,
    Attribution,
    FiniteSharing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotKind {
    Body,
    SseData,
    Value,
    SqlValue,
    SqlColumn,
    SqlField,
    RedisValue,
}
impl SlotKind {
    pub fn of(slot: &Slot) -> Self {
        match slot {
            Slot::Body => Self::Body,
            Slot::SseData(_) => Self::SseData,
            Slot::Value => Self::Value,
            Slot::SqlValue(_) => Self::SqlValue,
            Slot::SqlColumn(_) => Self::SqlColumn,
            Slot::SqlField(_) => Self::SqlField,
            Slot::RedisValue(_) => Self::RedisValue,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexRequirement {
    Scope,
    EndpointOperation,
    SessionOrder,
    TypedSlot,
    SemanticLink,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IndexRequirements {
    pub required: BTreeSet<IndexRequirement>,
}
impl IndexRequirements {
    pub fn new(required: impl IntoIterator<Item = IndexRequirement>) -> Self {
        Self {
            required: required.into_iter().collect(),
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EvidenceRequirements {
    pub source_record: bool,
    pub independent_target: bool,
    pub protected_values: bool,
    pub all_hypothesis_attempts: bool,
    pub native_delivery: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleExecutionPlan {
    pub kind: RuleKind,
    pub owner: ExecutionOwner,
    pub protocol: Option<ProtocolKind>,
    pub role: Option<ProtocolRole>,
    pub surface: Option<Surface>,
    pub slot: Option<SlotKind>,
    pub codec: Option<CodecKind>,
    pub capabilities: BTreeSet<CapabilityId>,
    pub indexes: IndexRequirements,
    pub evidence: EvidenceRequirements,
}
