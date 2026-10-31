//! Pure rule requirements shared by preparation, execution indexes and evidence.
use crate::{
    policy::{CapabilityId, Slot, Surface},
    protocol_contract::{ProtocolKind, ProtocolRole},
    value_codec::CodecKind,
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleKind {
    Value,
    Identity,
    RedisSequence,
    RedisAppendStream,
    RedisReadCommutation,
    RedisReadObservation,
    RedisExpiryRefresh,
    RedisActivityRefresh,
    ResponseJwt,
    ResponseHeaderDate,
    ResponseGenerated,
    ResponseBody,
    HttpRequest,
    MysqlValues,
    InputJwt,
    InputSignedTimestamp,
    CaptureHttp,
    CaptureBreeze,
    CaptureHttpResponse,
    ProcessOwned,
    FiniteSharing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExecutionOwner {
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
pub(crate) enum SlotKind {
    Body,
    SseData,
    Value,
    SqlValue,
    SqlColumn,
    SqlField,
    RedisValue,
}
impl SlotKind {
    pub(crate) fn of(slot: &Slot) -> Self {
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
pub(crate) enum IndexRequirement {
    Scope,
    EndpointOperation,
    SessionOrder,
    TypedSlot,
    SemanticLink,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct IndexRequirements {
    pub(crate) required: BTreeSet<IndexRequirement>,
}
impl IndexRequirements {
    pub(crate) fn new(required: impl IntoIterator<Item = IndexRequirement>) -> Self {
        Self {
            required: required.into_iter().collect(),
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct EvidenceRequirements {
    pub(crate) source_record: bool,
    pub(crate) independent_target: bool,
    pub(crate) protected_values: bool,
    pub(crate) all_hypothesis_attempts: bool,
    pub(crate) native_delivery: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RuleExecutionPlan {
    pub(crate) kind: RuleKind,
    pub(crate) owner: ExecutionOwner,
    pub(crate) protocol: Option<ProtocolKind>,
    pub(crate) role: Option<ProtocolRole>,
    pub(crate) surface: Option<Surface>,
    pub(crate) slot: Option<SlotKind>,
    pub(crate) codec: Option<CodecKind>,
    pub(crate) capabilities: BTreeSet<CapabilityId>,
    pub(crate) indexes: IndexRequirements,
    pub(crate) evidence: EvidenceRequirements,
}
