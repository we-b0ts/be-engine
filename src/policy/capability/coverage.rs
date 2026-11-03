//! Exhaustive semantic/carrier admission. Unsupported is explicit, never a no-op.
use super::*;
use crate::{
    dependency_provider::{
        DependencyProvider, NativeResource, ResourcePreparationRequest, ResourceProvider,
    },
    policy::{NativeEffect, NativeRule, Rule, Surface},
    protocol_contract::{CapabilitySupport, ProtocolKind, ProtocolRole},
    value_codec::CodecKind,
    value_contract::plan::{
        EvidenceRequirements, ExecutionOwner, IndexRequirement as I, IndexRequirements,
        RuleExecutionPlan, RuleKind, SlotKind,
    },
};
use anyhow::Context;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ValueCoordinate {
    pub(crate) protocol: ProtocolKind,
    pub(crate) role: ProtocolRole,
    pub(crate) surface: Surface,
    pub(crate) slot: SlotKind,
    pub(crate) codec: CodecKind,
}

pub(crate) fn value_capability_support(
    coordinate: ValueCoordinate,
    capability: CapabilityId,
) -> CapabilitySupport {
    use CapabilitySupport::{Supported, Unsupported};
    let ValueCoordinate {
        protocol,
        role,
        surface,
        slot,
        codec,
    } = coordinate;
    if protocol == ProtocolKind::Mysql && role == ProtocolRole::Dependency {
        return Unsupported {
            reason: "direct MySQL value-rule execution is not installed; existing native SQL effects and global JSON/MySQL formats retain their own executable routes",
        };
    }
    let carrier = match role {
        ProtocolRole::Dependency => {
            ResourceProvider::for_protocol(protocol).value_slot(surface, slot)
        }
        ProtocolRole::Primary => match (protocol, surface, slot) {
            (ProtocolKind::Http, Surface::ApiResponse, SlotKind::Body | SlotKind::SseData) => {
                Supported
            }
            (ProtocolKind::Motan, _, _) => Unsupported {
                reason: "Motan native framing exists; a typed rule payload-slot adapter is not installed",
            },
            (ProtocolKind::Kafka, _, _) => Unsupported {
                reason: "Kafka native replay exists; a typed rule payload-slot adapter is not installed",
            },
            (
                ProtocolKind::Http
                | ProtocolKind::Redis
                | ProtocolKind::Mysql
                | ProtocolKind::Memcached,
                _,
                _,
            ) => Unsupported {
                reason: "the selected primary protocol, surface and physical value slot have no installed adapter",
            },
        },
    };
    if let Unsupported { .. } = carrier {
        return carrier;
    }
    if slot == SlotKind::SseData && codec != CodecKind::Json {
        return Unsupported {
            reason: "SSE data rule slots require the existing JSON event adapter",
        };
    }
    if capability == CapabilityId::RebaseTime && surface != Surface::DependencyResponse {
        return Unsupported {
            reason: "derived timestamp delivery is installed only on dependency.response",
        };
    }
    // Deliberately exhaust both closed axes: adding a codec or a semantic
    // capability must register its support instead of inheriting a default.
    match (codec, capability) {
        (
            CodecKind::Json,
            CapabilityId::Unordered
            | CapabilityId::RelativeTime
            | CapabilityId::Duration
            | CapabilityId::RebaseTime
            | CapabilityId::Identity,
        )
        | (
            CodecKind::Scalar,
            CapabilityId::RelativeTime
            | CapabilityId::Duration
            | CapabilityId::RebaseTime
            | CapabilityId::Identity,
        )
        | (
            CodecKind::Protobuf,
            CapabilityId::Unordered
            | CapabilityId::RelativeTime
            | CapabilityId::Duration
            | CapabilityId::RebaseTime,
        ) => Supported,
        (CodecKind::Scalar, CapabilityId::Unordered) => Unsupported {
            reason: "unordered requires a structured collection; the scalar codec rejects containers",
        },
        (CodecKind::Protobuf, CapabilityId::Identity) => Unsupported {
            reason: "identity contracts require JSON or a physical SQL scalar; Protobuf identity is unsupported",
        },
    }
}

pub(crate) fn validate_rule_coverage(rule: &Rule) -> Result<RuleExecutionPlan> {
    let protocol = rule
        .selector
        .resource
        .as_ref()
        .map(|resource| ProtocolKind::from(resource.protocol))
        .unwrap_or(ProtocolKind::Http);
    let role = if rule.surface == Surface::ApiResponse {
        ProtocolRole::Primary
    } else {
        ProtocolRole::Dependency
    };
    let coordinate = ValueCoordinate {
        protocol,
        role,
        surface: rule.surface,
        slot: SlotKind::of(&rule.slot),
        codec: CodecKind::of(&rule.codec),
    };
    let mut capabilities = rule
        .contract
        .values()
        .map(CapabilityId::for_contract)
        .collect::<BTreeSet<_>>();
    if rule
        .delivery
        .as_ref()
        .is_some_and(|delivery| !delivery.rebase_time.is_empty())
    {
        capabilities.insert(CapabilityId::RebaseTime);
    }
    for capability in &capabilities {
        value_capability_support(coordinate, *capability)
            .require()
            .with_context(|| format!(
                "rule {:?} has unsupported value binding: protocol={}, role={role:?}, surface={:?}, slot={:?}, codec={:?}, capability={capability:?}",
                rule.id, protocol.as_str(), coordinate.surface, coordinate.slot, coordinate.codec
            ))?;
    }
    for (pointer, contract) in &rule.contract {
        validate_contract_binding(&rule.codec, pointer, contract)?;
    }
    let semantic_links = capabilities.contains(&CapabilityId::Identity)
        || capabilities.contains(&CapabilityId::RebaseTime);
    let indexes = if role == ProtocolRole::Dependency {
        if let Some(resource) = &rule.selector.resource {
            ResourceProvider::for_protocol(protocol)
                .bind_resource(NativeResource::from_policy(resource)?)?;
        }
        ResourceProvider::for_protocol(protocol)
            .prepare(ResourcePreparationRequest {
                operation: rule.selector.operation.as_deref(),
                value_slot: Some((rule.surface, coordinate.slot)),
                semantic_links,
            })?
            .indexes
    } else {
        let mut indexes = vec![I::Scope, I::TypedSlot];
        if semantic_links {
            indexes.push(I::SemanticLink);
        }
        IndexRequirements::new(indexes)
    };
    Ok(RuleExecutionPlan {
        kind: RuleKind::Value,
        owner: ExecutionOwner::ValueKernel,
        protocol: Some(protocol),
        role: Some(role),
        surface: Some(rule.surface),
        slot: Some(coordinate.slot),
        codec: Some(coordinate.codec),
        capabilities,
        indexes,
        evidence: EvidenceRequirements {
            source_record: true,
            independent_target: rule.surface != Surface::DependencyResponse,
            protected_values: true,
            all_hypothesis_attempts: rule.surface != Surface::DependencyResponse,
            native_delivery: rule.surface == Surface::DependencyResponse,
        },
    })
}

/// Bind a generic value plan to the actual admitted adapter. A primary plan's
/// historical HTTP default is not evidence that another primary protocol can
/// expose the same slots. Native stateful owners keep their own typed guards.
pub(crate) fn validate_actual_protocol(
    plan: &RuleExecutionPlan,
    protocol: ProtocolKind,
    role: ProtocolRole,
) -> Result<()> {
    if plan.kind != RuleKind::Value {
        return Ok(());
    }
    ensure!(
        plan.role == Some(role),
        "value plan role differs from the actual protocol adapter"
    );
    if role == ProtocolRole::Dependency {
        ensure!(
            plan.protocol == Some(protocol),
            "value plan resource protocol differs from the actual dependency adapter"
        );
    }
    let coordinate = ValueCoordinate {
        protocol,
        role,
        surface: plan
            .surface
            .context("value plan lacks its comparison surface")?,
        slot: plan.slot.context("value plan lacks its physical slot")?,
        codec: plan
            .codec
            .context("value plan lacks its prepared payload codec")?,
    };
    ensure!(
        !plan.capabilities.is_empty(),
        "value plan has no declared semantic capabilities"
    );
    for capability in &plan.capabilities {
        value_capability_support(coordinate, *capability)
            .require()
            .with_context(|| format!(
                "actual value adapter does not support protocol={}, role={role:?}, surface={:?}, slot={:?}, codec={:?}, capability={capability:?}",
                protocol.as_str(), coordinate.surface, coordinate.slot, coordinate.codec
            ))?;
    }
    Ok(())
}

/// Every current native effect has exactly one stage owner. Keeping this match
/// exhaustive makes a new effect require an explicit ownership decision.
pub(crate) fn native_kind_owner(effect: &NativeEffect) -> (RuleKind, ExecutionOwner) {
    use ExecutionOwner as O;
    use NativeEffect as E;
    use RuleKind as K;
    match effect {
        E::Identity(_) => (K::Identity, O::IdentityState),
        E::RedisSequence(_) => (K::RedisSequence, O::RedisState),
        E::RedisAppendStream => (K::RedisAppendStream, O::RedisState),
        E::RedisReadCommutation(_) => (K::RedisReadCommutation, O::RedisState),
        E::RedisReadObservation(_) => (K::RedisReadObservation, O::RedisState),
        E::RedisExpiryRefresh(_) => (K::RedisExpiryRefresh, O::RedisState),
        E::RedisActivityRefresh(_) => (K::RedisActivityRefresh, O::RedisState),
        E::ResponseJwt(_) => (K::ResponseJwt, O::ResponseDelivery),
        E::ResponseHeaderDate(_) => (K::ResponseHeaderDate, O::ResponseDelivery),
        E::ResponseGenerated(_) => (K::ResponseGenerated, O::ResponseDelivery),
        E::ResponseBody(_) => (K::ResponseBody, O::ResponseDelivery),
        E::HttpRequest(_) => (K::HttpRequest, O::ValueKernel),
        E::MysqlValues(_) => (K::MysqlValues, O::ValueKernel),
        E::InputJwt(_) => (K::InputJwt, O::PrimaryInput),
        E::InputSignedTimestamp(_) => (K::InputSignedTimestamp, O::PrimaryInput),
        E::CaptureHttp(_) => (K::CaptureHttp, O::Capture),
        E::CaptureBreeze(_) => (K::CaptureBreeze, O::Capture),
        E::CaptureHttpResponse(_) => (K::CaptureHttpResponse, O::Capture),
        E::ProcessOwned(_) => (K::ProcessOwned, O::Attribution),
        E::FiniteSharing(_) => (K::FiniteSharing, O::FiniteSharing),
    }
}

pub(crate) fn validate_native_coverage(rule: &NativeRule) -> Result<RuleExecutionPlan> {
    let (kind, owner) = native_kind_owner(&rule.effect);
    let declared = rule
        .selector
        .resource
        .as_ref()
        .map(|resource| ProtocolKind::from(resource.protocol));
    let redis = owner == ExecutionOwner::RedisState;
    if redis {
        ensure!(
            declared.is_none_or(|protocol| protocol == ProtocolKind::Redis),
            "Redis stateful effects require their Redis native owner"
        );
    }
    let protocol = if redis {
        Some(ProtocolKind::Redis)
    } else {
        declared.or(match &rule.effect {
            NativeEffect::HttpRequest(_) => Some(ProtocolKind::Http),
            NativeEffect::MysqlValues(_) => Some(ProtocolKind::Mysql),
            NativeEffect::FiniteSharing(crate::policy::native::FiniteSharingEffect::Http) => {
                Some(ProtocolKind::Http)
            }
            NativeEffect::FiniteSharing(crate::policy::native::FiniteSharingEffect::Redis {
                ..
            }) => Some(ProtocolKind::Redis),
            _ => None,
        })
    };
    let runtime = matches!(
        owner,
        ExecutionOwner::ValueKernel
            | ExecutionOwner::IdentityState
            | ExecutionOwner::RedisState
            | ExecutionOwner::ResponseDelivery
            | ExecutionOwner::FiniteSharing
    );
    let (role, surface) = match owner {
        ExecutionOwner::PrimaryInput => (Some(ProtocolRole::Primary), None),
        ExecutionOwner::ValueKernel
        | ExecutionOwner::RedisState
        | ExecutionOwner::FiniteSharing => (
            Some(ProtocolRole::Dependency),
            Some(Surface::DependencyRequest),
        ),
        ExecutionOwner::ResponseDelivery if declared.is_some() => (
            Some(ProtocolRole::Dependency),
            Some(Surface::DependencyResponse),
        ),
        ExecutionOwner::ResponseDelivery => {
            (Some(ProtocolRole::Primary), Some(Surface::ApiResponse))
        }
        ExecutionOwner::IdentityState | ExecutionOwner::Capture | ExecutionOwner::Attribution => {
            (None, None)
        }
    };
    let mut indexes = vec![I::Scope];
    if declared.is_some() || owner == ExecutionOwner::RedisState {
        indexes.push(I::EndpointOperation);
    }
    if runtime || owner == ExecutionOwner::PrimaryInput {
        indexes.push(I::TypedSlot);
    }
    if matches!(
        owner,
        ExecutionOwner::IdentityState
            | ExecutionOwner::RedisState
            | ExecutionOwner::FiniteSharing
            | ExecutionOwner::ValueKernel
    ) {
        indexes.push(I::SemanticLink);
    }
    if let Some(protocol) = protocol
        && role == Some(ProtocolRole::Dependency)
    {
        if let Some(resource) = &rule.selector.resource {
            ResourceProvider::for_protocol(protocol)
                .bind_resource(NativeResource::from_policy(resource)?)?;
        }
        let resource =
            ResourceProvider::for_protocol(protocol).prepare(ResourcePreparationRequest {
                operation: rule.selector.operation.as_deref(),
                value_slot: None,
                semantic_links: false,
            })?;
        indexes.extend(resource.indexes.required);
    }
    let independent = runtime && surface != Some(Surface::DependencyResponse);
    Ok(RuleExecutionPlan {
        kind,
        owner,
        protocol,
        role,
        surface,
        slot: None,
        codec: None,
        capabilities: BTreeSet::new(),
        indexes: IndexRequirements::new(indexes),
        evidence: EvidenceRequirements {
            source_record: true,
            independent_target: independent,
            protected_values: runtime || owner == ExecutionOwner::PrimaryInput,
            all_hypothesis_attempts: independent,
            native_delivery: runtime || owner == ExecutionOwner::PrimaryInput,
        },
    })
}

#[cfg(test)]
mod tests;
