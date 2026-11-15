//! Complete Memcached value contracts and protected request/response observations.
//! Wire adaptation, lane admission and finite consumption remain with the caller.
use super::*;
use crate::policy::{Protocol, Slot, Surface};
use crate::policy_evidence::{SourceIdentity, SourceRole, TargetRole, WitnessMetadata};
mod witness;
pub(crate) use witness::{source_witness, validate_witness};

/// Text byte counts describe framing, rather than an independent application
/// field. Release them only for a selected value contract and require each to
/// agree with its own complete payload before using the native option matcher.
pub(super) fn request_arguments_match(
    policy: Option<&ReplayPolicyRuntime>,
    exchange: &ReplayExchange,
    _target: &TargetKey,
    wire: MemcachedWireProtocol,
    request: &MemcachedRequest,
    observed_at: DateTime<Utc>,
) -> bool {
    let mut normalized = None;
    if wire == MemcachedWireProtocol::Text
        && matches!(
            request.command.to_ascii_lowercase().as_str(),
            "set" | "add" | "replace" | "cas"
        )
        && policy.is_some_and(|policy| policy.request_contracts.global_json().is_some())
    {
        let (Some(source), Some(target)) = (&exchange.value, &request.value) else {
            return false;
        };
        let Ok(args) =
            witness::normalize_value_count(&exchange.args, &request.args, source, target)
        else {
            return false;
        };
        normalized = Some(args);
    }
    arguments_match(
        wire,
        &request.command,
        ArgumentSnapshot {
            args: &exchange.args,
            extras: exchange.extras.as_deref(),
            observed_at: source_start(&exchange.record),
        },
        ArgumentSnapshot {
            args: normalized.as_deref().unwrap_or(&request.args),
            extras: request.extras.as_deref(),
            observed_at: Some(observed_at),
        },
    )
}

pub(super) fn record_request(
    policy: &ReplayPolicyRuntime,
    exchange: &ReplayExchange,
    request: &MemcachedRequest,
    observed_at: DateTime<Utc>,
    observation_id: Option<uuid::Uuid>,
) -> Result<()> {
    if policy.request_contracts.compiled_rules().is_none()
        || !matches!(
            request.command.to_ascii_lowercase().as_str(),
            "set" | "add" | "replace" | "cas"
        )
        || exchange.value.is_none()
        || request.value.is_none()
    {
        return Ok(());
    }
    let Some(case) = exchange.case_id.as_deref() else {
        return Ok(());
    };
    let Some(observation_id) = observation_id else {
        return Ok(());
    };
    let clocks = policy.request_contracts.contract_clocks(
        Some(case),
        source_start(&exchange.record),
        Some(observed_at),
        None,
        None,
    );
    let metadata = metadata(
        &exchange.record,
        case,
        Surface::DependencyRequest,
        TargetRole::IndependentTargetObservation,
        clocks,
    );
    let id = observation_id.to_string();
    if policy
        .request_contracts
        .associate_value_witness(&metadata, &id, None)?
        == crate::policy_evidence::AssociationOutcome::SourceRequired
    {
        let source = serde_json::to_vec(&request_envelope(exchange))?;
        policy
            .request_contracts
            .associate_value_witness(&metadata, &id, Some(&source))?;
    }
    Ok(())
}

pub(super) fn record_target(
    policy: &ReplayPolicyRuntime,
    case: &str,
    target: &TargetKey,
    wire: &str,
    request: &MemcachedRequest,
    observation: (uuid::Uuid, DateTime<Utc>),
) -> Result<crate::policy_evidence::ObservationRetention> {
    let owner = &policy.request_contracts;
    if owner.compiled_rules().is_none() || !owner.retains_value_witnesses() {
        return Ok(crate::policy_evidence::ObservationRetention::Retained);
    }
    let (id, observed_at) = observation;
    let mut actual = envelope(
        wire,
        &request.command,
        request.key.as_deref(),
        &request.args,
        request.value.as_deref(),
        request.extras.as_deref(),
        request.cas,
        request.quiet,
        request.noreply,
    );
    actual["opcode"] = serde_json::to_value(request.opcode)?;
    actual["observed_at"] = serde_json::to_value(observed_at)?;
    actual["request_started_at"] = serde_json::to_value(observed_at)?;
    owner.record_independent_request(
        &id.to_string(),
        case,
        Some(crate::policy::Resource {
            protocol: Protocol::Memcached,
            endpoint: crate::policy::Endpoint {
                host: target.host.clone(),
                port: target.port,
            },
            database: None,
            username: None,
        }),
        &request.command.to_ascii_uppercase(),
        observed_at,
        &serde_json::to_vec(&actual)?,
    )
}

pub(super) fn materialize_response(
    state: &ReplayState,
    matched: &MatchedMemcachedExchange,
) -> Result<(Vec<Vec<u8>>, DependencyRuleDecision)> {
    let Some(policy) = state.replay_policy.as_ref() else {
        return Ok((
            matched.response_frames.clone(),
            DependencyRuleDecision::default(),
        ));
    };
    let exchange = &state.protocols.memcached.exchanges[matched.index];
    let source_key = exchange.key.as_deref();
    let Some(global) = policy.request_contracts.global_json() else {
        return Ok((
            matched.response_frames.clone(),
            DependencyRuleDecision::default(),
        ));
    };
    if !matches!(exchange.record.command.as_str(), "get" | "gets") {
        return Ok((
            matched.response_frames.clone(),
            DependencyRuleDecision::default(),
        ));
    }
    anyhow::ensure!(
        matches!(exchange.record.command.as_str(), "get" | "gets"),
        "Memcached response value contracts currently require GET/GETS"
    );
    if exchange.record.no_response
        || exchange.record.outcome == DependencyExchangeOutcome::NoResponse
    {
        return no_payload(matched);
    }
    anyhow::ensure!(
        exchange.record.outcome == DependencyExchangeOutcome::Response,
        "response value contract requires complete response evidence"
    );
    let source_frames = exchange.response_bytes()?;
    let source_slots =
        crate::memcached::value_slot::extract(&source_frames, &exchange.record.wire_protocol)?;
    let target_slots = crate::memcached::value_slot::extract(
        &matched.response_frames,
        &exchange.record.wire_protocol,
    )?;
    if source_slots.is_empty() {
        return no_payload(matched);
    }
    anyhow::ensure!(
        source_slots.len() == target_slots.len(),
        "Memcached response value count changed"
    );
    let delivered_at = Utc::now();
    let clocks = policy.request_contracts.contract_clocks(
        matched.report.case_id.as_deref(),
        source_start(&exchange.record),
        Some(matched.request_observed_at),
        Some(exchange.record.timestamp),
        Some(delivered_at),
    );
    let mut output = matched.response_frames.clone();
    let mut edits = Vec::new();
    let mut decision = DependencyRuleDecision::default();
    for (slot, target_slot) in source_slots.iter().zip(&target_slots) {
        let key = slot.key.as_deref().or(source_key);
        anyhow::ensure!(
            target_slot.key.as_deref().or(source_key) == key,
            "Memcached response value association changed"
        );
        let payload = &source_frames[slot.frame][slot.payload.clone()];
        if crate::json_value::parse(payload).is_none() {
            continue;
        }
        let delivery = crate::value_contract::response_delivery::Delivery::prepare_global(
            payload, global, clocks,
        )?;
        let mut validation =
            crate::policy::runtime::request_contract::Decision::from_value_comparison(
                delivery.validation().clone(),
            );
        let encoded = if delivery.has_identities() {
            let case = matched
                .report
                .case_id
                .as_deref()
                .context("Memcached identity delivery requires a case")?;
            let (encoded, identities) =
                delivery.render_with_identities(delivered_at, &policy.request_contracts, case)?;
            validation.identity = Some(identities);
            encoded
        } else {
            delivery.render(delivered_at)?
        };
        decision.value_contracts.push(validation);
        edits.push((target_slot.clone(), encoded));
    }
    if edits.is_empty() {
        return no_payload(matched);
    }
    edits.sort_by_key(|(slot, _)| {
        (
            std::cmp::Reverse(slot.frame),
            std::cmp::Reverse(slot.payload.start),
        )
    });
    for (slot, value) in edits {
        output[slot.frame] =
            crate::memcached::value_slot::replace(&output[slot.frame], &slot, &value)?;
    }
    if let Some(case) = matched.report.case_id.as_deref() {
        let mut source = request_envelope(exchange);
        source["response_frames"] = encoded_frames(&source_frames);
        source["outcome"] = serde_json::to_value(exchange.record.outcome)?;
        source["no_response"] = exchange.record.no_response.into();
        let mut target = request_envelope(exchange);
        target["response_frames"] = encoded_frames(&output);
        target["outcome"] = source["outcome"].clone();
        target["no_response"] = source["no_response"].clone();
        target["delivery_request_started_at"] = serde_json::to_value(matched.request_observed_at)?;
        target["response_delivered_at"] = serde_json::to_value(delivered_at)?;
        if exchange.record.wire_protocol == "binary" {
            target["delivery_request"] = serde_json::json!({"opcode": matched.request_opcode, "opaque": matched.request_opaque});
        }
        let allowed = source_slots
            .iter()
            .filter_map(|slot| slot.key.clone().or_else(|| source_key.map(<[u8]>::to_vec)))
            .collect::<Vec<_>>();
        validate_witness(
            &serde_json::to_vec(&source)?,
            &serde_json::to_vec(&target)?,
            Surface::DependencyResponse,
            &allowed,
            clocks,
        )?;
        policy.request_contracts.record_value_witness(
            metadata(
                &exchange.record,
                case,
                Surface::DependencyResponse,
                TargetRole::DerivedDelivery,
                clocks,
            ),
            &serde_json::to_vec(&source)?,
            Some(&serde_json::to_vec(&target)?),
        )?;
    }
    Ok((output, decision))
}

fn no_payload(
    matched: &MatchedMemcachedExchange,
) -> Result<(Vec<Vec<u8>>, DependencyRuleDecision)> {
    tracing::debug!(
        disposition = "no_payload",
        "Memcached response value slot is unavailable; preserving its protocol outcome"
    );
    Ok((
        matched.response_frames.clone(),
        DependencyRuleDecision::default(),
    ))
}

pub(crate) fn source_observation(
    contracts: &crate::policy::runtime::request_contract::RequestContracts,
    case: &str,
    event: &serde_json::Value,
) -> Result<()> {
    if contracts.compiled_rules().is_none()
        || event["event_type"] != "memcached_exchange"
        || event["replay_safe"] != true
    {
        return Ok(());
    }
    let record: RecordedExchange = serde_json::from_value(event.clone())?;
    let value = record
        .value
        .as_ref()
        .map(RecordedCapture::decode)
        .transpose()?;
    let mut source: serde_json::Value =
        serde_json::from_slice(&source_witness(event, Surface::DependencyRequest)?)?;
    let clocks = contracts.contract_clocks(
        Some(case),
        source_start(&record),
        None,
        Some(record.timestamp),
        None,
    );
    if matches!(
        record.command.to_ascii_lowercase().as_str(),
        "set" | "add" | "replace" | "cas"
    ) && value.is_some()
    {
        if let (Some(value), Some(global)) = (&value, contracts.global_json())
            && crate::json_value::parse(value).is_some()
        {
            let checked = crate::value_contract::response_delivery::Delivery::prepare_global(
                value, global, clocks,
            )?;
            contracts.observe_value_slot_applicable(checked.validation().evaluated.clone());
        }
        contracts.record_value_witness(
            metadata(
                &record,
                case,
                Surface::DependencyRequest,
                TargetRole::Unavailable,
                clocks,
            ),
            &serde_json::to_vec(&source)?,
            None,
        )?;
    }
    if matches!(record.command.as_str(), "get" | "gets") {
        let frames = record
            .response_frames
            .iter()
            .map(RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        let slots = if contracts.global_json().is_none() {
            Vec::new()
        } else if record.no_response || record.outcome == DependencyExchangeOutcome::NoResponse {
            anyhow::ensure!(
                frames.is_empty(),
                "no-response Memcached evidence contains response bytes"
            );
            Vec::new()
        } else {
            anyhow::ensure!(
                record.outcome == DependencyExchangeOutcome::Response,
                "Memcached value contract requires complete response evidence"
            );
            crate::memcached::value_slot::extract(&frames, &record.wire_protocol)?
        };
        let mut applicable = std::collections::BTreeSet::new();
        for slot in slots {
            let payload = &frames[slot.frame][slot.payload];
            let Some(global) = contracts
                .global_json()
                .filter(|_| crate::json_value::parse(payload).is_some())
            else {
                continue;
            };
            let checked = crate::value_contract::response_delivery::Delivery::prepare_global(
                payload, global, clocks,
            )?;
            applicable.extend(checked.validation().evaluated.iter().cloned());
        }
        contracts.observe_value_slot_applicable(applicable);
        source["response_frames"] = encoded_frames(&frames);
        source["outcome"] = serde_json::to_value(record.outcome)?;
        source["no_response"] = record.no_response.into();
        contracts.record_value_witness(
            metadata(
                &record,
                case,
                Surface::DependencyResponse,
                TargetRole::Unavailable,
                clocks,
            ),
            &serde_json::to_vec(&source)?,
            None,
        )?;
    }
    Ok(())
}

pub(super) fn source_start(record: &RecordedExchange) -> Option<DateTime<Utc>> {
    record.request_started_at.or_else(|| {
        if record.timestamp == DateTime::UNIX_EPOCH {
            return None;
        }
        i64::try_from(record.duration_ms).ok().and_then(|duration| {
            record
                .timestamp
                .checked_sub_signed(chrono::Duration::milliseconds(duration))
        })
    })
}

fn metadata(
    record: &RecordedExchange,
    case: &str,
    surface: Surface,
    target_role: TargetRole,
    clocks: crate::value_contract::json::AnchorClocks,
) -> WitnessMetadata {
    let pair = |pair: crate::value_contract::time::ClockPair| crate::policy_evidence::ClockPair {
        source: pair.source,
        target: pair.target,
    };
    WitnessMetadata {
        surface,
        source_role: if surface == Surface::DependencyRequest {
            SourceRole::DependencyRequest
        } else {
            SourceRole::DependencyResponse
        },
        target_role,
        source: SourceIdentity {
            case_id: case.into(),
            exchange_id: None,
            connection_id: Some(record.connection_id.to_string()),
            sequence: Some(record.sequence),
        },
        resource: Some(crate::policy::Resource {
            protocol: Protocol::Memcached,
            endpoint: crate::policy::Endpoint {
                host: record.target_host.clone(),
                port: record.target_port,
            },
            database: None,
            username: None,
        }),
        operation: record.command.to_ascii_uppercase(),
        slot: Slot::Value,
        clocks: crate::policy_evidence::WitnessClocks {
            case: pair(clocks.case),
            dependency: pair(clocks.dependency),
            delivery: pair(clocks.delivery),
        },
    }
}

fn request_envelope(exchange: &ReplayExchange) -> serde_json::Value {
    let mut document = envelope(
        &exchange.record.wire_protocol,
        &exchange.record.command,
        exchange.key.as_deref(),
        &exchange.args,
        exchange.value.as_deref(),
        exchange.extras.as_deref(),
        exchange.record.cas,
        exchange.record.quiet,
        exchange.record.noreply,
    );
    document["opcode"] = serde_json::json!(exchange.record.opcode);
    document["observed_at"] = serde_json::json!(exchange.record.timestamp);
    document["request_started_at"] = serde_json::json!(source_start(&exchange.record));
    document
}

#[allow(clippy::too_many_arguments)]
fn envelope(
    wire: &str,
    command: &str,
    key: Option<&[u8]>,
    args: &[Vec<u8>],
    value: Option<&[u8]>,
    extras: Option<&[u8]>,
    cas: Option<u64>,
    quiet: bool,
    noreply: bool,
) -> serde_json::Value {
    serde_json::json!({ "protocol":"memcached", "wire_protocol":wire, "command":command.to_ascii_uppercase(),
        "key":key.map(|value| STANDARD.encode(value)), "args":args.iter().map(|value| STANDARD.encode(value)).collect::<Vec<_>>(),
        "value":value.map(|value| STANDARD.encode(value)), "extras":extras.map(|value| STANDARD.encode(value)),
        "cas":cas,"quiet":quiet,"noreply":noreply })
}

fn encoded_frames(frames: &[Vec<u8>]) -> serde_json::Value {
    serde_json::Value::Array(
        frames
            .iter()
            .map(|frame| serde_json::Value::String(STANDARD.encode(frame)))
            .collect(),
    )
}

#[cfg(test)]
mod tests;
