//! JSON/PB body contracts never own HTTP identity, headers, snapshots or claims.
use super::*;
use crate::policy::{Slot, Surface};
use crate::policy_evidence::{SourceIdentity, SourceRole, TargetRole, WitnessMetadata};
use crate::value_contract::json::AnchorClocks;
#[cfg(test)]
mod attachment_tests;
mod headers;
mod prefix;
mod stream;
pub(in crate::protocols::replay::http) mod time_copies;
mod witness;
pub(crate) use witness::{
    multipart_witness_matches, source_witness, validate_witness, witness_metadata_matches,
    witness_value,
};

pub(super) struct RequestView<'a> {
    pub(super) observation_id: Option<uuid::Uuid>,
    pub(super) scheme: HttpReplayScheme,
    pub(super) target: &'a TargetKey,
    pub(super) method: &'a Method,
    pub(super) uri: &'a Uri,
    pub(super) headers: &'a HeaderSnapshot,
    pub(super) body: &'a [u8],
    pub(super) started_at: chrono::DateTime<Utc>,
}

pub(super) fn record_request(
    policy: &ReplayPolicyRuntime,
    exchange: &ReplayHttpExchange,
    actual: &RequestView<'_>,
) -> Result<()> {
    if policy.request_contracts.compiled_rules().is_none()
        || exchange.source != ReplaySource::Case
        || exchange.shared_origin.is_some()
    {
        return Ok(());
    }
    let Some(case) = exchange.case_id.as_deref() else {
        return Ok(());
    };
    let Some(observation_id) = actual.observation_id else {
        return Ok(());
    };
    let clocks = policy.request_contracts.contract_clocks(
        Some(case),
        request_headers::time_reference::source(&exchange.record),
        Some(actual.started_at),
        None,
        None,
    );
    let metadata = metadata(
        &exchange.record,
        case,
        Surface::DependencyRequest,
        TargetRole::IndependentTargetObservation,
        clocks,
    )?;
    let id = observation_id.to_string();
    if policy
        .request_contracts
        .associate_value_witness(&metadata, &id, None)?
        == crate::policy_evidence::AssociationOutcome::SourceRequired
    {
        let source = serde_json::to_vec(&witness::from_record(
            &exchange.record,
            Surface::DependencyRequest,
        )?)?;
        policy
            .request_contracts
            .associate_value_witness(&metadata, &id, Some(&source))?;
    }
    Ok(())
}

pub(super) fn record_target(
    policy: &ReplayPolicyRuntime,
    case: &str,
    actual: &RequestView<'_>,
) -> Result<crate::policy_evidence::ObservationRetention> {
    let owner = &policy.request_contracts;
    if !owner.retains_value_witnesses() {
        return Ok(crate::policy_evidence::ObservationRetention::Unavailable);
    }
    let target = serde_json::json!({"protocol":"http", "exchange_id":actual.observation_id,
        "scheme":actual.scheme, "endpoint":{"host":actual.target.host,"port":actual.target.port},
        "method":actual.method.as_str().to_ascii_uppercase(), "uri":actual.uri.to_string(),
        "request_headers":actual.headers, "request_body":STANDARD.encode(actual.body),
        "request_started_at":actual.started_at});
    owner.record_independent_request(
        &actual
            .observation_id
            .context("HTTP Target observation identity is missing")?
            .to_string(),
        case,
        Some(crate::policy::Resource {
            protocol: crate::policy::Protocol::Http,
            endpoint: crate::policy::Endpoint {
                host: actual.target.host.clone(),
                port: actual.target.port,
            },
            database: None,
            username: None,
        }),
        actual.method.as_str(),
        actual.started_at,
        &serde_json::to_vec(&target)?,
    )
}

pub(super) fn record_unanchored_target(
    observations: &crate::replay::TargetObservations,
    case: Option<&str>,
    actual: &RequestView<'_>,
) -> Result<crate::policy_evidence::ObservationRetention> {
    let target = serde_json::json!({"protocol":"http", "exchange_id":actual.observation_id,
        "scheme":actual.scheme,"endpoint":{"host":actual.target.host,"port":actual.target.port},
        "method":actual.method.as_str().to_ascii_uppercase(),"uri":actual.uri.to_string(),
        "request_headers":actual.headers,"request_body":STANDARD.encode(actual.body),"request_started_at":actual.started_at});
    observations.record(
        actual
            .observation_id
            .context("HTTP Target observation identity missing")?,
        case,
        Some(crate::policy::Resource {
            protocol: crate::policy::Protocol::Http,
            endpoint: crate::policy::Endpoint {
                host: actual.target.host.clone(),
                port: actual.target.port,
            },
            database: None,
            username: None,
        }),
        actual.method.as_str(),
        actual.started_at,
        &serde_json::to_vec(&target)?,
    )
}

pub(super) fn preview_request(
    policy: &ReplayPolicyRuntime,
    exchange: &ReplayHttpExchange,
    active_case: Option<&str>,
    actual: &RequestView<'_>,
    validated_query_params: &[String],
    diagnostic: &mut Option<Value>,
    allow_pre_match: bool,
) -> Option<Result<crate::policy::runtime::request_contract::Decision>> {
    let ordinary = exchange.source == ReplaySource::Case && exchange.shared_origin.is_none();
    let mut owner = if allow_pre_match && ordinary {
        policy.request_contracts.with_hypothesis_context(
            crate::policy::runtime::request_contract::HypothesisContext {
                carrier: "json".into(),
                source_reference: serde_json::json!({"exchange_id":exchange.record.native.id}),
                target_observation_id: actual.observation_id.map(|id| id.to_string()),
            },
        )
    } else {
        policy.request_contracts.clone()
    };
    if !allow_pre_match || !ordinary {
        owner.configure_pre_match(false);
    }
    if !ordinary
        && policy.request_contracts.global_json().is_none()
        && policy
            .request_contracts
            .compiled_rules()
            .is_none_or(|policy| policy.http.is_none())
    {
        return None;
    }
    let case = if ordinary {
        exchange.case_id.as_deref()
    } else {
        active_case
    }?;
    let global = owner.global_json()?;
    let mut owns_body = true;
    let result = (|| {
        anyhow::ensure!(
            uri_mismatch_reason(
                &exchange.record.native.uri,
                &actual.uri.to_string(),
                validated_query_params
            )
            .is_none(),
            "HTTP body contract preserves path and unowned query parameters"
        );
        let source = decode_body(&exchange.record.native.request_body)?;
        if global.fields.is_empty() && source == actual.body {
            owns_body = false;
            return Ok(crate::policy::runtime::request_contract::Decision::default());
        }
        let clocks = policy.request_contracts.contract_clocks(
            Some(case),
            request_headers::time_reference::source(&exchange.record),
            Some(actual.started_at),
            None,
            None,
        );
        let comparison =
            owner.compare_global_case_value(case, &source, actual.body, &[], clocks)?;
        // An empty automatic plan must preserve ordinary strict comparison and
        // its discovery diagnostics when Source has no semantic field owner.
        owns_body = !comparison.evaluated.is_empty() || !comparison.pre_matches.is_empty();
        if !owns_body {
            return Ok(crate::policy::runtime::request_contract::Decision::default());
        }
        *diagnostic = Some(serde_json::json!({
            "source_exchange_id":exchange.record.native.id,
            "selected_rule_ids":comparison.evaluated,
            "comparison":comparison,
            "passed":comparison.passed(),
            "source_comparison_body_sha256":crate::policy_evidence::digest(&source),
            "target_comparison_body_sha256":crate::policy_evidence::digest(actual.body),
            "origin":"runtime_shared_value_contract_comparator"
        }));
        anyhow::ensure!(
            comparison.passed(),
            "HTTP request body contract failed: {:?}",
            comparison.differences
        );
        let identity = policy
            .request_contracts
            .identity_decision(case, &comparison)?;
        let mut decision =
            crate::policy::runtime::request_contract::Decision::from_value_comparison(comparison);
        decision.identity = Some(identity);
        Ok(decision)
    })();
    owns_body.then_some(result)
}

pub(super) fn materialize_response(
    owner: &crate::policy::runtime::request_contract::RequestContracts,
    exchange: &mut ReplayHttpExchange,
    active_case: Option<&str>,
    request_started_at: chrono::DateTime<Utc>,
) -> Result<DependencyRuleDecision> {
    if exchange.record.cleanup_authorized && exchange.record.native.response_stream.is_some() {
        return prefix::materialize(owner, exchange, active_case, request_started_at);
    }
    let mut decision = DependencyRuleDecision::default();
    if owner.compiled_rules().is_none()
        || upstream_failure::is_recorded(&exchange.record)
        || exchange.record.native.outcome.is_client_terminated()
        || exchange.record.native.outcome.is_server_terminated()
    {
        return Ok(decision);
    }
    let ordinary = exchange.source == ReplaySource::Case && exchange.shared_origin.is_none();
    if !ordinary
        && owner.global_json().is_none()
        && owner
            .compiled_rules()
            .is_none_or(|policy| policy.http.is_none())
    {
        return Ok(decision);
    }
    let Some(case) = (if ordinary {
        exchange.case_id.as_deref()
    } else {
        active_case
    }) else {
        return Ok(decision);
    };
    let source = witness::from_record(&exchange.record, Surface::DependencyResponse)?;
    let payload_slot = witness_value(&serde_json::to_vec(&source)?, Surface::DependencyResponse)?;
    let payload = payload_slot.clone().unwrap_or_default();
    let delivered_at = Utc::now();
    let clocks = owner.contract_clocks(
        Some(case),
        request_headers::time_reference::source(&exchange.record),
        Some(request_started_at),
        exchange.record.native.timestamp,
        Some(delivered_at),
    );
    let value = materialize_value(owner, case, &payload, clocks, delivered_at, &mut decision)?;
    if value != payload {
        anyhow::ensure!(
            !witness::has_integrity_headers(exchange.record.native.response_headers.as_ref()),
            "HTTP body rebase requires a typed owner for its payload digest or signature headers"
        );
    }
    let mut native_headers = response_headers_for_payload(
        exchange.record.native.response_headers.as_ref(),
        value.len(),
        delivered_at,
    );
    let expected_native_headers = request_headers::capture(&native_headers);
    if let Some(validation) = headers::materialize(
        owner,
        case,
        exchange.record.native.response_headers.as_ref(),
        &mut native_headers,
        clocks,
        delivered_at,
    )? {
        decision.value_contracts.push(validation);
    }
    anyhow::ensure!(
        expected_native_headers == request_headers::capture(&native_headers)
            || !witness::has_integrity_headers(exchange.record.native.response_headers.as_ref()),
        "HTTP header rebase requires a typed owner for its digest or signature headers"
    );
    let mut target = source.clone();
    if payload_slot.is_some() {
        target["response_body"] = STANDARD.encode(&value).into();
    }
    target["response_headers"] = serde_json::to_value(request_headers::capture(&native_headers))?;
    target["response_delivered_at"] = serde_json::to_value(delivered_at)?;
    validate_witness(
        &serde_json::to_vec(&source)?,
        &serde_json::to_vec(&headers::native_validation_target(
            &target,
            &expected_native_headers,
            owner,
        )?)?,
        Surface::DependencyResponse,
        clocks,
    )?;
    if ordinary {
        if let Some(plan) = owner.global_json() {
            exchange.time_copy_delivery = Some(time_copies::prepare(
                exchange, &payload, &value, plan, clocks,
            )?);
        }
        owner.record_value_witness(
            metadata(
                &exchange.record,
                case,
                Surface::DependencyResponse,
                TargetRole::DerivedDelivery,
                clocks,
            )?,
            &serde_json::to_vec(&source)?,
            Some(&serde_json::to_vec(&target)?),
        )?;
    }
    if value != payload
        && let Some(stream) = &mut exchange.record.native.response_stream
    {
        stream::remap(stream, &payload, &value)?;
    }

    if payload_slot.is_some() {
        exchange.record.native.response_body = Some(RecordedBodyCapture {
            encoding: "base64".into(),
            truncated: false,
            stored_len: Some(value.len()),
            data: STANDARD.encode(value),
        });
    }
    exchange.record.native.response_headers = Some(request_headers::capture(&native_headers));
    Ok(decision)
}

/// Render only fully decoded values. Unknown/partial payloads keep exact bytes.
fn materialize_value(
    owner: &crate::policy::runtime::request_contract::RequestContracts,
    case: &str,
    payload: &[u8],
    clocks: AnchorClocks,
    delivered_at: chrono::DateTime<Utc>,
    decision: &mut DependencyRuleDecision,
) -> Result<Vec<u8>> {
    if owner
        .global_json()
        .is_none_or(|plan| plan.fields.is_empty())
    {
        return Ok(payload.to_vec());
    }
    let global = owner
        .global_json()
        .filter(|_| crate::json_value::parse(payload).is_some());
    let sse = owner
        .global_json()
        .filter(|_| crate::value_codec::sse::Document::decode(payload).is_ok());
    let value = if let Some(plan) = sse {
        let delivery = crate::replay::contract_value::SseDelivery::prepare(payload, plan, clocks)?;
        let (value, validation) = delivery.render(delivered_at, owner, case)?;
        decision.value_contracts.push(validation.into());
        value
    } else if global.is_none() {
        payload.to_vec()
    } else {
        let delivery = crate::replay::contract_value::Delivery::prepare_global(
            payload,
            global.context("JSON field plan missing")?,
            clocks,
        )?;
        let mut validation =
            crate::policy::runtime::request_contract::Decision::from_value_comparison(
                delivery.validation().clone(),
            );
        let value = if delivery.has_identities() {
            let (value, identity) = delivery.render_with_identities(delivered_at, owner, case)?;
            validation.identity = Some(identity);
            value
        } else {
            delivery.render(delivered_at)?
        };
        decision.value_contracts.push(validation);
        value
    };
    Ok(value)
}

pub(crate) fn observe_source(
    contracts: &crate::policy::runtime::request_contract::RequestContracts,
    case: &str,
    event: &Value,
    key_context: &std::path::Path,
) -> Result<()> {
    let mut record: RecordedHttpExchange = serde_json::from_value(event.clone())?;
    record.decrypt_request_headers(key_context)?;
    let clocks = contracts.contract_clocks(
        Some(case),
        request_headers::time_reference::source(&record),
        None,
        record.native.timestamp,
        None,
    );
    for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
        if surface == Surface::DependencyResponse && upstream_failure::is_recorded(&record) {
            // The proxy-generated 502 has no upstream header/body format slot.
            // Its finite request is still compared and consumed normally.
            continue;
        }
        if let Some(plan) = contracts
            .compiled_rules()
            .and_then(|policy| policy.http.as_ref())
        {
            let headers = if surface == Surface::DependencyRequest {
                Some(&record.native.request_headers)
            } else {
                record.native.response_headers.as_ref()
            };
            if let Some(headers) = headers {
                let validation =
                    crate::value_contract::http_headers::compare(headers, headers, plan, clocks)?;
                anyhow::ensure!(validation.passed(), "Source HTTP header shape is invalid");
                contracts.observe_value_slot_applicable(validation.evaluated);
            }
        }
        if surface == Surface::DependencyResponse
            && (record.native.outcome != crate::DependencyExchangeOutcome::Response
                || record.native.error.is_some()
                || record
                    .native
                    .response_stream
                    .as_ref()
                    .is_some_and(|stream| !stream.complete))
        {
            // Captured prefixes may prove decoded field shapes, but never a
            // complete dependency response for independent plan witnesses.
            if let Some(body) = &record.native.response_body {
                observe_known_value(contracts, &decode_body(body)?, clocks)?;
            }
            continue;
        }
        let source = witness::from_record(&record, surface)?;
        let bytes = serde_json::to_vec(&source)?;
        if let Some(payload) = witness_value(&bytes, surface)? {
            observe_known_value(contracts, &payload, clocks)?;
        }
        contracts.record_value_witness(
            metadata(&record, case, surface, TargetRole::Unavailable, clocks)?,
            &bytes,
            None,
        )?;
    }
    Ok(())
}

fn observe_known_value(
    contracts: &crate::policy::runtime::request_contract::RequestContracts,
    payload: &[u8],
    clocks: AnchorClocks,
) -> Result<()> {
    if contracts
        .global_json()
        .is_none_or(|plan| plan.fields.is_empty())
    {
        return Ok(());
    }
    if let Some(global) = contracts
        .global_json()
        .filter(|_| crate::json_value::parse(payload).is_some())
    {
        let validation =
            crate::replay::contract_value::Delivery::prepare_global(payload, global, clocks)?;
        contracts.observe_value_slot_applicable(validation.validation().evaluated.iter().cloned());
    } else if let Some(plan) = contracts
        .global_json()
        .filter(|_| crate::value_codec::sse::Document::decode(payload).is_ok())
    {
        let validation =
            crate::replay::contract_value::SseDelivery::prepare(payload, plan, clocks)?;
        contracts.observe_value_slot_applicable(validation.validation().evaluated.iter().cloned());
    }
    Ok(())
}

fn metadata(
    record: &RecordedHttpExchange,
    case: &str,
    surface: Surface,
    target_role: TargetRole,
    clocks: AnchorClocks,
) -> Result<WitnessMetadata> {
    let identity = identity_from_record(record)?;
    let id = record
        .native
        .id
        .as_deref()
        .filter(|id| !id.is_empty())
        .context("HTTP value witness requires original http_exchange.id")?;
    let pair = |pair: crate::value_contract::time::ClockPair| crate::policy_evidence::ClockPair {
        source: pair.source,
        target: pair.target,
    };
    Ok(WitnessMetadata {
        surface,
        source_role: if surface == Surface::DependencyRequest {
            SourceRole::DependencyRequest
        } else {
            SourceRole::DependencyResponse
        },
        target_role,
        source: SourceIdentity {
            case_id: case.into(),
            exchange_id: Some(id.into()),
            connection_id: None,
            sequence: None,
        },
        resource: Some(crate::policy::Resource {
            protocol: crate::policy::Protocol::Http,
            endpoint: crate::policy::Endpoint {
                host: identity.target.host,
                port: identity.target.port,
            },
            database: None,
            username: None,
        }),
        operation: record.native.method.to_ascii_uppercase(),
        slot: Slot::Body,
        clocks: crate::policy_evidence::WitnessClocks {
            case: pair(clocks.case),
            dependency: pair(clocks.dependency),
            delivery: pair(clocks.delivery),
        },
    })
}

#[cfg(test)]
mod tests;
