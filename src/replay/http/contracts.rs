//! JSON/PB body contracts never own HTTP identity, headers, snapshots or claims.
use super::*;
use crate::policy::{Slot, Surface};
use crate::policy_evidence::{SourceIdentity, SourceRole, TargetRole, WitnessMetadata};
use crate::value_contract::json::AnchorClocks;
mod witness;
pub(crate) use witness::{
    source_witness, validate_witness, witness_matches, witness_metadata_matches, witness_value,
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
    if owner.compiled_rules().is_none() || !owner.retains_value_witnesses() {
        return Ok(crate::policy_evidence::ObservationRetention::Retained);
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

pub(super) fn preview_request(
    policy: &ReplayPolicyRuntime,
    exchange: &ReplayHttpExchange,
    actual: &RequestView<'_>,
    validated_query_params: &[String],
) -> Option<Result<crate::replay::policy::request_contract::Decision>> {
    if exchange.source != ReplaySource::Case || exchange.shared_origin.is_some() {
        return None;
    }
    let rules = policy.request_contracts.http_value_rules(
        Surface::DependencyRequest,
        exchange.case_id.as_deref(),
        &exchange.identity.target,
        actual.method.as_str(),
        actual.uri.path(),
    );
    if rules.is_empty() {
        return None;
    }
    Some((|| {
        anyhow::ensure!(
            uri_mismatch_reason(
                &exchange.record.uri,
                &actual.uri.to_string(),
                validated_query_params
            )
            .is_none(),
            "HTTP body contract preserves path and unowned query parameters"
        );
        let source = decode_body(&exchange.record.request_body)?;
        let clocks = policy.request_contracts.contract_clocks(
            exchange.case_id.as_deref(),
            request_headers::time_reference::source(&exchange.record),
            Some(actual.started_at),
            None,
            None,
        );
        let comparison =
            crate::replay::contract_value::compare(&source, actual.body, &rules, clocks)?;
        anyhow::ensure!(
            comparison.passed(),
            "HTTP request body contract failed: {:?}",
            comparison.differences
        );
        Ok(crate::replay::policy::request_contract::Decision::from_value_comparison(comparison))
    })())
}

pub(super) fn materialize_response(
    policy: &ReplayPolicyRuntime,
    exchange: &mut ReplayHttpExchange,
    request_started_at: chrono::DateTime<Utc>,
) -> Result<DependencyRuleDecision> {
    let mut decision = DependencyRuleDecision::default();
    if policy.request_contracts.compiled_rules().is_none()
        || exchange.source != ReplaySource::Case
        || exchange.shared_origin.is_some()
        || exchange.record.outcome.is_client_terminated()
    {
        return Ok(decision);
    }
    let Some(case) = exchange.case_id.as_deref() else {
        return Ok(decision);
    };
    let rules = policy.request_contracts.http_value_rules(
        Surface::DependencyResponse,
        Some(case),
        &exchange.identity.target,
        &exchange.record.method,
        &uri_path_only(&exchange.record.uri),
    );
    let source = witness::from_record(&exchange.record, Surface::DependencyResponse)?;
    let Some(payload) = witness_value(&serde_json::to_vec(&source)?, Surface::DependencyResponse)?
    else {
        return Ok(decision);
    };
    let delivered_at = Utc::now();
    let clocks = policy.request_contracts.contract_clocks(
        Some(case),
        request_headers::time_reference::source(&exchange.record),
        Some(request_started_at),
        exchange.record.timestamp,
        Some(delivered_at),
    );
    let value = if rules.is_empty() {
        payload.clone()
    } else {
        if rules.iter().any(|rule| !rule.delivery_time.is_empty()) {
            anyhow::ensure!(
                !witness::has_integrity_headers(exchange.record.response_headers.as_ref()),
                "HTTP body rebase requires a typed owner for its payload digest or signature headers"
            );
        }
        let delivery = crate::replay::contract_value::Delivery::prepare(&payload, &rules, clocks)?;
        let value = delivery.render(delivered_at)?;
        decision.value_contracts.push(
            crate::replay::policy::request_contract::Decision::from_value_comparison(
                delivery.validation().clone(),
            ),
        );
        value
    };
    let native_headers = response_headers_for_payload(
        exchange.record.response_headers.as_ref(),
        value.len(),
        delivered_at,
    );
    let mut target = source.clone();
    target["response_body"] = STANDARD.encode(&value).into();
    target["response_headers"] = serde_json::to_value(request_headers::capture(&native_headers))?;
    target["response_delivered_at"] = serde_json::to_value(delivered_at)?;
    validate_witness(
        &serde_json::to_vec(&source)?,
        &serde_json::to_vec(&target)?,
        Surface::DependencyResponse,
        clocks,
    )?;
    policy.request_contracts.record_value_witness(
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
    exchange.record.response_body = Some(RecordedBodyCapture {
        encoding: "base64".into(),
        truncated: false,
        data: STANDARD.encode(value),
    });
    exchange.record.response_headers = Some(request_headers::capture(&native_headers));
    Ok(decision)
}

pub(in crate::replay) fn observe_source(
    contracts: &crate::replay::policy::request_contract::RequestContracts,
    case: &str,
    event: &Value,
    key_context: &std::path::Path,
) -> Result<()> {
    let mut record: RecordedHttpExchange = serde_json::from_value(event.clone())?;
    record.decrypt_request_headers(key_context)?;
    let identity = identity_from_record(&record)?;
    let clocks = contracts.contract_clocks(
        Some(case),
        request_headers::time_reference::source(&record),
        None,
        record.timestamp,
        None,
    );
    for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
        let rules = contracts.http_value_rules(
            surface,
            Some(case),
            &identity.target,
            &record.method,
            &uri_path_only(&record.uri),
        );
        let source = witness::from_record(&record, surface)?;
        let bytes = serde_json::to_vec(&source)?;
        match witness_value(&bytes, surface)? {
            Some(payload) => {
                if !rules.is_empty() {
                    let validation =
                        crate::replay::contract_value::Delivery::prepare(&payload, &rules, clocks)?;
                    contracts.observe_value_slot_applicable(
                        validation.validation().evaluated.iter().cloned(),
                    );
                }
            }
            None => contracts
                .observe_value_slot_unavailable(rules.iter().map(|rule| rule.rule.id.clone())),
        }
        contracts.record_value_witness(
            metadata(&record, case, surface, TargetRole::Unavailable, clocks)?,
            &bytes,
            None,
        )?;
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
        operation: record.method.to_ascii_uppercase(),
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
