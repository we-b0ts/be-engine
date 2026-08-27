use chrono::{DateTime, Utc};
use motan_protocol::{Frame, ProtocolVersion};
use serde::Serialize;
use tracing::{info, warn};

use crate::motan::response_kind_label;
use crate::recorder::{
    CaseBodyCapture, CaseContext, CaseInvalidation, PrimaryCaseDescriptor, Recorder,
    capture_case_body,
};
use crate::{ActiveCaseActivationError, ActiveCaseGuard, ActiveCaseRejection, AppState};

#[derive(Serialize)]
struct MotanCaseAdmissionRecord<'a> {
    timestamp: DateTime<Utc>,
    case_id: uuid::Uuid,
    rule_name: &'a str,
    api_key: &'a str,
    upstream: &'a str,
}

#[derive(Serialize)]
pub(super) struct MotanCaseRequestRecord {
    timestamp: DateTime<Utc>,
    client_addr: Option<String>,
    method: &'static str,
    uri: String,
    api_pattern: String,
    protocol_version: &'static str,
    request_id: u64,
    api_key: String,
    matched_rule: String,
    upstream: String,
    frame: CaseBodyCapture,
}

#[derive(Serialize)]
pub(super) struct MotanCaseResponseRecord {
    timestamp: DateTime<Utc>,
    protocol_version: &'static str,
    response_expected: bool,
    status: Option<&'static str>,
    frame: Option<CaseBodyCapture>,
    duration_ms: u128,
    error: Option<String>,
}

pub(super) async fn try_admit_case(
    state: &AppState,
    case: &CaseContext,
    descriptor: &PrimaryCaseDescriptor,
    max_cases: usize,
    upstream: &str,
) -> Option<ActiveCaseGuard> {
    let published_cases = state.recorder().published_case_count(case).await;
    if published_cases >= max_cases {
        info!(
            reason = "case_limit_reached",
            rule = %case.rule_name,
            api_key = %descriptor.api_key,
            published_cases,
            max_cases,
            "Motan gateway matched request sent to fixed response"
        );
        return None;
    }

    match state.try_reserve_active_case(case.clone()) {
        Ok(guard) => {
            if let Err(error) = state
                .seal_bootstrap_dependencies("Motan gateway case admission")
                .await
            {
                warn!(%error, case_id = %case.id, "failed to seal bootstrap dependencies");
                return None;
            }
            let admission = MotanCaseAdmissionRecord {
                timestamp: Utc::now(),
                case_id: case.id,
                rule_name: &case.rule_name,
                api_key: &descriptor.api_key,
                upstream,
            };
            for (filename, value) in [
                ("admission.json", serde_json::to_value(&admission)),
                ("case.json", serde_json::to_value(descriptor)),
            ] {
                let value = match value {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(%error, case_id = %case.id, "failed to serialize Motan case metadata");
                        discard_unadmitted_case(state, case).await;
                        return None;
                    }
                };
                if let Err(error) = state
                    .recorder()
                    .write_case_json(case, filename, &value)
                    .await
                {
                    warn!(%error, case_id = %case.id, filename, "failed to persist Motan case metadata");
                    discard_unadmitted_case(state, case).await;
                    return None;
                }
            }
            if let Err(reason) = state.activate_case_dependencies(&guard) {
                info!(
                    reason = activation_error(reason),
                    rule = %case.rule_name,
                    api_key = %descriptor.api_key,
                    "Motan gateway case admission stopped before dependency activation"
                );
                discard_unadmitted_case(state, case).await;
                return None;
            }
            info!(
                case_id = %case.id,
                rule = %case.rule_name,
                api_key = %descriptor.api_key,
                upstream,
                "registered active Motan gateway case"
            );
            Some(guard)
        }
        Err(reason) => {
            info!(
                reason = rejection_reason(reason),
                rule = %case.rule_name,
                api_key = %descriptor.api_key,
                "Motan gateway matched request sent to fixed response"
            );
            None
        }
    }
}

pub(super) fn request_record(
    state: &AppState,
    request: &Frame,
    client_addr: Option<String>,
    descriptor: &PrimaryCaseDescriptor,
    matched_rule: &str,
    upstream: &str,
) -> MotanCaseRequestRecord {
    let api_pattern = format!("/rpc/{}", super::rules::api_directory(descriptor));
    MotanCaseRequestRecord {
        timestamp: Utc::now(),
        client_addr,
        method: "MOTAN",
        uri: api_pattern.clone(),
        api_pattern,
        protocol_version: protocol_version(request.version),
        request_id: request.request_id,
        api_key: descriptor.api_key.clone(),
        matched_rule: matched_rule.to_string(),
        upstream: upstream.to_string(),
        frame: capture_case_body(
            request.raw(),
            state.config().recording.max_body_bytes,
            state.config().recording.decoded_body_limit(),
            None,
        ),
    }
}

pub(super) fn response_record(
    state: &AppState,
    request: &Frame,
    response: Option<&Frame>,
    duration_ms: u128,
    error: Option<String>,
) -> MotanCaseResponseRecord {
    MotanCaseResponseRecord {
        timestamp: Utc::now(),
        protocol_version: protocol_version(request.version),
        response_expected: !request.flags.oneway(),
        status: response.map(|frame| response_kind_label(frame.response_kind())),
        frame: response.map(|frame| {
            capture_case_body(
                frame.raw(),
                state.config().recording.max_body_bytes,
                state.config().recording.decoded_body_limit(),
                None,
            )
        }),
        duration_ms,
        error,
    }
}

pub(super) async fn finalize_case(
    recorder: &Recorder,
    case: &CaseContext,
    request: MotanCaseRequestRecord,
    response: MotanCaseResponseRecord,
    invalidation: Option<CaseInvalidation>,
) -> anyhow::Result<()> {
    if let Some(invalidation) = invalidation {
        recorder
            .write_case_json(case, "request.json.invalid", &request)
            .await?;
        recorder
            .write_case_json(case, "expected-response.json.invalid", &response)
            .await?;
        return recorder
            .fail_case_with_context(
                case,
                invalidation.reason,
                invalidation.message,
                invalidation.context,
            )
            .await;
    }
    if let Some((reason, message)) = invalid_case_reason(&request, &response) {
        recorder
            .write_case_json(case, "request.json.partial", &request)
            .await?;
        recorder
            .write_case_json(case, "expected-response.json.partial", &response)
            .await?;
        return recorder.fail_case(case, reason, message).await;
    }
    recorder
        .write_case_json(case, "request.json", &request)
        .await?;
    recorder
        .write_case_json(case, "expected-response.json", &response)
        .await?;
    if let Some(message) = recorder.case_dependency_safety_issue(case).await? {
        return recorder
            .fail_case(case, "dependency_replay_unsafe", message)
            .await;
    }
    recorder
        .publish_case_for_api(case, Some(&format!("MOTAN {}", request.api_pattern)))
        .await
}

fn invalid_case_reason(
    request: &MotanCaseRequestRecord,
    response: &MotanCaseResponseRecord,
) -> Option<(&'static str, String)> {
    if request.frame.truncated {
        return Some((
            "request_frame_truncated",
            format!(
                "Motan request frame exceeded recording limit: wire_len={} stored_len={} limit_bytes={}",
                request.frame.original_len, request.frame.stored_len, request.frame.limit_bytes
            ),
        ));
    }
    if let Some(error) = &response.error {
        return Some(("upstream_response_error", error.clone()));
    }
    if response.response_expected && response.frame.is_none() {
        return Some((
            "expected_response_missing",
            "Motan upstream returned no response".to_string(),
        ));
    }
    if response.frame.as_ref().is_some_and(|frame| frame.truncated) {
        return Some((
            "expected_response_frame_truncated",
            "Motan response frame exceeded the recording limit".to_string(),
        ));
    }
    None
}

async fn discard_unadmitted_case(state: &AppState, case: &CaseContext) {
    if let Err(error) = state.recorder().discard_unadmitted_case(case).await {
        warn!(%error, case_id = %case.id, "failed to discard unadmitted Motan case");
    }
}

fn protocol_version(version: ProtocolVersion) -> &'static str {
    match version {
        ProtocolVersion::Motan1 => "motan1",
        ProtocolVersion::Motan2 => "motan2",
    }
}

fn rejection_reason(reason: ActiveCaseRejection) -> &'static str {
    match reason {
        ActiveCaseRejection::NotReady => "not_ready",
        ActiveCaseRejection::Busy => "busy",
        ActiveCaseRejection::Quiescing => "quiescing",
    }
}

fn activation_error(reason: ActiveCaseActivationError) -> &'static str {
    match reason {
        ActiveCaseActivationError::Quiescing => "quiescing",
        ActiveCaseActivationError::ReservationMissing => "reservation_missing",
    }
}
