use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::http::sse::{SseObservation, SseObservationPolicy};
use crate::recorder::{
    CaseBodyCapture, CaseContext, CaseInvalidation, HeaderMapSnapshot, Recorder,
};

#[derive(Serialize)]
pub(crate) struct CaseRequestRecord {
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) client_addr: Option<String>,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) api_pattern: Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) upstream: String,
    pub(crate) headers: HeaderMapSnapshot,
    pub(crate) body: CaseBodyCapture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sse_observation: Option<SseObservationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) interaction: Option<crate::interaction::model::InputTranscript>,
}

#[derive(Serialize)]
pub(crate) struct CaseResponseRecord {
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) upstream: String,
    pub(crate) status: Option<u16>,
    pub(crate) headers: Option<HeaderMapSnapshot>,
    pub(crate) body: Option<CaseBodyCapture>,
    pub(crate) duration_ms: u128,
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sse_observation: Option<SseObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) interaction: Option<crate::interaction::model::OutputObservation>,
}

pub(crate) async fn finalize_http_case(
    recorder: &Recorder,
    case: &CaseContext,
    request: CaseRequestRecord,
    response: CaseResponseRecord,
    invalidation: Option<CaseInvalidation>,
) -> Result<()> {
    let stored_request = serde_json::to_value(&request)?;
    let mut stored_response = serde_json::to_value(&response)?;
    crate::interaction::artifact::prepare_output(&mut stored_response);
    if let Some(invalidation) = invalidation {
        recorder
            .write_case_json(case, "request.json.invalid", &stored_request)
            .await?;
        recorder
            .write_case_json(case, "expected-response.json.invalid", &stored_response)
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
        let request_filename = if request.body.truncated {
            "request.json.truncated"
        } else {
            "request.json.partial"
        };
        recorder
            .write_case_json(case, request_filename, &stored_request)
            .await?;
        if response.body.is_some() {
            let response_filename = if response.body.as_ref().is_some_and(|body| body.truncated) {
                "expected-response.json.truncated"
            } else {
                "expected-response.json.partial"
            };
            recorder
                .write_case_json(case, response_filename, &stored_response)
                .await?;
        }
        recorder.fail_case(case, reason, message).await
    } else {
        let recording_api = request
            .api_pattern
            .as_ref()
            .map(|pattern| format!("{} {pattern}", request.method));
        recorder
            .write_case_json(case, "request.json", &stored_request)
            .await?;
        recorder
            .write_case_json(case, "expected-response.json", &stored_response)
            .await?;
        if let Some(message) = recorder.case_dependency_safety_issue(case).await? {
            return recorder
                .fail_case(case, "dependency_replay_unsafe", message)
                .await;
        }
        recorder
            .publish_case_for_api(case, recording_api.as_deref())
            .await
    }
}

pub(crate) async fn finalize_owned_http_case(
    recorder: &Recorder,
    publication: &crate::active_case::CasePublication,
    case: &CaseContext,
    request: CaseRequestRecord,
    mut response: CaseResponseRecord,
    invalidation: Option<CaseInvalidation>,
) -> Result<()> {
    // This is the primary case publication linearization point. Keep ownership
    // across all file writes, safety checks, rename and run-report publication.
    let mut commit = publication.begin().await;
    let invalidation = if let Some(observation) = &response.interaction {
        interaction_invalidation(
            observation.end.reason,
            observation.end.offset_ms,
            &observation.end.pending,
            commit.invalidation.clone(),
            invalidation,
        )
    } else {
        commit.invalidation.clone().or(invalidation)
    };
    if invalidation.is_some()
        && let Some(observation) = &mut response.interaction
    {
        observation.end.clean = false;
    }
    let result = finalize_http_case(recorder, case, request, response, invalidation).await;
    commit.finalized = true;
    result
}

pub(crate) fn interaction_invalidation(
    reason: crate::interaction::model::EndReason,
    elapsed_ms: u64,
    pending: &[u64],
    reservation: Option<CaseInvalidation>,
    dependency: Option<CaseInvalidation>,
) -> Option<CaseInvalidation> {
    use crate::interaction::model::EndReason;
    let dependency = dependency.filter(|secondary| {
        reservation.as_ref().is_none_or(|earlier| {
            earlier.reason != secondary.reason || earlier.message != secondary.message
        })
    });
    let primary = primary_interaction_failure(reason, elapsed_ms, pending);
    let mut secondary = reservation.into_iter().chain(dependency);
    // A cleanup transport error can be caused by an already recorded lease or
    // dependency failure. Only independent primary budgets override that cause.
    let mut failure = if matches!(reason, EndReason::RequestTimeout | EndReason::MaxDuration) {
        primary.or_else(|| secondary.next())
    } else {
        secondary.next().or(primary)
    }?;
    for secondary in secondary {
        if secondary.reason == failure.reason && secondary.message == failure.message {
            continue;
        }
        failure.message.push_str(&format!(
            "; secondary invalidation {}: {}",
            secondary.reason, secondary.message
        ));
        if failure.context.is_none() {
            failure.context = secondary.context;
        }
    }
    Some(failure)
}

pub(crate) fn primary_interaction_failure(
    reason: crate::interaction::model::EndReason,
    elapsed_ms: u64,
    pending: &[u64],
) -> Option<CaseInvalidation> {
    use crate::interaction::model::EndReason;
    let failure = match reason {
        EndReason::RequestTimeout => "interaction_request_timeout",
        EndReason::DependencyFailure => "interaction_dependency_failure",
        EndReason::MaxDuration => "interaction_max_duration",
        EndReason::TransportError => "interaction_transport_error",
        EndReason::ProtocolError => "interaction_protocol_error",
        EndReason::BudgetExceeded => "interaction_budget_exceeded",
        EndReason::CleanupTimeout => "interaction_cleanup_timeout",
        EndReason::BusinessIdle
        | EndReason::ServerEof
        | EndReason::ClientClose
        | EndReason::ClientTransportEnd => return None,
    };
    Some(CaseInvalidation::new(
        failure,
        format!("primary interaction ended with {reason:?} at {elapsed_ms}ms; pending={pending:?}"),
    ))
}

fn invalid_case_reason(
    request: &CaseRequestRecord,
    response: &CaseResponseRecord,
) -> Option<(&'static str, String)> {
    if request.body.truncated {
        return Some((
            "request_body_truncated",
            format!(
                "request body exceeded recording limit: wire_len={} stored_len={} limit_bytes={}",
                request.body.original_len, request.body.stored_len, request.body.limit_bytes
            ),
        ));
    }
    if let Some(error) = &request.body.decode_error {
        return Some(("request_body_decode_error", error.clone()));
    }
    if let Some(error) = &response.error {
        return Some(("upstream_response_error", error.clone()));
    }
    if let Some(observation) = &response.interaction {
        if !observation.end.clean {
            return Some((
                "interaction_incomplete",
                format!(
                    "interaction ended with {:?}; pending={:?}",
                    observation.end.reason, observation.end.pending
                ),
            ));
        }
        return None;
    }
    let Some(body) = &response.body else {
        return Some((
            "expected_response_missing",
            "upstream response body was not captured".to_string(),
        ));
    };
    if body.truncated {
        return Some((
            "expected_response_body_truncated",
            format!(
                "decoded response body exceeded recording limit: wire_len={} stored_decoded_len={} decoded_limit_bytes={}",
                body.original_len, body.stored_len, body.limit_bytes
            ),
        ));
    }
    if let Some(error) = &body.decode_error {
        return Some(("expected_response_body_decode_error", error.clone()));
    }
    if response_is_json(response)
        && !body_is_empty(body)
        && body.encoding == "utf8"
        && let Err(err) = serde_json::from_str::<serde_json::Value>(&body.data)
    {
        return Some((
            "expected_response_json_invalid",
            format!("expected response body is not valid JSON: {err}"),
        ));
    }
    None
}

fn body_is_empty(body: &CaseBodyCapture) -> bool {
    body.original_len == 0 && body.stored_len == 0 && body.data.is_empty()
}

fn response_is_json(response: &CaseResponseRecord) -> bool {
    response
        .headers
        .as_ref()
        .and_then(|headers| headers.get("content-type"))
        .into_iter()
        .flat_map(|values| values.iter())
        .any(|value| value.to_ascii_lowercase().contains("json"))
}

#[cfg(test)]
mod tests {
    mod plaintext;
    use super::*;
    use crate::recorder::capture_case_body;
    use uuid::Uuid;

    fn request() -> CaseRequestRecord {
        CaseRequestRecord {
            timestamp: Utc::now(),
            client_addr: None,
            method: "GET".to_string(),
            uri: "/api/resource/getprivkey/127.0.0.1".to_string(),
            api_pattern: Some("/api/resource/getprivkey/*".to_string()),
            authority: Some("example.com".to_string()),
            matched_rule: Some("api".to_string()),
            upstream: "http://127.0.0.1:7171".to_string(),
            headers: HeaderMapSnapshot::new(),
            body: capture_case_body(b"", 1024, 1024, None),
            sse_observation: None,
            interaction: None,
        }
    }

    fn json_response(body: &[u8]) -> CaseResponseRecord {
        let mut headers = HeaderMapSnapshot::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json; charset=utf-8".to_string()],
        );
        headers.insert("content-length".to_string(), vec![body.len().to_string()]);
        CaseResponseRecord {
            timestamp: Utc::now(),
            matched_rule: Some("api".to_string()),
            upstream: "http://127.0.0.1:7171".to_string(),
            status: Some(200),
            headers: Some(headers),
            body: Some(capture_case_body(body, 1024, 1024, None)),
            duration_ms: 1,
            error: None,
            sse_observation: None,
            interaction: None,
        }
    }

    #[tokio::test]
    async fn publishes_complete_empty_json_response() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: Some("api-resource-getprivkey-wildcard".to_string()),
        };

        finalize_http_case(&recorder, &case, request(), json_response(b""), None)
            .await
            .unwrap();

        let published = recorder.case_dir(&case);
        assert!(published.join("request.json").is_file());
        assert!(published.join("expected-response.json").is_file());
        assert!(published.join("dependencies-summary.json").is_file());
        assert!(!recorder.case_failed_dir(&case).exists());
        let expected: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(published.join("expected-response.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expected["body"]["original_len"], 0);
        assert_eq!(expected["body"]["stored_len"], 0);
        assert_eq!(expected["body"]["data"], "");
    }

    #[tokio::test]
    async fn published_http_case_advances_its_explicit_api_limit() {
        let temp = tempfile::tempdir().unwrap();
        let config = crate::config::RecordingConfig::default();
        let recorder = Recorder::new_with_recording_config_at_and_run_id(
            &config,
            temp.path(),
            None,
            vec![("GET /api/resource/getprivkey/*".to_string(), 1)],
            None,
        )
        .await
        .unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: Some("api-resource-getprivkey-wildcard".to_string()),
        };

        finalize_http_case(&recorder, &case, request(), json_response(b"{}"), None)
            .await
            .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            recorder.wait_for_explicit_api_case_limit(),
        )
        .await
        .unwrap();
    }

    #[test]
    fn rejects_nonempty_invalid_json_response() {
        let reason = invalid_case_reason(&request(), &json_response(b"not-json")).unwrap();

        assert_eq!(reason.0, "expected_response_json_invalid");
    }

    #[test]
    fn observed_client_transport_end_retains_independent_lease_or_dependency_failure() {
        use crate::interaction::model::EndReason;
        assert!(primary_interaction_failure(EndReason::ClientTransportEnd, 10, &[1]).is_none());
        let failure = interaction_invalidation(
            EndReason::ClientTransportEnd,
            10,
            &[1],
            Some(CaseInvalidation::new(
                "interaction_reservation_lost",
                "real lease loss",
            )),
            None,
        )
        .unwrap();
        assert_eq!(failure.reason, "interaction_reservation_lost");
        assert!(primary_interaction_failure(EndReason::TransportError, 10, &[1]).is_some());
    }

    #[tokio::test]
    async fn interaction_lease_loss_after_drain_prevents_publication() {
        use crate::active_case::{ActiveCaseRegistry, DependencyDrainResult};
        use crate::interaction::{
            model::{EndReason, Protocol},
            observation::Observation,
        };
        use std::time::Duration;

        for end in [
            EndReason::TransportError,
            EndReason::ProtocolError,
            EndReason::MaxDuration,
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(temp.path().join(".traffic-e2e/local")).unwrap();
            crate::platform::encryption_key::load_or_create(temp.path()).unwrap();
            let recorder =
                Recorder::new(temp.path().join(".traffic-e2e/local/artifacts/recordings"))
                    .await
                    .unwrap();
            let registry = ActiveCaseRegistry::default();
            let case = CaseContext {
                id: Uuid::new_v4(),
                rule_name: "stream".into(),
                uri_group: None,
            };
            let _owner = registry.try_reserve(case.clone()).unwrap();
            _owner.activate_dependencies().unwrap();
            let publication = registry.register_case_publication(case.id).unwrap();
            assert_eq!(
                registry
                    .drain_case_dependencies(
                        case.id,
                        Duration::from_millis(1),
                        Duration::from_secs(1),
                    )
                    .await,
                DependencyDrainResult::Drained
            );
            let loss = CaseInvalidation::new("interaction_reservation_lost", "test token replaced");
            assert!(registry.invalidate_case(case.id, loss.clone()).is_none());
            assert!(registry.invalidate_interaction_reservation(Some(case.id), loss.clone()));
            let (input, output) = Observation::new(Protocol::Sse, Default::default())
                .unwrap()
                .finish(end, 10, true)
                .unwrap();
            let mut request = request();
            request.interaction = Some(input);
            let mut response = json_response(b"");
            response.interaction = Some(output);
            finalize_owned_http_case(
                &recorder,
                &publication,
                &case,
                request,
                response,
                Some(loss),
            )
            .await
            .unwrap();
            assert!(!recorder.case_dir(&case).exists());
            let failed = recorder.case_failed_dir(&case);
            assert!(failed.join("request.json.invalid").exists());
            let detail: serde_json::Value = serde_json::from_slice(
                &tokio::fs::read(failed.join("recording-error.json"))
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                detail["reason"],
                if end == EndReason::MaxDuration {
                    "interaction_max_duration"
                } else {
                    "interaction_reservation_lost"
                }
            );
            assert_eq!(
                detail["message"]
                    .as_str()
                    .unwrap()
                    .matches("test token replaced")
                    .count(),
                1
            );
            assert!(publication.begin().await.finalized);
            assert!(!registry.invalidate_interaction_reservation(
                Some(case.id),
                CaseInvalidation::new("late_loss", "after failed publication")
            ));
        }
    }

    #[tokio::test]
    async fn interaction_publication_barrier_orders_later_lease_loss_after_commit() {
        use crate::active_case::ActiveCaseRegistry;
        use std::time::Duration;

        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let registry = ActiveCaseRegistry::default();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "stream".into(),
            uri_group: None,
        };
        let _owner = registry.try_reserve(case.clone()).unwrap();
        let publication = registry.register_case_publication(case.id).unwrap();
        // Block real file writes after the finalizer has acquired its commit
        // ownership; this makes the loss/publication ordering deterministic.
        let disk = recorder.dependency_write_lock.lock().await;
        let task = tokio::spawn({
            let recorder = recorder.clone();
            let case = case.clone();
            let publication = publication.clone();
            async move {
                finalize_owned_http_case(
                    &recorder,
                    &publication,
                    &case,
                    request(),
                    json_response(b""),
                    None,
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match tokio::time::timeout(Duration::from_millis(5), publication.begin()).await {
                    Err(_) => break,
                    Ok(guard) => drop(guard),
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let loss = || CaseInvalidation::new("interaction_reservation_lost", "late token loss");
        assert!(!registry.invalidate_interaction_reservation(Some(case.id), loss()));
        assert!(!task.is_finished());
        drop(disk);
        task.await.unwrap().unwrap();
        assert!(recorder.case_dir(&case).join("request.json").exists());
        assert!(!registry.invalidate_interaction_reservation(Some(case.id), loss()));
        assert!(!recorder.case_failed_dir(&case).exists());
    }
}
