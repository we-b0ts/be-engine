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
}

pub(crate) async fn finalize_http_case(
    recorder: &Recorder,
    case: &CaseContext,
    request: CaseRequestRecord,
    response: CaseResponseRecord,
    invalidation: Option<CaseInvalidation>,
) -> Result<()> {
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
        let request_filename = if request.body.truncated {
            "request.json.truncated"
        } else {
            "request.json.partial"
        };
        recorder
            .write_case_json(case, request_filename, &request)
            .await?;
        if response.body.is_some() {
            let response_filename = if response.body.as_ref().is_some_and(|body| body.truncated) {
                "expected-response.json.truncated"
            } else {
                "expected-response.json.partial"
            };
            recorder
                .write_case_json(case, response_filename, &response)
                .await?;
        }
        recorder.fail_case(case, reason, message).await
    } else {
        let recording_api = request
            .api_pattern
            .as_ref()
            .map(|pattern| format!("{} {pattern}", request.method));
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
            .publish_case_for_api(case, recording_api.as_deref())
            .await
    }
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
}
