use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::recorder::{CaseBodyCapture, CaseContext, HeaderMapSnapshot, Recorder};

#[derive(Serialize)]
pub(crate) struct CaseRequestRecord {
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) client_addr: Option<String>,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) authority: Option<String>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) upstream: String,
    pub(crate) headers: HeaderMapSnapshot,
    pub(crate) body: CaseBodyCapture,
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
}

pub(crate) async fn finalize_http_case(
    recorder: &Recorder,
    case: &CaseContext,
    request: CaseRequestRecord,
    response: CaseResponseRecord,
) -> Result<()> {
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
        recorder.publish_case(case).await
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
                "request body exceeded recording limit: original_len={} stored_len={}",
                request.body.original_len, request.body.stored_len
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
                "expected response body exceeded recording limit: original_len={} stored_len={}",
                body.original_len, body.stored_len
            ),
        ));
    }
    if let Some(error) = &body.decode_error {
        return Some(("expected_response_body_decode_error", error.clone()));
    }
    if response_is_json(response)
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

fn response_is_json(response: &CaseResponseRecord) -> bool {
    response
        .headers
        .as_ref()
        .and_then(|headers| headers.get("content-type"))
        .into_iter()
        .flat_map(|values| values.iter())
        .any(|value| value.to_ascii_lowercase().contains("json"))
}
