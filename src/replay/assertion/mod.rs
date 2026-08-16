mod artifact;
mod compare;
mod model;
mod motan;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use self::artifact::{
    ActualResponse, ComparisonResponse, ExpectedResponse, RecordedRequest, decode_body,
};
use self::compare::compare_json;
pub use self::model::{
    ResponseAssertionCaseReport, ResponseBodyMode, ResponseDifference, ResponseDifferenceKind,
};
use super::policy::{fingerprint, load_replay_policy, uri_path};
use crate::config::DEFAULT_BODY_LIMIT_BYTES;
use crate::http::content_encoding;

pub struct ResponseAssertionOptions {
    pub case_id: String,
    pub request: PathBuf,
    pub expected_response: PathBuf,
    pub actual_response: PathBuf,
    pub policy: PathBuf,
}

pub(crate) struct ComparisonResponseAssertionOptions {
    pub case_id: String,
    pub request: PathBuf,
    pub expected_response: PathBuf,
    pub response: PathBuf,
    pub policy: PathBuf,
}

pub(crate) struct ComparisonResponseObservation {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

pub fn assert_recorded_response(
    options: ResponseAssertionOptions,
) -> Result<ResponseAssertionCaseReport> {
    let request_bytes = read_regular(&options.request, "recorded request")?;
    let expected_bytes = read_regular(&options.expected_response, "expected response")?;
    let actual_bytes = read_regular(&options.actual_response, "actual response")?;
    let request: RecordedRequest = serde_json::from_slice(&request_bytes)
        .with_context(|| format!("invalid recorded request {}", options.request.display()))?;
    let expected: ExpectedResponse =
        serde_json::from_slice(&expected_bytes).with_context(|| {
            format!(
                "invalid expected response {}",
                options.expected_response.display()
            )
        })?;
    let actual: ActualResponse = serde_json::from_slice(&actual_bytes).with_context(|| {
        format!(
            "invalid actual response {}",
            options.actual_response.display()
        )
    })?;
    ensure!(
        actual.version == 1,
        "unsupported actual response version {}; expected 1",
        actual.version
    );
    let oneway = expected.response_expected == Some(false);
    let expected_status = match expected.status.as_ref() {
        Some(status) => status.code(),
        None if oneway => 204,
        None => anyhow::bail!("expected response has no status"),
    };
    let mut expected_body = match expected.body.as_ref().or(expected.frame.as_ref()) {
        Some(body) => decode_body(body, "expected response")?,
        None if oneway => Vec::new(),
        None => anyhow::bail!("expected response has no body or frame"),
    };
    let mut actual_body = decode_body(&actual.body, "actual response")?;
    if request.is_motan2() && !oneway {
        expected_body = motan::comparable_response_frame(&expected_body, "expected response")?;
        actual_body = motan::comparable_response_frame(&actual_body, "actual response")?;
    }
    evaluate_response(AssertionInputs {
        mode: AssertionMode::Replay,
        case_id: options.case_id,
        request,
        expected_status,
        expected_body,
        expected_path: options.expected_response,
        expected_bytes,
        actual_status: actual.status,
        actual_body,
        actual_path: options.actual_response,
        actual_bytes,
        policy: options.policy,
    })
}

pub(crate) fn assert_comparison_response(
    options: ComparisonResponseAssertionOptions,
) -> Result<ResponseAssertionCaseReport> {
    let request_bytes = read_regular(&options.request, "recorded request")?;
    let expected_bytes = read_regular(&options.expected_response, "expected response")?;
    let response_bytes = read_regular(&options.response, "response")?;
    let request: RecordedRequest = serde_json::from_slice(&request_bytes)
        .with_context(|| format!("invalid recorded request {}", options.request.display()))?;
    let expected: ComparisonResponse =
        serde_json::from_slice(&expected_bytes).with_context(|| {
            format!(
                "invalid expected response {}",
                options.expected_response.display()
            )
        })?;
    let response: ComparisonResponse = serde_json::from_slice(&response_bytes)
        .with_context(|| format!("invalid response {}", options.response.display()))?;
    ensure!(
        expected.version == 1,
        "unsupported expected response version {}; expected 1",
        expected.version
    );
    ensure!(
        response.version == 1,
        "unsupported response version {}; expected 1",
        response.version
    );
    let expected_status = captured_status(&expected, "expected response")?;
    let expected_body = captured_body(&expected, "expected response")?;
    let actual_status = captured_status(&response, "response")?;
    let actual_body = captured_body(&response, "response")?;
    evaluate_response(AssertionInputs {
        mode: AssertionMode::Comparison,
        case_id: options.case_id,
        request,
        expected_status,
        expected_body,
        expected_path: options.expected_response,
        expected_bytes,
        actual_status,
        actual_body,
        actual_path: options.response,
        actual_bytes: response_bytes,
        policy: options.policy,
    })
}

pub(crate) fn read_comparison_response_observation(
    path: &Path,
    label: &str,
) -> Result<ComparisonResponseObservation> {
    let bytes = read_regular(path, label)?;
    let response: ComparisonResponse = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid {label} {}", path.display()))?;
    ensure!(
        response.version == 1,
        "unsupported {label} version {}; expected 1",
        response.version
    );
    Ok(ComparisonResponseObservation {
        status: captured_status(&response, label)?,
        body: captured_body(&response, label)?,
    })
}

fn captured_status(response: &ComparisonResponse, label: &str) -> Result<u16> {
    response.status.with_context(|| {
        format!(
            "{label} has no HTTP status{}",
            response
                .error
                .as_deref()
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        )
    })
}

fn captured_body(response: &ComparisonResponse, label: &str) -> Result<Vec<u8>> {
    let body = response.body.as_ref().with_context(|| {
        format!(
            "{label} has no body{}",
            response
                .error
                .as_deref()
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        )
    })?;
    let captured = decode_body(body, label)?;
    if body.decoded == Some(true) {
        return Ok(captured);
    }
    let content_encoding = body.content_encoding.clone().or_else(|| {
        response
            .headers
            .as_ref()
            .and_then(|headers| headers.get("content-encoding"))
            .filter(|values| !values.is_empty())
            .map(|values| values.join(","))
    });
    let Some(content_encoding) = content_encoding else {
        return Ok(captured);
    };
    let limit = body.limit_bytes.unwrap_or(DEFAULT_BODY_LIMIT_BYTES);
    let decoded = content_encoding::decode(&captured, &content_encoding, limit)
        .with_context(|| format!("{label} body content decoding failed"))?;
    ensure!(
        !decoded.truncated,
        "{label} decoded body exceeds limit of {limit} bytes"
    );
    Ok(decoded.body)
}

struct AssertionInputs {
    mode: AssertionMode,
    case_id: String,
    request: RecordedRequest,
    expected_status: u16,
    expected_body: Vec<u8>,
    expected_path: PathBuf,
    expected_bytes: Vec<u8>,
    actual_status: u16,
    actual_body: Vec<u8>,
    actual_path: PathBuf,
    actual_bytes: Vec<u8>,
    policy: PathBuf,
}

#[derive(Debug, Clone, Copy)]
enum AssertionMode {
    Replay,
    Comparison,
}

fn evaluate_response(inputs: AssertionInputs) -> Result<ResponseAssertionCaseReport> {
    let AssertionInputs {
        mode,
        case_id,
        request,
        expected_status,
        expected_body,
        expected_path,
        expected_bytes,
        actual_status,
        actual_body,
        actual_path,
        actual_bytes,
        policy,
    } = inputs;
    let loaded = load_replay_policy(&policy)?;
    ensure!(
        loaded.document.version >= 2,
        "runner-owned response assertions require replay policy version 2"
    );
    let path = uri_path(&request.uri);
    let response_fields = match mode {
        AssertionMode::Replay => loaded
            .document
            .response_rules
            .matching_replay_fields(&request.method, &path),
        AssertionMode::Comparison => loaded
            .document
            .response_rules
            .matching_comparison_fields(&request.method, &path),
    };
    let mut report = ResponseAssertionCaseReport::new(
        case_id,
        request.method,
        path,
        loaded.path.display().to_string(),
        loaded.fingerprint,
        expected_path.display().to_string(),
        fingerprint(&expected_bytes),
        actual_path.display().to_string(),
        fingerprint(&actual_bytes),
    );
    if expected_status != actual_status {
        report
            .differences
            .push(ResponseDifference::status(expected_status, actual_status));
    }
    match (
        serde_json::from_slice::<serde_json::Value>(&expected_body),
        serde_json::from_slice::<serde_json::Value>(&actual_body),
    ) {
        (Ok(expected), Ok(actual)) => {
            report.body_mode = ResponseBodyMode::JsonStructural;
            compare_json(&expected, &actual, &response_fields, &mut report);
            let applicable_fields = response_fields
                .iter()
                .filter(|field| {
                    expected.pointer(&field.pointer).is_some()
                        && actual.pointer(&field.pointer).is_some()
                })
                .cloned()
                .collect::<Vec<_>>();
            report.finish(&applicable_fields);
        }
        _ => {
            report.body_mode = ResponseBodyMode::ExactBytes;
            ensure!(
                response_fields.is_empty(),
                "response rules require JSON response bodies"
            );
            if expected_body != actual_body {
                report
                    .differences
                    .push(ResponseDifference::exact_body_mismatch());
            }
            report.finish(&[]);
        }
    }
    Ok(report)
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink"
    );
    fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
mod tests;
