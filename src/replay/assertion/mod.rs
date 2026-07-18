mod artifact;
mod compare;
mod model;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use self::artifact::{ActualResponse, ExpectedResponse, RecordedRequest, decode_body};
use self::compare::compare_json;
pub use self::model::{ResponseAssertionCaseReport, ResponseBodyMode, ResponseDifference};
use super::policy::{fingerprint, load_replay_policy, uri_path};

pub struct ResponseAssertionOptions {
    pub case_id: String,
    pub request: PathBuf,
    pub expected_response: PathBuf,
    pub actual_response: PathBuf,
    pub policy: PathBuf,
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
    let expected_status = expected
        .status
        .context("expected response has no HTTP status")?;
    let expected_body = expected
        .body
        .as_ref()
        .context("expected response has no body")?;
    let expected_body = decode_body(expected_body, "expected response")?;
    let actual_body = decode_body(&actual.body, "actual response")?;
    let loaded = load_replay_policy(&options.policy)?;
    ensure!(
        loaded.document.version >= 2,
        "runner-owned response assertions require replay policy version 2"
    );
    let path = uri_path(&request.uri);
    let response_fields = loaded
        .document
        .response_rules
        .matching_fields(&request.method, &path);
    let mut report = ResponseAssertionCaseReport::new(
        options.case_id,
        request.method,
        path,
        loaded.path.display().to_string(),
        loaded.fingerprint,
        options.expected_response.display().to_string(),
        fingerprint(&expected_bytes),
        options.actual_response.display().to_string(),
        fingerprint(&actual_bytes),
    );
    if expected_status != actual.status {
        report
            .differences
            .push(ResponseDifference::status(expected_status, actual.status));
    }
    match (
        serde_json::from_slice::<serde_json::Value>(&expected_body),
        serde_json::from_slice::<serde_json::Value>(&actual_body),
    ) {
        (Ok(expected), Ok(actual)) => {
            report.body_mode = ResponseBodyMode::JsonStructural;
            compare_json(&expected, &actual, &response_fields, &mut report);
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
        }
    }
    report.finish(&response_fields);
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
