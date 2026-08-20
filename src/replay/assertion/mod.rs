mod artifact;
mod binary_body;
mod compare;
pub(in crate::replay) mod hessian2;
mod model;
mod motan;
pub(in crate::replay) mod protobuf;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use self::artifact::{
    ActualResponse, ComparisonResponse, ExpectedResponse, RecordedRequest, decode_body,
};
use self::compare::compare_json;
pub use self::model::{
    Hessian2BodyDifference, Hessian2BodyDifferenceKind, Hessian2JoinedStringCandidate,
    Hessian2ValuePathCandidate, MotanBodyAssertionReport, MotanBodyDifference,
    MotanUnorderedPathCandidate, ProtobufBodyDifference, ProtobufBodyDifferenceKind,
    ProtobufFieldPathCandidate, ResponseAssertionCaseReport, ResponseBodyMode, ResponseDifference,
    ResponseDifferenceKind,
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
    let expected_body = match expected.body.as_ref().or(expected.frame.as_ref()) {
        Some(body) => decode_body(body, "expected response")?,
        None if oneway => Vec::new(),
        None => anyhow::bail!("expected response has no body or frame"),
    };
    let actual_body = decode_body(&actual.body, "actual response")?;
    let (expected_body, actual_body) = if request.has_motan_frame() && !oneway {
        (
            AssertionBody::MotanFrame(motan::comparable_response_frame(
                &expected_body,
                "expected response",
            )?),
            AssertionBody::MotanFrame(motan::comparable_response_frame(
                &actual_body,
                "actual response",
            )?),
        )
    } else {
        (
            AssertionBody::Bytes(expected_body),
            AssertionBody::Bytes(actual_body),
        )
    };
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
    let expected_body = AssertionBody::Bytes(captured_body(&expected, "expected response")?);
    let actual_status = captured_status(&response, "response")?;
    let actual_body = AssertionBody::Bytes(captured_body(&response, "response")?);
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
    expected_body: AssertionBody,
    expected_path: PathBuf,
    expected_bytes: Vec<u8>,
    actual_status: u16,
    actual_body: AssertionBody,
    actual_path: PathBuf,
    actual_bytes: Vec<u8>,
    policy: PathBuf,
}

enum AssertionBody {
    Bytes(Vec<u8>),
    MotanFrame(motan::ComparableResponseFrame),
}

impl AssertionBody {
    fn exact_bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::MotanFrame(frame) => frame.encoded(),
        }
    }

    fn protocol_body(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::MotanFrame(frame) => frame.body(),
        }
    }

    fn protocol_carrier_matches(&self, actual: &Self) -> bool {
        match (self, actual) {
            (Self::Bytes(_), Self::Bytes(_)) => true,
            (Self::MotanFrame(expected), Self::MotanFrame(actual)) => {
                expected.carrier() == actual.carrier()
            }
            _ => false,
        }
    }
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
        loaded.document.version >= 3,
        "runner-owned response assertions require replay policy version 3"
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
    let motan_rules = loaded
        .document
        .response_rules
        .matching_motan_rules(&request.method, &path);
    let is_motan_request = request.method.eq_ignore_ascii_case("MOTAN");
    ensure!(
        motan_rules.len() <= 1,
        "multiple Motan response rules match {} {}",
        request.method,
        path
    );
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
    if let Some(rule) = motan_rules.first() {
        ensure!(
            response_fields.is_empty(),
            "Motan response rules cannot be combined with JSON response rules"
        );
        let (body_matches, motan_report) = match rule.protocol {
            super::policy::MotanBodyProtocol::Protobuf => {
                ensure!(
                    rule.unordered_joined_string_paths.is_empty(),
                    "protobuf Motan rule cannot carry joined-string paths"
                );
                let unordered_paths = rule
                    .unordered_paths
                    .iter()
                    .map(|path| match path {
                        super::policy::MotanUnorderedPath::Protobuf(path) => Ok(path.clone()),
                        super::policy::MotanUnorderedPath::Hessian2(_) => {
                            anyhow::bail!("protobuf Motan rule contains a Hessian2 unordered path")
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                report.body_mode = ResponseBodyMode::MotanProtobuf;
                let (body_matches, discovery) = protobuf::evaluate_motan_protobuf(
                    expected_body.protocol_body(),
                    actual_body.protocol_body(),
                    &unordered_paths,
                )
                .context("failed to apply configured Motan protobuf response rule")?;
                (
                    body_matches,
                    MotanBodyAssertionReport {
                        rule_kind: "motan".to_string(),
                        protocol: rule.protocol,
                        envelope: "simple_byte_array".to_string(),
                        configured: true,
                        protocol_candidates: vec![rule.protocol],
                        unordered_path_candidates: discovery
                            .unordered_paths
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        unordered_joined_string_candidates: Vec::new(),
                        differences: discovery.differences.into_iter().map(Into::into).collect(),
                        order_only: discovery.order_only,
                    },
                )
            }
            super::policy::MotanBodyProtocol::Hessian2 => {
                let unordered_paths = rule
                    .unordered_paths
                    .iter()
                    .map(|path| match path {
                        super::policy::MotanUnorderedPath::Hessian2(path) => Ok(path.clone()),
                        super::policy::MotanUnorderedPath::Protobuf(_) => {
                            anyhow::bail!("Hessian2 Motan rule contains a protobuf unordered path")
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                report.body_mode = ResponseBodyMode::MotanHessian2;
                let (body_matches, discovery) = hessian2::evaluate_motan_hessian2(
                    expected_body.protocol_body(),
                    actual_body.protocol_body(),
                    &unordered_paths,
                    &rule.unordered_joined_string_paths,
                )
                .context("failed to apply configured Motan Hessian2 response rule")?;
                (
                    body_matches,
                    MotanBodyAssertionReport {
                        rule_kind: "motan".to_string(),
                        protocol: rule.protocol,
                        envelope: discovery.envelope.as_str().to_string(),
                        configured: true,
                        protocol_candidates: vec![rule.protocol],
                        unordered_path_candidates: discovery
                            .unordered_paths
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        unordered_joined_string_candidates: discovery
                            .unordered_joined_string_paths
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        differences: discovery.differences.into_iter().map(Into::into).collect(),
                        order_only: discovery.order_only,
                    },
                )
            }
        };
        report.applied_motan_rule_ids.push(rule.id.clone());
        report.motan = Some(motan_report);
        if !body_matches || !expected_body.protocol_carrier_matches(&actual_body) {
            report
                .differences
                .push(ResponseDifference::exact_body_mismatch());
        }
        report.finish(&[], std::slice::from_ref(&rule.id));
        return Ok(report);
    }

    match (
        serde_json::from_slice::<serde_json::Value>(expected_body.exact_bytes()),
        serde_json::from_slice::<serde_json::Value>(actual_body.exact_bytes()),
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
            report.finish(&applicable_fields, &[]);
        }
        _ => {
            report.body_mode = ResponseBodyMode::ExactBytes;
            ensure!(
                response_fields.is_empty(),
                "response rules require JSON response bodies"
            );
            if expected_body.exact_bytes() != actual_body.exact_bytes() {
                report
                    .differences
                    .push(ResponseDifference::exact_body_mismatch());
                let expected_protocol_body = expected_body.protocol_body();
                let actual_protocol_body = actual_body.protocol_body();
                if is_motan_request && expected_protocol_body != actual_protocol_body {
                    let protobuf_candidate =
                        protobuf::is_motan_protobuf_body(expected_protocol_body)
                            && protobuf::is_motan_protobuf_body(actual_protocol_body);
                    let hessian2_candidate =
                        hessian2::is_motan_hessian2_body(expected_protocol_body)
                            && hessian2::is_motan_hessian2_body(actual_protocol_body);
                    let mut protocol_candidates = Vec::new();
                    if protobuf_candidate {
                        protocol_candidates
                            .push(crate::replay::policy::MotanBodyProtocol::Protobuf);
                    }
                    if hessian2_candidate {
                        protocol_candidates
                            .push(crate::replay::policy::MotanBodyProtocol::Hessian2);
                    }
                    if protobuf_candidate {
                        let discovery = protobuf::discover_motan_protobuf_order(
                            expected_protocol_body,
                            actual_protocol_body,
                        )?;
                        report.motan = Some(MotanBodyAssertionReport {
                            rule_kind: "motan".to_string(),
                            protocol: crate::replay::policy::MotanBodyProtocol::Protobuf,
                            envelope: "simple_byte_array".to_string(),
                            configured: false,
                            protocol_candidates,
                            unordered_path_candidates: discovery
                                .unordered_paths
                                .into_iter()
                                .map(Into::into)
                                .collect(),
                            unordered_joined_string_candidates: Vec::new(),
                            differences: discovery
                                .differences
                                .into_iter()
                                .map(Into::into)
                                .collect(),
                            order_only: discovery.order_only,
                        });
                    } else if hessian2_candidate {
                        let discovery = hessian2::discover_motan_hessian2_order(
                            expected_protocol_body,
                            actual_protocol_body,
                        )?;
                        report.motan = Some(MotanBodyAssertionReport {
                            rule_kind: "motan".to_string(),
                            protocol: crate::replay::policy::MotanBodyProtocol::Hessian2,
                            envelope: discovery.envelope.as_str().to_string(),
                            configured: false,
                            protocol_candidates,
                            unordered_path_candidates: discovery
                                .unordered_paths
                                .into_iter()
                                .map(Into::into)
                                .collect(),
                            unordered_joined_string_candidates: discovery
                                .unordered_joined_string_paths
                                .into_iter()
                                .map(Into::into)
                                .collect(),
                            differences: discovery
                                .differences
                                .into_iter()
                                .map(Into::into)
                                .collect(),
                            order_only: discovery.order_only,
                        });
                    }
                }
            }
            report.finish(&[], &[]);
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
