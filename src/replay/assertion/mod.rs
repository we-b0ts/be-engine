mod artifact;
mod binary_body;
mod compare;
pub(in crate::replay) mod hessian2;
mod joined_string;
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
    Hessian2ValuePathCandidate, JsonJoinedStringCandidate, ProtobufBodyDifference,
    ProtobufBodyDifferenceKind, ProtobufFieldPathCandidate, ProtobufJoinedStringCandidate,
    ResponseAssertionCaseReport, ResponseBodyAssertionReport, ResponseBodyDifferenceDetail,
    ResponseBodyJoinedStringCandidate, ResponseBodyUnorderedPathCandidate, ResponseDifference,
    ResponseDifferenceKind, ResponseGatewayProtocol,
};
use super::policy::{ResponseBodyCodec, fingerprint, load_replay_policy, uri_path};
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

pub(crate) fn read_expected_response_body(
    path: &Path,
    gateway_protocol: ResponseGatewayProtocol,
) -> Result<Vec<u8>> {
    let bytes = read_regular(path, "expected response")?;
    let response: ExpectedResponse = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid expected response {}", path.display()))?;
    let body = response
        .body
        .as_ref()
        .or(response.frame.as_ref())
        .context("expected response has no body or frame")?;
    response_body_for_gateway(decode_body(body, "expected response")?, gateway_protocol)
}

pub(crate) fn read_actual_response_body(
    path: &Path,
    gateway_protocol: ResponseGatewayProtocol,
) -> Result<Vec<u8>> {
    let bytes = read_regular(path, "actual response")?;
    let response: ActualResponse = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid actual response {}", path.display()))?;
    response_body_for_gateway(
        decode_body(&response.body, "actual response")?,
        gateway_protocol,
    )
}

fn response_body_for_gateway(
    bytes: Vec<u8>,
    gateway_protocol: ResponseGatewayProtocol,
) -> Result<Vec<u8>> {
    match gateway_protocol {
        ResponseGatewayProtocol::Http => Ok(bytes),
        ResponseGatewayProtocol::Motan1 | ResponseGatewayProtocol::Motan2 => {
            Ok(motan::comparable_response_frame(&bytes, "response")?
                .body()
                .to_vec())
        }
    }
}

pub(in crate::replay) fn diagnose_response_body(
    expected: &[u8],
    actual: &[u8],
    codec: ResponseBodyCodec,
) -> Result<ResponseBodyAssertionReport> {
    match codec {
        ResponseBodyCodec::Protobuf => {
            let discovery = protobuf::discover_protobuf_order(expected, actual)?;
            Ok(ResponseBodyAssertionReport {
                codec,
                envelope: "simple_byte_array".to_string(),
                configured: false,
                codec_candidates: vec![codec],
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
                candidates_explain_all_differences: discovery.candidates_explain_all_differences,
                order_only: discovery.order_only,
            })
        }
        ResponseBodyCodec::Hessian2 => {
            let discovery = hessian2::discover_hessian2_order(expected, actual)?;
            Ok(ResponseBodyAssertionReport {
                codec,
                envelope: discovery.envelope.as_str().to_string(),
                configured: false,
                codec_candidates: vec![codec],
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
                candidates_explain_all_differences: discovery.candidates_explain_all_differences,
                order_only: discovery.order_only,
            })
        }
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
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
        request_path: options.request,
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
        request_path: options.request,
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
    request_path: PathBuf,
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
    fn body(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::MotanFrame(frame) => frame.body(),
        }
    }

    fn gateway_metadata_matches(&self, actual: &Self) -> bool {
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
        request_path,
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
    let body_rules = loaded
        .document
        .response_rules
        .matching_response_body_rules(&request.method, &path);
    ensure!(
        body_rules.len() <= 1,
        "multiple response-body rules match {} {}",
        request.method,
        path
    );
    let gateway_protocol = request.gateway_protocol()?;
    let mut report = ResponseAssertionCaseReport::new(
        case_id,
        request.method,
        path,
        gateway_protocol,
        request_path.display().to_string(),
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
    if let Some(rule) = body_rules.first() {
        ensure!(
            response_fields.is_empty(),
            "typed response-body rules cannot be combined with JSON response rules"
        );
        let (body_matches, body_diagnosis) = match rule.codec {
            super::policy::ResponseBodyCodec::Protobuf => {
                let unordered_paths = rule
                    .unordered_paths
                    .iter()
                    .map(|path| match path {
                        super::policy::ResponseBodyUnorderedPath::Protobuf(path) => {
                            Ok(path.clone())
                        }
                        super::policy::ResponseBodyUnorderedPath::Hessian2(_) => {
                            anyhow::bail!(
                                "protobuf response-body rule contains a Hessian2 unordered path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                let joined_string_paths = rule
                    .unordered_joined_string_paths
                    .iter()
                    .map(|path| match path {
                        super::policy::ResponseBodyJoinedStringPath::Protobuf(path) => {
                            Ok(path.clone())
                        }
                        super::policy::ResponseBodyJoinedStringPath::Hessian2(_) => {
                            anyhow::bail!(
                                "protobuf response-body rule contains a Hessian2 joined-string path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                report.body_codec = ResponseBodyCodec::Protobuf;
                let (body_matches, discovery) = protobuf::evaluate_protobuf(
                    expected_body.body(),
                    actual_body.body(),
                    &unordered_paths,
                    &joined_string_paths,
                )
                .context("failed to apply configured protobuf response-body rule")?;
                (
                    body_matches,
                    ResponseBodyAssertionReport {
                        codec: rule.codec,
                        envelope: "simple_byte_array".to_string(),
                        configured: true,
                        codec_candidates: vec![rule.codec],
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
                        candidates_explain_all_differences: discovery
                            .candidates_explain_all_differences,
                        order_only: discovery.order_only,
                    },
                )
            }
            super::policy::ResponseBodyCodec::Hessian2 => {
                let unordered_paths = rule
                    .unordered_paths
                    .iter()
                    .map(|path| match path {
                        super::policy::ResponseBodyUnorderedPath::Hessian2(path) => {
                            Ok(path.clone())
                        }
                        super::policy::ResponseBodyUnorderedPath::Protobuf(_) => {
                            anyhow::bail!(
                                "Hessian2 response-body rule contains a protobuf unordered path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                let joined_string_paths = rule
                    .unordered_joined_string_paths
                    .iter()
                    .map(|path| match path {
                        super::policy::ResponseBodyJoinedStringPath::Hessian2(path) => {
                            Ok(path.clone())
                        }
                        super::policy::ResponseBodyJoinedStringPath::Protobuf(_) => {
                            anyhow::bail!(
                                "Hessian2 response-body rule contains a protobuf joined-string path"
                            )
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                report.body_codec = ResponseBodyCodec::Hessian2;
                let (body_matches, discovery) = hessian2::evaluate_hessian2(
                    expected_body.body(),
                    actual_body.body(),
                    &unordered_paths,
                    &joined_string_paths,
                )
                .context("failed to apply configured Hessian2 response-body rule")?;
                (
                    body_matches,
                    ResponseBodyAssertionReport {
                        codec: rule.codec,
                        envelope: discovery.envelope.as_str().to_string(),
                        configured: true,
                        codec_candidates: vec![rule.codec],
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
                        candidates_explain_all_differences: discovery
                            .candidates_explain_all_differences,
                        order_only: discovery.order_only,
                    },
                )
            }
            codec => anyhow::bail!("unsupported configured response-body codec {codec:?}"),
        };
        report.applied_body_rule_ids.push(rule.id.clone());
        report.body_diagnosis = Some(body_diagnosis);
        if !body_matches || !expected_body.gateway_metadata_matches(&actual_body) {
            if !body_matches {
                report
                    .differences
                    .push(ResponseDifference::exact_body_mismatch());
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
        }
        report.finish(&[], std::slice::from_ref(&rule.id));
        return Ok(report);
    }

    match (
        serde_json::from_slice::<serde_json::Value>(expected_body.body()),
        serde_json::from_slice::<serde_json::Value>(actual_body.body()),
    ) {
        (Ok(expected), Ok(actual)) => {
            report.body_codec = ResponseBodyCodec::Json;
            compare_json(&expected, &actual, &response_fields, &mut report);
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
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
            report.body_codec = ResponseBodyCodec::ExactBytes;
            let bodies_match = expected_body.body() == actual_body.body();
            // Configured response rules are JSON-pointer-based and cannot apply
            // to a non-JSON body. When the bodies are byte-equal there is no
            // difference for any rule to evaluate, so the case passes
            // regardless of configured rules. Only a differing non-JSON body
            // with configured rules is unevaluable, because the rules cannot
            // judge whether the difference would be tolerated.
            ensure!(
                bodies_match || response_fields.is_empty(),
                "response rules require JSON response bodies"
            );
            if !bodies_match {
                report
                    .differences
                    .push(ResponseDifference::exact_body_mismatch());
                let expected_body_value = expected_body.body();
                let actual_body_value = actual_body.body();
                if expected_body_value != actual_body_value {
                    let protobuf_candidate = protobuf::is_protobuf_body(expected_body_value)
                        && protobuf::is_protobuf_body(actual_body_value);
                    let hessian2_candidate = hessian2::is_hessian2_body(expected_body_value)
                        && hessian2::is_hessian2_body(actual_body_value);
                    let mut codec_candidates = Vec::new();
                    if protobuf_candidate {
                        codec_candidates.push(crate::replay::policy::ResponseBodyCodec::Protobuf);
                    }
                    if hessian2_candidate {
                        codec_candidates.push(crate::replay::policy::ResponseBodyCodec::Hessian2);
                    }
                    let diagnostic_codec = if protobuf_candidate {
                        Some(ResponseBodyCodec::Protobuf)
                    } else if hessian2_candidate {
                        Some(ResponseBodyCodec::Hessian2)
                    } else {
                        None
                    };
                    if let Some(codec) = diagnostic_codec {
                        let mut diagnosis =
                            diagnose_response_body(expected_body_value, actual_body_value, codec)?;
                        diagnosis.codec_candidates = codec_candidates;
                        report.body_codec = codec;
                        report.body_diagnosis = Some(diagnosis);
                    }
                }
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
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
