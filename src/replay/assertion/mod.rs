mod artifact;
mod binary_body;
mod compare;
pub(in crate::replay) mod docx;
pub(in crate::replay) mod headers;
pub(crate) mod native;
mod unified;
pub use headers::date::ResponseHeaderDateCandidate;
pub(in crate::replay) mod hessian2;
mod joined_string;
pub(in crate::replay) mod jwt;
mod model;
pub(in crate::replay) mod time;
pub(in crate::replay) use time::RequestTimes;
mod motan;
mod payload;
pub(crate) use payload::response_payload_pair;
pub(in crate::replay) mod protobuf;
mod sse;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use self::artifact::{ActualResponse, ExpectedResponse, RecordedRequest, decode_body};
use self::compare::compare_json;
pub use self::model::{
    DocxBodyDifference, DocxBodyDifferenceKind, Hessian2BodyDifference, Hessian2BodyDifferenceKind,
    Hessian2JoinedStringCandidate, Hessian2ValuePathCandidate, JsonJoinedStringCandidate,
    ProtobufBodyDifference, ProtobufBodyDifferenceKind, ProtobufFieldPathCandidate,
    ProtobufJoinedStringCandidate, ResponseAssertionCaseReport, ResponseBodyAssertionReport,
    ResponseBodyDifferenceDetail, ResponseBodyJoinedStringCandidate,
    ResponseBodyUnorderedPathCandidate, ResponseDifference, ResponseDifferenceKind,
    ResponseGatewayProtocol,
};
use super::policy::{
    LoadedReplayPolicy, ResponseBodyCodec, fingerprint, load_replay_policy, uri_path,
};

pub struct ResponseAssertionOptions {
    pub case_id: String,
    pub request: PathBuf,
    pub expected_response: PathBuf,
    pub actual_response: PathBuf,
    pub policy: PathBuf,
}

pub(crate) struct ResponseAssertionRuntime {
    policy: LoadedReplayPolicy,
}

impl ResponseAssertionRuntime {
    pub(crate) fn load(policy: &Path) -> Result<Self> {
        Ok(Self {
            policy: load_replay_policy(policy)?,
        })
    }

    pub(crate) fn assert_recorded_response(
        &self,
        options: ResponseAssertionOptions,
        request_bytes: &[u8],
        expected_bytes: &[u8],
        actual_bytes: &[u8],
    ) -> Result<ResponseAssertionCaseReport> {
        assert_recorded_response_with_policy(
            options,
            request_bytes,
            expected_bytes,
            actual_bytes,
            &self.policy,
        )
    }
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

pub(crate) fn read_replay_request_times(
    request_path: &Path,
    actual_path: &Path,
) -> Result<RequestTimes> {
    let request: RecordedRequest =
        serde_json::from_slice(&read_regular(request_path, "recorded request")?)?;
    let actual: ActualResponse =
        serde_json::from_slice(&read_regular(actual_path, "actual response")?)?;
    Ok(RequestTimes {
        source: request.timestamp,
        target: actual.request_sent_at,
    })
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
                envelope: discovery.envelope.as_str().to_string(),
                configured: false,
                used_for_verdict: false,
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
                used_for_verdict: false,
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
        ResponseBodyCodec::Docx => docx::diagnose_docx(expected, actual),
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
}

pub fn assert_recorded_response(
    options: ResponseAssertionOptions,
) -> Result<ResponseAssertionCaseReport> {
    let request_bytes = read_regular(&options.request, "recorded request")?;
    let expected_bytes = read_regular(&options.expected_response, "expected response")?;
    let actual_bytes = read_regular(&options.actual_response, "actual response")?;
    let policy = load_replay_policy(&options.policy)?;
    assert_recorded_response_with_policy(
        options,
        &request_bytes,
        &expected_bytes,
        &actual_bytes,
        &policy,
    )
}

fn assert_recorded_response_with_policy(
    options: ResponseAssertionOptions,
    request_bytes: &[u8],
    expected_bytes: &[u8],
    actual_bytes: &[u8],
    policy: &LoadedReplayPolicy,
) -> Result<ResponseAssertionCaseReport> {
    let request: RecordedRequest = serde_json::from_slice(request_bytes)
        .with_context(|| format!("invalid recorded request {}", options.request.display()))?;
    let expected: ExpectedResponse = serde_json::from_slice(expected_bytes).with_context(|| {
        format!(
            "invalid expected response {}",
            options.expected_response.display()
        )
    })?;
    let actual: ActualResponse = serde_json::from_slice(actual_bytes).with_context(|| {
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
    let actual_status = actual.status;
    let expected_request_headers = request.headers.clone();
    let expected_body =
        payload::business_body(&request, expected_body, oneway, "expected response")?;
    let actual_body = payload::business_body(&request, actual_body, oneway, "actual response")?;
    let expected_status = expected_body.carrier_status().unwrap_or(expected_status);
    let actual_status = actual_body.carrier_status().unwrap_or(actual_status);
    evaluate_response(
        AssertionInputs {
            times: RequestTimes {
                source: request.timestamp,
                target: actual.request_sent_at,
            },
            case_id: options.case_id,
            request,
            request_path: options.request,
            expected_request_headers,
            actual_request_headers: actual.request_headers,
            expected_status,
            expected_headers: expected.headers,
            expected_sse_observation: expected.sse_observation,
            expected_body,
            expected_path: options.expected_response,
            expected_fingerprint: fingerprint(expected_bytes),
            actual_status,
            actual_headers: actual.headers,
            actual_sse_observation: actual.sse_observation,
            actual_body,
            actual_path: options.actual_response,
            actual_fingerprint: fingerprint(actual_bytes),
        },
        policy,
    )
}

struct AssertionInputs {
    times: RequestTimes,
    case_id: String,
    request: RecordedRequest,
    request_path: PathBuf,
    expected_request_headers: Option<crate::recorder::HeaderMapSnapshot>,
    actual_request_headers: Option<crate::recorder::HeaderMapSnapshot>,
    expected_status: u16,
    expected_headers: Option<crate::recorder::HeaderMapSnapshot>,
    expected_sse_observation: Option<crate::http::sse::SseObservation>,
    expected_body: AssertionBody,
    expected_path: PathBuf,
    expected_fingerprint: String,
    actual_status: u16,
    actual_headers: Option<crate::recorder::HeaderMapSnapshot>,
    actual_sse_observation: Option<crate::http::sse::SseObservation>,
    actual_body: AssertionBody,
    actual_path: PathBuf,
    actual_fingerprint: String,
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

    fn protocol_body_codec(&self) -> Option<ResponseBodyCodec> {
        let body_kind = match self {
            Self::MotanFrame(frame) => frame.body_kind(),
            Self::Bytes(_) => return None,
        };
        match body_kind {
            motan::ComparableBodyKind::Motan1Hessian2Value => Some(ResponseBodyCodec::Hessian2),
            _ => None,
        }
    }

    fn type_difference(&self, actual: &Self) -> Option<ResponseDifference> {
        let (expected, actual) = match (self, actual) {
            (Self::MotanFrame(expected), Self::MotanFrame(actual)) => {
                (expected.body_kind(), actual.body_kind())
            }
            _ => return None,
        };
        (expected != actual)
            .then(|| ResponseDifference::body_type_mismatch(expected.as_str(), actual.as_str()))
    }
}

fn evaluate_response(
    inputs: AssertionInputs,
    loaded: &LoadedReplayPolicy,
) -> Result<ResponseAssertionCaseReport> {
    let AssertionInputs {
        times,
        case_id,
        request,
        request_path,
        expected_request_headers,
        actual_request_headers,
        expected_status,
        expected_headers,
        expected_sse_observation,
        expected_body,
        expected_path,
        expected_fingerprint,
        actual_status,
        actual_headers,
        actual_sse_observation,
        actual_body,
        actual_path,
        actual_fingerprint,
    } = inputs;
    ensure!(
        loaded.document.version >= 3,
        "runner-owned response assertions require replay policy version 3"
    );
    let path = uri_path(&request.uri);
    let source_request_body = request
        .body
        .as_ref()
        .map(|body| decode_body(body, "immutable Source request"))
        .transpose()?
        .and_then(|body| crate::json_value::parse(&body));
    let native_selected = loaded
        .compiled
        .as_ref()
        .map(|compiled| {
            native::selected(
                compiled,
                &request.method,
                &path,
                source_request_body.as_ref(),
            )
        })
        .unwrap_or_default();
    let native_root = if native::needs_startup(&native_selected) {
        crate::config::resolve_unified_policy_root(&loaded.path)?
    } else {
        PathBuf::from(".")
    };
    let native_context = loaded
        .compiled
        .as_ref()
        .map(|_| {
            native::NativeResponseContext::from_rules(
                &native_selected,
                &native_root,
                request_path.parent().unwrap_or(Path::new(".")),
            )
        })
        .transpose();
    let (native_context, native_key_unavailable) = match native_context {
        Ok(context) => (context, false),
        Err(_)
            if native_selected.iter().any(|rule| {
                matches!(
                    rule.rule.effect,
                    crate::policy::NativeEffect::ResponseJwt(_)
                )
            }) =>
        {
            (None, true)
        }
        Err(error) => return Err(error),
    };
    let native_body_ids = native_selected.iter().filter(|rule|
        matches!(&rule.rule.effect, crate::policy::NativeEffect::ResponseBody(effect) if effect.codec != crate::policy::native::BodyCodec::Json))
        .map(|rule| rule.rule.id.clone()).collect::<Vec<_>>();
    let native_headers = loaded
        .compiled
        .as_ref()
        .map(|_| {
            let rules = native_selected.iter().copied().cloned().collect::<Vec<_>>();
            super::policy::native_projection::project_native(&rules)
        })
        .transpose()?;
    let response_rules = native_headers
        .as_ref()
        .map_or(&loaded.document.response_rules, |projection| {
            &projection.document.response_rules
        });
    let response_fields = response_rules.matching_replay_fields(&request.method, &path);
    let body_rules = response_rules.matching_response_body_rules(&request.method, &path);
    let body_rules = if loaded.compiled.is_some() {
        native::body::merge_opaque(body_rules)?
    } else {
        body_rules
    };
    ensure!(
        body_rules.len() <= 1,
        "multiple response-body rules match {} {}",
        request.method,
        path
    );
    let gateway_protocol = request.gateway_protocol()?;
    let unified_rules = unified::selected(loaded, &request, &path)?;
    let mut report = ResponseAssertionCaseReport::new(
        case_id,
        request.method.clone(),
        path,
        gateway_protocol,
        request_path.display().to_string(),
        loaded.path.display().to_string(),
        loaded.fingerprint.clone(),
        expected_path.display().to_string(),
        expected_fingerprint,
        actual_path.display().to_string(),
        actual_fingerprint,
    );
    if native_key_unavailable {
        let mut difference = ResponseDifference::body_value_mismatch();
        difference.kind = ResponseDifferenceKind::JwtSigningKeyUnavailable;
        report.differences.push(difference);
    }
    if expected_status != actual_status {
        report
            .differences
            .push(ResponseDifference::status(expected_status, actual_status));
    }
    if gateway_protocol == ResponseGatewayProtocol::Http {
        sse::compare(
            expected_sse_observation,
            actual_sse_observation,
            &mut report,
        );
        headers::compare_with_rules(
            expected_headers.as_ref(),
            actual_headers.as_ref(),
            expected_request_headers.as_ref(),
            actual_request_headers.as_ref(),
            native_headers
                .as_ref()
                .map_or(&loaded.document.response_rules.headers, |projection| {
                    &projection.document.response_rules.headers
                }),
            times,
            &mut report,
        )?;
    }
    if let Some(projection) = &native_headers {
        for id in report
            .applied_header_rule_ids
            .iter_mut()
            .chain(&mut report.unused_applicable_header_rule_ids)
        {
            if let Some(native_id) = projection.response_aliases.get(id) {
                *id = native_id.clone();
            }
        }
    }
    if !unified_rules.is_empty()
        || native_context
            .as_ref()
            .is_some_and(|context| !context.is_empty())
    {
        let mut applicable_ids = unified_rules
            .iter()
            .map(|rule| rule.rule.id.clone())
            .collect::<Vec<_>>();
        if let Some(context) = native_context
            .as_ref()
            .filter(|context| !context.is_empty())
        {
            let codec = context.payload_codec(&unified_rules)?;
            ensure!(
                body_rules.is_empty()
                    || matches!(codec, crate::policy::Codec::Protobuf(_))
                        && body_rules
                            .iter()
                            .all(|rule| rule.codec == ResponseBodyCodec::Protobuf),
                "native value contracts cannot consume another opaque body codec"
            );
            let comparison = context.compare_encoded(
                expected_body.body(),
                actual_body.body(),
                &unified_rules,
                crate::value_contract::json::AnchorClocks {
                    case: times,
                    ..Default::default()
                },
            )?;
            applicable_ids.extend(context.rule_ids());
            report.body_codec = if matches!(codec, crate::policy::Codec::Protobuf(_)) {
                ResponseBodyCodec::Protobuf
            } else {
                ResponseBodyCodec::Json
            };
            if report.body_codec == ResponseBodyCodec::Protobuf && !comparison.passed() {
                if let Ok(mut diagnosis) = diagnose_response_body(
                    expected_body.body(),
                    actual_body.body(),
                    ResponseBodyCodec::Protobuf,
                ) {
                    diagnosis.configured = true;
                    diagnosis.used_for_verdict = false;
                    report.body_diagnosis = Some(diagnosis);
                }
            }
            report.applied_body_rule_ids.extend(comparison.evaluated);
            for diff in comparison.differences {
                report.differences.push(unified::contract_difference(diff));
            }
            if let Some(difference) = expected_body.type_difference(&actual_body) {
                report.differences.push(difference);
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
        } else {
            ensure!(
                body_rules.is_empty(),
                "generic and native opaque body contracts require one compiled codec owner"
            );
            unified::compare(
                &unified_rules,
                &expected_body,
                &actual_body,
                times,
                &mut report,
            )?;
        }
        applicable_ids.retain(|id| report.applied_body_rule_ids.contains(id));
        report.finish(&[], &applicable_ids);
        return Ok(report);
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
                        envelope: discovery.envelope.as_str().to_string(),
                        configured: true,
                        used_for_verdict: true,
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
                        used_for_verdict: true,
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
            super::policy::ResponseBodyCodec::Docx => {
                ensure!(
                    rule.unordered_paths.is_empty()
                        && rule.unordered_joined_string_paths.is_empty(),
                    "DOCX response-body rule cannot contain typed collection paths"
                );
                report.body_codec = ResponseBodyCodec::Docx;
                docx::evaluate_docx(
                    expected_body.body(),
                    actual_body.body(),
                    &rule.docx_timestamps,
                    times,
                )
                .context("failed to apply configured DOCX response-body rule")?
            }
            codec => anyhow::bail!("unsupported configured response-body codec {codec:?}"),
        };
        if loaded.compiled.is_some() {
            report.applied_body_rule_ids.extend(native_body_ids.clone());
        } else {
            report.applied_body_rule_ids.push(rule.id.clone());
        }
        report.body_diagnosis = Some(body_diagnosis);
        let body_type_difference = expected_body.type_difference(&actual_body);
        if !body_matches
            || body_type_difference.is_some()
            || !expected_body.gateway_metadata_matches(&actual_body)
        {
            if !body_matches {
                report
                    .differences
                    .push(ResponseDifference::body_value_mismatch());
            }
            if let Some(difference) = body_type_difference {
                report.differences.push(difference);
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
        }
        report.finish(
            &[],
            if loaded.compiled.is_some() {
                &native_body_ids
            } else {
                std::slice::from_ref(&rule.id)
            },
        );
        return Ok(report);
    }

    if expected_body.protocol_body_codec() == Some(ResponseBodyCodec::Hessian2)
        && actual_body.protocol_body_codec() == Some(ResponseBodyCodec::Hessian2)
    {
        ensure!(
            response_fields.is_empty(),
            "JSON response rules cannot apply to a Motan1 Hessian2 value response"
        );
        report.body_codec = ResponseBodyCodec::Hessian2;
        let (body_matches, discovery) =
            hessian2::evaluate_hessian2(expected_body.body(), actual_body.body(), &[], &[])
                .context("failed to compare Motan1 Hessian2 value response bodies")?;
        report.body_diagnosis = Some(ResponseBodyAssertionReport {
            codec: ResponseBodyCodec::Hessian2,
            envelope: discovery.envelope.as_str().to_string(),
            configured: false,
            used_for_verdict: true,
            codec_candidates: vec![ResponseBodyCodec::Hessian2],
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
        });
        if !body_matches {
            report
                .differences
                .push(ResponseDifference::body_value_mismatch());
        }
        if let Some(difference) = expected_body.type_difference(&actual_body) {
            report.differences.push(difference);
        }
        if !expected_body.gateway_metadata_matches(&actual_body) {
            report
                .differences
                .push(ResponseDifference::gateway_metadata_mismatch());
        }
        report.finish(&[], &[]);
        return Ok(report);
    }

    match (
        serde_json::from_slice::<serde_json::Value>(expected_body.body()),
        serde_json::from_slice::<serde_json::Value>(actual_body.body()),
    ) {
        (Ok(expected), Ok(actual)) => {
            report.body_codec = ResponseBodyCodec::Json;
            let applicable_fields =
                compare_json(&expected, &actual, &response_fields, &mut report, times);
            if let Some(difference) = expected_body.type_difference(&actual_body) {
                report.differences.push(difference);
            }
            if !expected_body.gateway_metadata_matches(&actual_body) {
                report
                    .differences
                    .push(ResponseDifference::gateway_metadata_mismatch());
            }
            report.finish(&applicable_fields, &[]);
        }
        _ => {
            report.body_codec = ResponseBodyCodec::ExactBytes;
            let bodies_match = expected_body.body() == actual_body.body();
            let body_type_difference = expected_body.type_difference(&actual_body);
            // Configured response rules are JSON-pointer-based and cannot apply
            // to a non-JSON body. When the bodies are byte-equal there is no
            // difference for any rule to evaluate, so the case passes
            // regardless of configured rules. Only a differing non-JSON body
            // with configured rules is unevaluable, because the rules cannot
            // judge whether the difference would be tolerated.
            ensure!(
                (bodies_match && body_type_difference.is_none()) || response_fields.is_empty(),
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
                    let docx_candidate = docx::is_docx_body(expected_body_value)
                        && docx::is_docx_body(actual_body_value);
                    let mut codec_candidates = Vec::new();
                    if protobuf_candidate {
                        codec_candidates.push(crate::replay::policy::ResponseBodyCodec::Protobuf);
                    }
                    if hessian2_candidate {
                        codec_candidates.push(crate::replay::policy::ResponseBodyCodec::Hessian2);
                    }
                    if docx_candidate {
                        codec_candidates.push(crate::replay::policy::ResponseBodyCodec::Docx);
                    }
                    let diagnostic_codec = if protobuf_candidate {
                        Some(ResponseBodyCodec::Protobuf)
                    } else if hessian2_candidate {
                        Some(ResponseBodyCodec::Hessian2)
                    } else if docx_candidate {
                        Some(ResponseBodyCodec::Docx)
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
            if let Some(difference) = body_type_difference {
                report.differences.push(difference);
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
