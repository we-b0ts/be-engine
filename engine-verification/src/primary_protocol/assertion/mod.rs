mod artifact;
mod compare;
mod evaluation;
use evaluation::evaluate_response;
pub mod headers;
pub mod native;
mod unified;
pub use headers::date::ResponseHeaderDateCandidate;
mod interaction;
mod joined_string;
pub mod jwt;
mod model;
pub mod time;
pub use time::RequestTimes;
mod payload;
pub use interaction::{compare_outputs_global as compare_interaction_global, decode_sse};
pub use payload::{ResponsePayloadPair, response_payload_pair, response_rule_payload_pair};
pub mod protobuf;
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
use crate::policy::runtime::{
    LoadedReplayPolicy, ResponseBodyCodec, fingerprint, load_replay_policy, uri_path,
};

pub struct ResponseAssertionOptions {
    pub case_id: String,
    pub request: PathBuf,
    pub expected_response: PathBuf,
    pub actual_response: PathBuf,
    pub policy: PathBuf,
}

pub struct ResponseAssertionRuntime {
    policy: LoadedReplayPolicy,
}

impl ResponseAssertionRuntime {
    pub fn needs_time_copies(&self) -> bool {
        self.policy
            .compiled
            .as_ref()
            .and_then(|policy| policy.global_json.as_ref())
            .is_some()
    }
    pub fn load(policy: &Path) -> Result<Self> {
        let policy = load_replay_policy(policy)?;
        policy.prepare_signatures()?;
        Ok(Self { policy })
    }

    pub fn assert_recorded_response(
        &self,
        options: ResponseAssertionOptions,
        request_bytes: &[u8],
        expected_bytes: &[u8],
        actual_bytes: &[u8],
        time_copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    ) -> Result<ResponseAssertionCaseReport> {
        assert_recorded_response_with_policy_and_time_copies(
            options,
            request_bytes,
            expected_bytes,
            actual_bytes,
            &self.policy,
            time_copies,
            ResponseExtent::Complete,
        )
    }

    /// Verify an observed primary response head before its body events arrive.
    pub fn assert_recorded_response_headers(
        &self,
        options: ResponseAssertionOptions,
        request_bytes: &[u8],
        expected_bytes: &[u8],
        actual_bytes: &[u8],
    ) -> Result<ResponseAssertionCaseReport> {
        assert_recorded_response_with_policy_and_time_copies(
            options,
            request_bytes,
            expected_bytes,
            actual_bytes,
            &self.policy,
            &Default::default(),
            ResponseExtent::Headers,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseExtent {
    Headers,
    Complete,
}

pub fn diagnose_response_body(
    expected: &[u8],
    actual: &[u8],
    codec: ResponseBodyCodec,
) -> Result<ResponseBodyAssertionReport> {
    traffic_policy_content::body::diagnose(traffic_extensions::policies(), expected, actual, codec)
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
    assert_recorded_response_with_policy_and_time_copies(
        options,
        request_bytes,
        expected_bytes,
        actual_bytes,
        policy,
        &Default::default(),
        ResponseExtent::Complete,
    )
}

fn assert_recorded_response_with_policy_and_time_copies(
    options: ResponseAssertionOptions,
    request_bytes: &[u8],
    expected_bytes: &[u8],
    actual_bytes: &[u8],
    policy: &LoadedReplayPolicy,
    time_copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    extent: ResponseExtent,
) -> Result<ResponseAssertionCaseReport> {
    policy.prepare_signatures()?;
    let decrypted_request =
        crate::request_headers::decrypt_request_bytes(request_bytes, &options.request)?;
    let request_bytes = decrypted_request.as_deref().unwrap_or(request_bytes);
    let decrypted_expected =
        interaction::decrypt_output_bytes(expected_bytes, &options.expected_response)?;
    let expected_content = decrypted_expected.as_deref().unwrap_or(expected_bytes);
    let decrypted_actual =
        interaction::decrypt_output_bytes(actual_bytes, &options.actual_response)?;
    let actual_content = decrypted_actual.as_deref().unwrap_or(actual_bytes);
    let request: RecordedRequest = serde_json::from_slice(request_bytes)
        .with_context(|| format!("invalid recorded request {}", options.request.display()))?;
    request.gateway_protocol()?;
    let expected: ExpectedResponse =
        serde_json::from_slice(expected_content).with_context(|| {
            format!(
                "invalid expected response {}",
                options.expected_response.display()
            )
        })?;
    let actual: ActualResponse = serde_json::from_slice(actual_content).with_context(|| {
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
    if let Some(primary) = &actual.primary {
        primary.validate_observation(request_bytes, request.timestamp, actual.request_sent_at)?;
    }
    ensure!(
        expected.sse_observation.is_none() && actual.sse_observation.is_none(),
        "legacy SSE observation recordings require re-recording with the interaction lifecycle"
    );
    let expected_interaction = expected.interaction.as_ref();
    let actual_interaction = actual.interaction.as_ref();
    interaction::validate_input(request.interaction.as_ref(), expected_interaction)?;
    let max_message_bytes = request
        .interaction
        .as_ref()
        .map_or(0, |input| input.policy.max_message_bytes);
    let ack_context = interaction::AckContext::prepare(request.interaction.as_ref())?;
    let source_heartbeat_tail = actual_interaction.is_some_and(|actual| {
        actual.end.reason == crate::interaction::model::EndReason::FastHeartbeatTailSkipped
            || actual.end.fast_heartbeat_eof_ms.is_some()
    }) && request
        .interaction
        .as_ref()
        .zip(expected_interaction)
        .is_some_and(|(input, source)| {
            use crate::interaction::replay::heartbeat_tail::{Passive, recognize};
            recognize(input, source).is_some() || Passive::recognize(input, source).is_some()
        });
    let oneway = expected.response_expected == Some(false);
    let expected_status = match expected.status.as_ref() {
        Some(status) => status.code(),
        None if oneway => 204,
        None => anyhow::bail!("expected response has no status"),
    };
    let headers_only = extent == ResponseExtent::Headers;
    let expected_body = match expected.body.as_ref().or(expected.frame.as_ref()) {
        _ if headers_only || expected_interaction.is_some() => Vec::new(),
        Some(body) => decode_body(body, "expected response")?,
        None if oneway => Vec::new(),
        None => anyhow::bail!("expected response has no body or frame"),
    };
    let actual_body = if headers_only || actual_interaction.is_some() {
        Vec::new()
    } else {
        decode_body(&actual.body, "actual response")?
    };
    let actual_status = actual.status;
    let times = RequestTimes {
        source: expected.response_completed_at(),
        target: actual.response_completed_at,
    };
    let request_times = RequestTimes {
        source: request.timestamp,
        target: actual.request_sent_at,
    };
    let interaction_times = RequestTimes {
        source: expected.interaction_started_at(),
        target: actual.interaction_started_at,
    };
    let expected_request_headers = request.headers.clone();
    let expected_body =
        payload::business_body(&request, expected_body, oneway, "expected response")?;
    let actual_body = payload::business_body(&request, actual_body, oneway, "actual response")?;
    let expected_status = expected_body.carrier_status().unwrap_or(expected_status);
    let actual_status = actual_body.carrier_status().unwrap_or(actual_status);
    let mut report = evaluate_response(
        AssertionInputs {
            times,
            request_times,
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
            body_available: !headers_only && expected_interaction.is_none(),
            actual_path: options.actual_response,
            actual_fingerprint: fingerprint(actual_bytes),
        },
        policy,
    )?;
    interaction::compare(
        expected_interaction,
        actual_interaction,
        policy
            .compiled
            .as_ref()
            .and_then(|p| p.global_json.as_ref()),
        interaction_times,
        request_times,
        time_copies,
        &mut report,
        ack_context.as_ref(),
        source_heartbeat_tail,
        max_message_bytes,
    )?;
    if !report.identity_pairs.is_empty() {
        let proposal = crate::value_contract::identities::IdentityDecision::prepare(
            &report.case_id,
            report.identity_pairs.clone(),
        )?;
        if crate::value_contract::identities::IdentityStore::default()
            .validate(&proposal)
            .is_err()
        {
            let mut difference = ResponseDifference::body_value_mismatch();
            difference.pointer = "$identity".into();
            report.differences.push(difference);
        }
    }
    report.passed &= report.differences.is_empty();
    Ok(report)
}

struct AssertionInputs {
    body_available: bool,
    times: RequestTimes,
    request_times: RequestTimes,
    case_id: String,
    request: RecordedRequest,
    request_path: PathBuf,
    expected_request_headers: Option<crate::protocols::recording::events::HeaderMapSnapshot>,
    actual_request_headers: Option<crate::protocols::recording::events::HeaderMapSnapshot>,
    expected_status: u16,
    expected_headers: Option<crate::protocols::recording::events::HeaderMapSnapshot>,
    expected_sse_observation: Option<crate::http::sse::SseObservation>,
    expected_body: AssertionBody,
    expected_path: PathBuf,
    expected_fingerprint: String,
    actual_status: u16,
    actual_headers: Option<crate::protocols::recording::events::HeaderMapSnapshot>,
    actual_sse_observation: Option<crate::http::sse::SseObservation>,
    actual_body: AssertionBody,
    actual_path: PathBuf,
    actual_fingerprint: String,
}

enum AssertionBody {
    Bytes(Vec<u8>),
    #[cfg(any())]
    MotanFrame(motan::ComparableResponseFrame),
}

impl AssertionBody {
    fn body(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            #[cfg(any())]
            Self::MotanFrame(frame) => frame.body(),
        }
    }

    fn gateway_metadata_matches(&self, actual: &Self) -> bool {
        match (self, actual) {
            (Self::Bytes(_), Self::Bytes(_)) => true,
            #[cfg(any())]
            (Self::MotanFrame(expected), Self::MotanFrame(actual)) => {
                expected.carrier() == actual.carrier()
            }
            #[cfg(any())]
            _ => false,
        }
    }

    fn protocol_body_codec(&self) -> Option<ResponseBodyCodec> {
        None
    }

    #[cfg(any())]
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

    fn type_difference(&self, _actual: &Self) -> Option<ResponseDifference> {
        None
    }

    #[cfg(any())]
    fn type_difference(&self, actual: &Self) -> Option<ResponseDifference> {
        let (expected, actual) = match (self, actual) {
            #[cfg(any())]
            (Self::MotanFrame(expected), Self::MotanFrame(actual)) => {
                (expected.body_kind(), actual.body_kind())
            }
            _ => return None,
        };
        (expected != actual)
            .then(|| ResponseDifference::body_type_mismatch(expected.as_str(), actual.as_str()))
    }
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
