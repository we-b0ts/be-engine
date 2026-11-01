//! Immutable response artifacts retain carrier/type checks before rule evaluation.
use super::*;

/// Payload bytes remain private process memory and must not enter plan reports.
pub(crate) struct ResponsePayloadPair {
    pub(crate) status_difference: Option<(u16, u16)>,
    pub(crate) source_interaction: Option<crate::interaction::model::OutputObservation>,
    pub(crate) target_interaction: Option<crate::interaction::model::OutputObservation>,
    pub(crate) body_available: bool,
    pub(crate) source: Vec<u8>,
    pub(crate) target: Option<Vec<u8>>,
    /// Independently observed ordinary response completion events.
    pub(crate) times: RequestTimes,
    pub(crate) request_times: RequestTimes,
    pub(crate) interaction_times: RequestTimes,
    pub(crate) source_headers: Option<crate::recorder::HeaderMapSnapshot>,
    pub(crate) target_headers: Option<crate::recorder::HeaderMapSnapshot>,
}

pub(crate) fn response_payload_pair(
    request: &serde_json::Value,
    source: &serde_json::Value,
    target: Option<&serde_json::Value>,
) -> Result<ResponsePayloadPair> {
    let output = response_rule_payload_pair(request, source, target)?;
    ensure!(
        output.status_difference.is_none(),
        "response status differs"
    );
    Ok(output)
}

/// Rule evidence retains status observations separately from value validation.
/// Artifact decoding and carrier integrity remain mandatory for both sides.
pub(crate) fn response_rule_payload_pair(
    request: &serde_json::Value,
    source: &serde_json::Value,
    target: Option<&serde_json::Value>,
) -> Result<ResponsePayloadPair> {
    let original_request = request;
    let request: RecordedRequest = serde_json::from_value(request.clone())?;
    request.gateway_protocol()?;
    let source: ExpectedResponse = serde_json::from_value(source.clone())?;
    ensure!(
        source.sse_observation.is_none(),
        "legacy SSE observation recordings require re-recording with the interaction lifecycle"
    );
    interaction::validate_input(request.interaction.as_ref(), source.interaction.as_ref())?;
    let body_available = source.interaction.is_none();
    let oneway = source.response_expected == Some(false);
    let source_status = source
        .status
        .as_ref()
        .map(|status| status.code())
        .or(oneway.then_some(204))
        .context("Source response status is absent")?;
    let bytes = match source.body.as_ref().or(source.frame.as_ref()) {
        _ if !body_available => vec![],
        Some(body) => decode_body(body, "Source response")?,
        None if oneway => vec![],
        None => anyhow::bail!("Source response body is absent"),
    };
    let source_body = business_body(&request, bytes, oneway, "Source response")?;
    let source_clock = source.response_completed_at();
    let source_interaction_started_at = source.interaction_started_at();
    let mut output = ResponsePayloadPair {
        status_difference: None,
        source_interaction: source.interaction,
        target_interaction: None,
        body_available,
        source: source_body.body().into(),
        target: None,
        times: RequestTimes {
            source: source_clock,
            target: None,
        },
        request_times: RequestTimes {
            source: request.timestamp,
            target: None,
        },
        interaction_times: RequestTimes {
            source: source_interaction_started_at,
            target: None,
        },
        source_headers: source.headers,
        target_headers: None,
    };
    if let Some(target) = target {
        let target: ActualResponse = serde_json::from_value(target.clone())?;
        if let Some(primary) = &target.primary {
            primary.validate_observation(
                &serde_json::to_vec(original_request)?,
                request.timestamp,
                target.request_sent_at,
            )?;
        }
        ensure!(
            target.version == 1,
            "unsupported Target response artifact version"
        );
        ensure!(
            !body_available || target.interaction.is_none(),
            "Target interaction cannot satisfy an ordinary response body contract"
        );
        let target_body = business_body(
            &request,
            if target.interaction.is_some() {
                vec![]
            } else {
                decode_body(&target.body, "Target response")?
            },
            oneway,
            "Target response",
        )?;
        ensure!(
            source_body.type_difference(&target_body).is_none(),
            "response carrier business type differs"
        );
        ensure!(
            source_body.gateway_metadata_matches(&target_body),
            "response gateway metadata differs"
        );
        let before = source_body.carrier_status().unwrap_or(source_status);
        let after = target_body.carrier_status().unwrap_or(target.status);
        output.status_difference = (before != after).then_some((before, after));
        output.target = Some(target_body.body().into());
        output.target_interaction = target.interaction;
        output.times.target = target.response_completed_at;
        output.request_times.target = target.request_sent_at;
        output.interaction_times.target = target.interaction_started_at;
        output.target_headers = target.headers;
    }
    Ok(output)
}

pub(super) fn business_body(
    request: &RecordedRequest,
    bytes: Vec<u8>,
    oneway: bool,
    label: &str,
) -> Result<AssertionBody> {
    if request.has_motan_frame() && !oneway {
        Ok(AssertionBody::MotanFrame(motan::comparable_response_frame(
            &bytes, label,
        )?))
    } else {
        Ok(AssertionBody::Bytes(bytes))
    }
}

impl AssertionBody {
    pub(super) fn carrier_status(&self) -> Option<u16> {
        match self {
            Self::MotanFrame(frame) => Some(frame.status_code()),
            Self::Bytes(_) => None,
        }
    }
}
