//! Immutable response artifacts retain carrier/type checks before rule evaluation.
use super::*;

/// Payload bytes remain private process memory and must not enter plan reports.
pub(crate) struct ResponsePayloadPair {
    pub(crate) source: Vec<u8>,
    pub(crate) target: Option<Vec<u8>>,
    pub(crate) times: RequestTimes,
    pub(crate) source_headers: Option<crate::recorder::HeaderMapSnapshot>,
    pub(crate) target_headers: Option<crate::recorder::HeaderMapSnapshot>,
}

pub(crate) fn response_payload_pair(
    request: &serde_json::Value,
    source: &serde_json::Value,
    target: Option<&serde_json::Value>,
) -> Result<ResponsePayloadPair> {
    let request: RecordedRequest = serde_json::from_value(request.clone())?;
    request.gateway_protocol()?;
    let source: ExpectedResponse = serde_json::from_value(source.clone())?;
    let oneway = source.response_expected == Some(false);
    let source_status = source
        .status
        .as_ref()
        .map(|status| status.code())
        .or(oneway.then_some(204))
        .context("Source response status is absent")?;
    let bytes = match source.body.as_ref().or(source.frame.as_ref()) {
        Some(body) => decode_body(body, "Source response")?,
        None if oneway => vec![],
        None => anyhow::bail!("Source response body is absent"),
    };
    let source_body = business_body(&request, bytes, oneway, "Source response")?;
    let mut output = ResponsePayloadPair {
        source: source_body.body().into(),
        target: None,
        times: RequestTimes {
            source: request.timestamp,
            target: None,
        },
        source_headers: source.headers,
        target_headers: None,
    };
    if let Some(target) = target {
        let target: ActualResponse = serde_json::from_value(target.clone())?;
        ensure!(
            target.version == 1,
            "unsupported Target response artifact version"
        );
        let target_body = business_body(
            &request,
            decode_body(&target.body, "Target response")?,
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
        ensure!(
            source_body.carrier_status().unwrap_or(source_status)
                == target_body.carrier_status().unwrap_or(target.status),
            "response status differs"
        );
        output.target = Some(target_body.body().into());
        output.times.target = target.request_sent_at;
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
