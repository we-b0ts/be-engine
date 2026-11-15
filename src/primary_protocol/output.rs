//! Independent Target output; expected Source responses never enter the driver.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::{ApiIdentity, CaseClock};
use crate::protocols::recording::events::HeaderMapSnapshot;

pub(crate) enum PrimaryObservation {
    Http(Box<crate::recorded_request::RecordedHttpResponse>),
    Motan {
        status: u16,
        response_frame: Vec<u8>,
    },
}

pub(crate) struct PrimaryOutput {
    pub(crate) api: ApiIdentity,
    pub(crate) clocks: CaseClock,
    pub(crate) response_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) observation: PrimaryObservation,
}

#[derive(Serialize)]
struct ActualResponse<'a> {
    primary: PrimaryMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    interaction_started_at: Option<chrono::DateTime<chrono::Utc>>,
    version: u8,
    request_sent_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_rules: &'a Vec<crate::request_rules::RequestRuleObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_headers: Option<&'a HeaderMapSnapshot>,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<&'a HeaderMapSnapshot>,
    body: CapturedBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    sse_observation: Option<&'a crate::http::sse::SseObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interaction: Option<&'a crate::interaction::model::OutputObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrimaryMetadata {
    pub(crate) api: ApiIdentity,
    pub(crate) clocks: crate::policy_evidence::WitnessClocks,
}

impl PrimaryMetadata {
    pub(crate) fn validate_observation(
        &self,
        request: &[u8],
        source_started_at: Option<chrono::DateTime<chrono::Utc>>,
        target_started_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<()> {
        use super::{NativePrimaryAdapter, PrimaryProtocol};
        let input = PrimaryProtocol::from_recorded(request)?;
        anyhow::ensure!(
            self.api == *input.api(),
            "actual primary API identity differs from the recorded input"
        );
        anyhow::ensure!(
            self.clocks.case.source == source_started_at
                && self.clocks.case.target == target_started_at
                && target_started_at.is_some(),
            "actual primary clocks differ from independent request observations"
        );
        anyhow::ensure!(
            self.clocks.dependency == Default::default()
                && self.clocks.delivery == Default::default(),
            "primary metadata cannot supply dependency or delivery clocks"
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct CapturedBody {
    encoding: &'static str,
    data: String,
    truncated: bool,
}

impl CapturedBody {
    fn from_bytes(bytes: &[u8]) -> Self {
        let (encoding, data) = match std::str::from_utf8(bytes) {
            Ok(text) => ("utf8", text.to_owned()),
            Err(_) => ("base64", STANDARD.encode(bytes)),
        };
        Self {
            encoding,
            data,
            truncated: false,
        }
    }
}

impl PrimaryOutput {
    pub(crate) fn artifact(&self) -> anyhow::Result<serde_json::Value> {
        let empty_rules = Vec::new();
        let metadata = || PrimaryMetadata {
            api: self.api.clone(),
            clocks: crate::policy_evidence::WitnessClocks {
                case: self.clocks.anchors(),
                ..Default::default()
            },
        };
        let response = match &self.observation {
            PrimaryObservation::Http(response) => ActualResponse {
                primary: metadata(),
                interaction_started_at: response.interaction_started_at,
                version: 1,
                request_sent_at: self.clocks.target_request_started_at,
                response_completed_at: self.response_completed_at,
                request_rules: &response.request_rules,
                request_headers: Some(&response.request_headers),
                status: response.status.as_u16(),
                headers: Some(&response.headers),
                body: CapturedBody::from_bytes(&response.body),
                sse_observation: response.sse_observation.as_ref(),
                interaction: response.interaction.as_ref(),
            },
            PrimaryObservation::Motan {
                status,
                response_frame,
            } => ActualResponse {
                primary: metadata(),
                interaction_started_at: None,
                version: 1,
                request_sent_at: self.clocks.target_request_started_at,
                response_completed_at: self.response_completed_at,
                request_rules: &empty_rules,
                request_headers: None,
                status: *status,
                headers: None,
                body: CapturedBody::from_bytes(response_frame),
                sse_observation: None,
                interaction: None,
            },
        };
        let mut value = serde_json::to_value(response)?;
        crate::interaction::artifact::prepare_output(&mut value);
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
