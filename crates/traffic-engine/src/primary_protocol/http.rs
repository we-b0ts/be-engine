//! HTTP and HTTP interaction execution delegates to the established native client.
pub(super) mod close_timing;
use super::{
    ApiIdentity, CaseClock, CaseExecutionContext, Metadata, NativePrimaryAdapter,
    PrimaryObservation, PrimaryOutput,
};
use crate::protocol_contract::NativeProtocolVersion;
use anyhow::Result;

pub(crate) struct HttpPrimary<'a> {
    bytes: &'a [u8],
    api: ApiIdentity,
    source_started_at: Option<chrono::DateTime<chrono::Utc>>,
    interaction: bool,
}

impl<'a> HttpPrimary<'a> {
    pub(super) fn from_recorded(bytes: &'a [u8], metadata: Metadata) -> Result<Self> {
        let uri: hyper::Uri = metadata.uri.parse()?;
        let method: hyper::Method = metadata.method.parse()?;
        Ok(Self {
            bytes,
            api: ApiIdentity::Http {
                method: method.to_string(),
                route: metadata
                    .api_pattern
                    .unwrap_or_else(|| uri.path().to_owned()),
            },
            source_started_at: metadata.timestamp,
            interaction: metadata.interaction.is_some(),
        })
    }

    pub(super) fn has_interaction(&self) -> bool {
        self.interaction
    }
}

impl NativePrimaryAdapter for HttpPrimary<'_> {
    fn api(&self) -> &ApiIdentity {
        &self.api
    }

    fn native_version(&self) -> NativeProtocolVersion {
        NativeProtocolVersion::Http
    }

    async fn execute(&self, context: &CaseExecutionContext<'_>) -> Result<PrimaryOutput> {
        let response = crate::recorded_request::RecordedHttpClient::new(
            context.settings.http_origin.to_owned(),
            context.remaining(),
            context.settings.max_response_bytes,
        )
        .with_execution_failure(context.dependency_failure.clone())
        .with_socketio_timing(context.settings.socketio_timing)
        .with_request_rule_runtime(context.request_rules.clone())
        .with_input_registration(context.session_path, context.case_id)
        .send_recorded_bytes(self.bytes, context.request_path)
        .await?;
        Ok(PrimaryOutput {
            api: self.api.clone(),
            response_completed_at: Some(response.response_completed_at),
            clocks: CaseClock {
                source_request_started_at: self.source_started_at,
                target_request_started_at: response.request_sent_at,
            },
            observation: PrimaryObservation::Http(Box::new(response)),
        })
    }
}
