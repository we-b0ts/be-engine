//! Application compatibility for historical HTTP evidence queries.
use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::Path;
pub(crate) use traffic_protocol_http::{multipart, request_contract::uri_mismatch_reason};
pub(crate) mod diagnosis;
pub(crate) mod request_headers {
    pub(crate) use traffic_protocol_http::headers::exact_contract_match;
}
pub(crate) mod contracts {
    use super::*;
    use crate::policy::{Protocol, Slot, Surface};
    use crate::policy_evidence::WitnessMetadata;
    use traffic_contract::compare::AnchorClocks;
    pub(crate) fn source_witness(
        event: &Value,
        surface: Surface,
        key_context: &Path,
    ) -> Result<Vec<u8>> {
        traffic_protocol_http::witness::source_payload(
            event,
            surface.dependency_side()?,
            &crate::request_headers::SourceSecrets::new(key_context),
        )
    }
    pub(crate) fn witness_value(bytes: &[u8], surface: Surface) -> Result<Option<Vec<u8>>> {
        traffic_protocol_http::witness::witness_value(bytes, surface.dependency_side()?)
    }
    pub(crate) fn multipart_witness_matches(
        source: &[u8],
        target: &[u8],
        surface: Surface,
    ) -> Result<bool> {
        traffic_protocol_http::witness::multipart_witness_matches(
            source,
            target,
            surface.dependency_side()?,
        )
    }
    pub(crate) fn validate_witness(
        source: &[u8],
        target: &[u8],
        surface: Surface,
        clocks: AnchorClocks,
    ) -> Result<()> {
        traffic_protocol_http::witness::validate_witness(
            source,
            target,
            surface.dependency_side()?,
            clocks,
        )
    }
    pub(crate) fn witness_metadata_matches(
        event: &Value,
        metadata: &WitnessMetadata,
    ) -> Result<()> {
        let record: traffic_protocol_http::recorded::RecordedExchange =
            serde_json::from_value(event.clone())?;
        let (_, endpoint) = record.identity()?;
        ensure!(
            record.id.as_deref().is_some_and(|id| !id.is_empty())
                && metadata.source.exchange_id == record.id
                && metadata.source.connection_id.is_none()
                && metadata.source.sequence.is_none()
                && metadata.slot == Slot::Body
                && metadata.operation.eq_ignore_ascii_case(&record.method)
                && metadata
                    .resource
                    .as_ref()
                    .is_some_and(|resource| resource.protocol == Protocol::Http
                        && resource.endpoint.host.eq_ignore_ascii_case(&endpoint.host)
                        && resource.endpoint.port == endpoint.port
                        && resource.database.is_none()
                        && resource.username.is_none()),
            "HTTP protected witness identity differs from immutable Source exchange"
        );
        Ok(())
    }
}
pub(crate) mod cross_case {
    use super::*;
    pub use traffic_protocol_http::request_contract::HttpCrossCaseSelector;
    pub(crate) fn discover(_: &Path, _: &Path, _: bool) -> Result<Value> {
        anyhow::bail!(
            "HTTP finite sharing discovery requires an installed native sharing capability"
        )
    }
    pub(crate) fn verify_candidate(_: &Path, _: &Path, _: &HttpCrossCaseSelector) -> Result<Value> {
        anyhow::bail!("HTTP finite sharing requires an installed native sharing capability")
    }
}

#[cfg(test)]
pub(crate) use super::http_test_support as tests;
#[cfg(test)]
pub(crate) async fn handle_http_replay_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    target: crate::replay::ReplayTarget,
    state: std::sync::Arc<tokio::sync::Mutex<super::ReplayState>>,
    _: std::sync::Arc<crate::MitmCa>,
) -> Result<()> {
    crate::replay::native::handle_connection(stream, peer, target, state).await
}
