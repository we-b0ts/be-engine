//! Native requests enter the common observe/select/wait/commit execution loop.
use super::*;
use traffic_contract::{compare::Comparison, identity::IdentityDecision};
use traffic_protocol::message::{MessageEncoder, ProtocolMessage};

pub struct Request {
    pub protocol: ProtocolId,
    pub endpoint: Endpoint,
    pub message: Arc<dyn ProtocolMessage>,
    pub session: Option<Uuid>,
    pub lane: Option<String>,
    pub request_session: Option<traffic_protocol::connection::RequestSession>,
    pub session_owner: Option<SessionOwner>,
    pub admission: RequestAdmission,
    pub observed: DateTime<Utc>,
    pub bytes: usize,
    pub diagnostics: diagnosis::CandidateDiagnostics,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RequestAdmission {
    Required,
    LegacyControl,
    DriverObservation,
    SessionControl,
    AutocommitCompletion,
}

impl RequestAdmission {
    pub fn allows_local_response(self) -> bool {
        matches!(
            self,
            Self::LegacyControl | Self::DriverObservation | Self::SessionControl
        )
    }
}

#[derive(Clone)]
pub struct SessionOwner {
    pub scope: ReplaySource,
    pub case: Option<String>,
    pub epoch: Option<u64>,
}

pub struct Matched {
    pub index: usize,
    pub ticket: admission::ClaimTicket,
    pub observed: DateTime<Utc>,
    pub delay: std::time::Duration,
    pub case: Option<String>,
    pub epoch: u64,
    pub run_owned: bool,
    pub storage: super::StorageDelivery,
}

pub struct Rejected {
    pub reason: String,
    pub blocker: Option<usize>,
    pub kind: RejectionKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RejectionKind {
    NoMatch,
    UnverifiedSession,
    Other,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}
impl std::fmt::Debug for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}
impl std::error::Error for Rejected {}
impl From<anyhow::Error> for Rejected {
    fn from(error: anyhow::Error) -> Self {
        Self {
            reason: error.to_string(),
            blocker: None,
            kind: RejectionKind::Other,
        }
    }
}

pub fn identity(
    owner: &dyn policy::ValueRuleHost,
    inventory: &Inventory,
    index: usize,
    comparison: &Comparison,
) -> Result<IdentityDecision> {
    let scope = inventory.scope(index);
    owner.preview_identity_pairs(
        &scope,
        &comparison.identity_pairs(),
        inventory.core.exchanges[index].source.source == ReplaySource::Case,
    )
}

pub struct ResponsePlan {
    pub output: Box<dyn traffic_protocol::output::OutputStream>,
    pub comparison: Comparison,
    pub identity: IdentityDecision,
}

impl ResponsePlan {
    fn from_packet(packet: stored::PacketDelivery) -> Self {
        Self {
            output: Box::new(traffic_protocol::output::SingleOutput::new(packet.bytes)),
            comparison: packet.comparison,
            identity: packet.identity,
        }
    }
}

impl Inventory {
    pub fn render_response(
        &self,
        index: usize,
        observed: DateTime<Utc>,
        loaded: Option<&dyn MessageEncoder>,
        storage: &super::StorageDelivery,
    ) -> Result<ResponsePlan> {
        self.render_loaded_response(index, observed, loaded, None, storage)
    }

    pub fn render_prefetched_response(
        &self,
        index: usize,
        observed: DateTime<Utc>,
        loaded: &mut LoadedResponse,
        storage: &super::StorageDelivery,
    ) -> Result<(ResponsePlan, bool)> {
        match &mut loaded.kind {
            stored::LoadedResponseKind::Stable(source) => {
                if self.owns_stable_source(index, source)
                    && storage.is_empty()
                    && let Some(packet) = source.packet.take()
                {
                    self.observe_prepared_rules(std::mem::take(&mut source.observed_rules));
                    return Ok((ResponsePlan::from_packet(packet), true));
                }
                // A compact packet belongs to one response in one Session.
                // The normal path still works if a caller cannot reuse it.
                let response = &self.core.exchanges[index].native.response;
                let decoded = response.stored().map(|stored| stored.load()).transpose()?;
                self.render_response(index, observed, decoded.as_deref(), storage)
                    .map(|plan| (plan, false))
            }
            stored::LoadedResponseKind::Decoded { encoder, source } => {
                if let Some(source) = source {
                    self.observe_prepared_rules(std::mem::take(&mut source.observed_rules));
                    if let Some(packet) = source.packet.take()
                        && self.event_session
                        && storage.is_empty()
                        && packet
                            .is_current(self.contracts.as_ref(), Self::EVENT_SESSION_VALUE_SCOPE)
                    {
                        return Ok((ResponsePlan::from_packet(packet.delivery), true));
                    }
                }
                self.render_loaded_response(
                    index,
                    observed,
                    Some(encoder.as_ref()),
                    source.as_ref(),
                    storage,
                )
                .map(|plan| (plan, false))
            }
        }
    }

    fn render_loaded_response(
        &self,
        index: usize,
        observed: DateTime<Utc>,
        loaded: Option<&dyn MessageEncoder>,
        source: Option<&stored::PreparedSource>,
        storage: &super::StorageDelivery,
    ) -> Result<ResponsePlan> {
        let exchange = &self.core.exchanges[index];
        let prepared;
        let (response, encoder) = if let (Some(source), Some(encoder)) = (source, loaded) {
            (&source.message, encoder)
        } else if let Some(encoder) = loaded {
            let (clocks, delivered) = stored::recorded_clocks(
                self.contracts.as_ref(),
                exchange.source.case_id.as_deref(),
                exchange.source.capture.as_ref(),
                exchange.native.response_delay,
            );
            prepared = self.prepare_response_message(
                &exchange.native,
                clocks,
                delivered,
                encoder,
                self.contracts.as_ref(),
            )?;
            (&prepared, encoder)
        } else {
            (
                exchange
                    .response
                    .as_ref()
                    .context("response was not prepared")?,
                exchange.native.response.as_ref(),
            )
        };
        let scope = self.scope(index);
        let clocks = self.clocks(index, observed, true);
        let storage_values = self.storage_values(index, storage, response)?;
        let rendered = response.render_delivery_with_prepared_documents(
            clocks,
            self.contracts.metadata(),
            &exchange.delivery,
            &storage_values,
            |selected| {
                self.contracts
                    .identity_deliveries(&scope, selected)
                    .map(|(values, _)| values)
            },
            |source, delivered, prepared| {
                if let Some(prepared) = prepared
                    && prepared.apply(&scope, source, delivered, clocks)?
                {
                    return Ok(());
                }
                self.contracts
                    .translate_delivery_document(&scope, source, delivered, clocks)
            },
        )?;
        let proposed = identity(self.contracts.as_ref(), self, index, &rendered.comparison)?;
        let response = encoder.output(&rendered.values)?;
        Ok(ResponsePlan {
            output: response,
            comparison: rendered.comparison,
            identity: proposed,
        })
    }
}
