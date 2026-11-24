//! Decode an immutable stored response for Replay delivery or read-ahead.
use super::*;
use crate::dependency_index::RecordRef;
use bytes::Bytes;
use traffic_contract::{
    compare::{AnchorClocks, Comparison},
    identity::IdentityDecision,
    time::ClockPair,
};
use traffic_policy_value::{PreparedDeliveryGuard, PreparedMessage};
use traffic_protocol::message::{MessageEncoder, ProjectedMessage, ProtocolMessage, StoredMessage};

pub(super) struct Response {
    pub reference: RecordRef,
    pub providers: Arc<crate::protocols::DependencyProviders>,
    pub protocol: crate::protocols::DependencyProtocol,
    pub structure: Option<Value>,
}

pub struct ResponsePreparation {
    response: Arc<dyn MessageEncoder>,
    source: Option<FrozenSource>,
}

struct FrozenSource {
    providers: Arc<crate::protocols::DependencyProviders>,
    contracts: Arc<dyn policy::ValueRuleHost>,
    protocol: ProtocolId,
    clocks: AnchorClocks,
    delivered: Option<DateTime<Utc>>,
    packet_scope: Option<&'static str>,
}

pub struct LoadedResponse {
    pub(super) encoder: Arc<dyn MessageEncoder>,
    pub(super) source: Option<PreparedSource>,
    bytes: usize,
}

pub(super) struct PreparedSource {
    pub(super) message: PreparedMessage,
    pub(super) observed_rules: BTreeSet<String>,
    pub(super) packet: Option<PreparedPacket>,
}

pub(super) struct PreparedPacket {
    pub(super) revision: u64,
    pub(super) bytes: Bytes,
    pub(super) comparison: Comparison,
    pub(super) identity: IdentityDecision,
    guards: Vec<Box<dyn PreparedDeliveryGuard>>,
}

impl PreparedPacket {
    pub(super) fn is_current(&self, contracts: &dyn policy::ValueRuleHost, scope: &str) -> bool {
        let Some(revision) = contracts.prefetch_delivery_revision(scope) else {
            return false;
        };
        revision == self.revision
            || self.guards.iter().all(|guard| guard.is_current())
                && contracts.prefetched_identity_is_current(&self.identity)
                && contracts.prefetch_delivery_revision(scope) == Some(revision)
    }
}

impl Inventory {
    pub fn stored_response_preparation(&self, index: usize) -> Option<ResponsePreparation> {
        let exchange = &self.core.exchanges[index];
        let response = &exchange.native.response;
        response.stored()?;
        let mut preparation = ResponsePreparation::decode_only(response.clone());
        if exchange.native.request().is_none()
            && exchange.source.case_id.is_none()
            && self.contracts.prefetch_source_response()
        {
            let (clocks, delivered) = recorded_clocks(
                self.contracts.as_ref(),
                None,
                exchange.source.capture.as_ref(),
                exchange.native.response_delay,
            );
            preparation.source = Some(FrozenSource {
                providers: self.providers.clone(),
                contracts: self.contracts.clone(),
                protocol: exchange.protocol,
                clocks,
                delivered,
                packet_scope: (self.event_session && exchange.delivery.is_empty())
                    .then_some(Inventory::EVENT_SESSION_VALUE_SCOPE),
            });
        }
        Some(preparation)
    }
}

impl ResponsePreparation {
    pub fn decode_only(response: Arc<dyn MessageEncoder>) -> Self {
        Self {
            response,
            source: None,
        }
    }

    pub fn load(&self, max_bytes: usize) -> Result<Option<LoadedResponse>> {
        let encoder = self
            .response
            .stored()
            .context("response is already decoded")?
            .load()?;
        let Some(mut bytes) = encoder
            .prefetch_retained_bytes()
            .filter(|bytes| *bytes <= max_bytes)
        else {
            return Ok(None);
        };
        let mut source = None;
        if let Some(frozen) = &self.source {
            let rules = frozen
                .providers
                .bindings()
                .for_protocol(frozen.protocol.as_str());
            let policy = frozen
                .contracts
                .document_policy(response_policy_clocks(frozen.clocks, frozen.delivered));
            let mut message = crate::value_extensions::prepare_message_with_policy(
                encoder.as_ref(),
                &rules.response,
                policy,
            )?;
            message.prepare_delivery()?;
            if let Some(prepared_bytes) = message
                .prefetch_retained_bytes()
                .filter(|prepared| *prepared <= max_bytes - bytes)
            {
                let mut clocks = comparison_clocks(frozen.clocks);
                clocks.observation = Some(clocks.delivery);
                let mut comparison = message.compare_source(clocks, frozen.contracts.metadata());
                ensure!(
                    comparison.passed(),
                    "Source projected value contract failed: response={:?}",
                    comparison.differences
                );
                let mut prepared_bytes = prepared_bytes;
                for rule in &comparison.evaluated {
                    prepared_bytes = prepared_bytes.saturating_add(rule.capacity() + 64);
                }
                if prepared_bytes <= max_bytes - bytes {
                    bytes += prepared_bytes;
                    let observed_rules = comparison.evaluated.clone();
                    // Speculative work can only save a later computation.
                    // Report validation errors from the ordered live path.
                    let packet = frozen
                        .prepare_packet(&message, &mut comparison, encoder.as_ref(), clocks)
                        .ok()
                        .flatten()
                        .filter(|(_, retained)| *retained <= max_bytes - bytes)
                        .map(|(packet, retained)| {
                            bytes += retained;
                            packet
                        });
                    source = Some(PreparedSource {
                        message,
                        observed_rules,
                        packet,
                    });
                }
            }
        }
        Ok(Some(LoadedResponse {
            encoder,
            source,
            bytes,
        }))
    }
}

impl FrozenSource {
    fn prepare_packet(
        &self,
        message: &PreparedMessage,
        source_comparison: &mut Comparison,
        encoder: &dyn MessageEncoder,
        clocks: AnchorClocks,
    ) -> Result<Option<(PreparedPacket, usize)>> {
        let Some(scope) = self.packet_scope else {
            return Ok(None);
        };
        let Some(revision) = self.contracts.prefetch_delivery_revision(scope) else {
            return Ok(None);
        };
        let Some(prepared) = message.prefetch_delivery(
            scope,
            clocks,
            self.contracts.metadata(),
            source_comparison,
        )?
        else {
            return Ok(None);
        };
        let rendered = prepared.rendered;
        let guards = prepared.guards;
        let Some(comparison_bytes) = rendered.comparison.prefetch_retained_bytes() else {
            return Ok(None);
        };
        let identity = self.contracts.preview_identity_pairs(
            scope,
            &rendered.comparison.identity_pairs(),
            false,
        )?;
        if self.contracts.prefetch_delivery_revision(scope) != Some(revision) {
            return Ok(None);
        }
        let Some((bytes, wire_bytes)) = encoder.prefetch_packet(&rendered.values)? else {
            return Ok(None);
        };
        let retained = std::mem::size_of::<PreparedPacket>()
            .saturating_add(wire_bytes)
            .saturating_add(comparison_bytes)
            .saturating_add(identity.retained_bytes())
            .saturating_add(
                guards.capacity() * std::mem::size_of::<Box<dyn PreparedDeliveryGuard>>(),
            )
            .saturating_add(
                guards
                    .iter()
                    .map(|guard| guard.retained_bytes())
                    .sum::<usize>(),
            );
        Ok(Some((
            PreparedPacket {
                revision,
                bytes,
                comparison: rendered.comparison,
                identity,
                guards,
            },
            retained,
        )))
    }
}

impl LoadedResponse {
    pub fn prefetch_retained_bytes(&self) -> usize {
        self.bytes
    }

    pub fn has_source_preparation(&self) -> bool {
        self.source.is_some()
    }

    pub fn has_prepared_delivery(&self) -> bool {
        self.source
            .as_ref()
            .is_some_and(|source| source.message.has_prepared_delivery())
    }

    pub fn has_prefetched_packet(&self) -> bool {
        self.source
            .as_ref()
            .is_some_and(|source| source.packet.is_some())
    }
}

pub(super) fn recorded_clocks(
    contracts: &dyn policy::ValueRuleHost,
    case: Option<&str>,
    capture: Option<&CaptureMetadata>,
    delay: std::time::Duration,
) -> (AnchorClocks, Option<DateTime<Utc>>) {
    let start = capture.map(|capture| capture.started_at);
    let delivered = start.and_then(|start| {
        chrono::Duration::from_std(delay)
            .ok()
            .and_then(|delay| start.checked_add_signed(delay))
    });
    (
        contracts.contract_clocks(case, start, None, delivered, None),
        delivered,
    )
}

pub(super) fn response_policy_clocks(
    mut clocks: AnchorClocks,
    delivered: Option<DateTime<Utc>>,
) -> AnchorClocks {
    clocks.observation = Some(ClockPair {
        source: delivered,
        target: None,
    });
    clocks
}

pub(super) fn comparison_clocks(mut clocks: AnchorClocks) -> AnchorClocks {
    clocks.case.target = clocks.case.source;
    clocks.dependency.target = clocks.dependency.source;
    clocks.delivery.target = clocks.delivery.source;
    clocks
}

impl StoredMessage for Response {
    fn load(&self) -> Result<Arc<dyn MessageEncoder>> {
        let provider = self.providers.provider(self.protocol)?;
        let native = provider
            .native_protocol()
            .context("stored response has no native protocol")?;
        if let Some(decode) = native.emission_body_decoder()
            && let Some(body) = self.reference.load_response_bytes()?
        {
            return decode(body);
        }
        let event = self.reference.load_value()?;
        let secrets = crate::request_headers::SourceSecrets::new(self.reference.source.path());
        Ok(native
            .recorded_exchange_with_secrets(&event, &secrets)?
            .context("stored response has no executable exchange")?
            .response)
    }

    fn source_structure(&self) -> Option<&Value> {
        self.structure.as_ref()
    }
}

impl ProtocolMessage for Response {
    fn project(&self) -> Result<ProjectedMessage> {
        self.load()?.project()
    }
    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        self.load()?.locate(selector)
    }
    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.load()?.evidence(selector)
    }
}

impl MessageEncoder for Response {
    fn stored(&self) -> Option<&dyn StoredMessage> {
        Some(self)
    }
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        self.load()?.encode(values)
    }
}
