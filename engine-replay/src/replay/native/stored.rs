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
    index: usize,
    providers: Arc<crate::protocols::DependencyProviders>,
    contracts: Arc<dyn policy::ValueRuleHost>,
    protocol: ProtocolId,
    clocks: AnchorClocks,
    delivered: Option<DateTime<Utc>>,
    packet_scope: Option<&'static str>,
}

pub struct LoadedResponse {
    pub(super) kind: LoadedResponseKind,
    bytes: usize,
}

pub(super) enum LoadedResponseKind {
    Decoded {
        encoder: Arc<dyn MessageEncoder>,
        source: Option<PreparedSource>,
    },
    Stable(StableSource),
}

pub(super) struct PreparedSource {
    pub(super) message: PreparedMessage,
    pub(super) observed_rules: BTreeSet<String>,
    pub(super) packet: Option<PreparedPacket>,
}

pub(super) struct PreparedPacket {
    revision: u64,
    pub(super) delivery: PacketDelivery,
    guards: Vec<Box<dyn PreparedDeliveryGuard>>,
}

pub(super) struct PacketDelivery {
    pub(super) bytes: Bytes,
    pub(super) comparison: Comparison,
    pub(super) identity: IdentityDecision,
}

pub(super) struct StableSource {
    index: usize,
    response: Arc<dyn MessageEncoder>,
    contracts: Arc<dyn policy::ValueRuleHost>,
    pub(super) observed_rules: BTreeSet<String>,
    pub(super) packet: Option<PacketDelivery>,
    had_prepared_delivery: bool,
}

enum PacketPreparation {
    Guarded(PreparedPacket, usize),
    Stable(PacketDelivery, usize),
}

impl PreparedPacket {
    pub(super) fn is_current(&self, contracts: &dyn policy::ValueRuleHost, scope: &str) -> bool {
        let Some(revision) = contracts.prefetch_delivery_revision(scope) else {
            return false;
        };
        revision == self.revision
            || self.guards.iter().all(|guard| guard.is_current())
                && contracts.prefetched_identity_is_current(&self.delivery.identity)
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
                index,
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
        let Some(encoder_bytes) = encoder
            .prefetch_retained_bytes()
            .filter(|bytes| *bytes <= max_bytes)
        else {
            return Ok(None);
        };
        let mut bytes = encoder_bytes;
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
                let observed_bytes = comparison.evaluated.iter().fold(0usize, |bytes, rule| {
                    bytes.saturating_add(rule.capacity() + 64)
                });
                let prepared_bytes = prepared_bytes.saturating_add(observed_bytes);
                if prepared_bytes <= max_bytes - bytes {
                    bytes += prepared_bytes;
                    let observed_rules = comparison.evaluated.clone();
                    // Speculative work can only save a later computation.
                    // Report validation errors from the ordered live path.
                    let packet = match frozen
                        .prepare_packet(&message, &mut comparison, encoder.as_ref(), clocks)
                        .ok()
                        .flatten()
                    {
                        Some(PacketPreparation::Stable(packet, retained)) => {
                            // An unchanged frame may retain the encoder's original bytes.
                            let stable_bytes = std::mem::size_of::<LoadedResponse>()
                                .saturating_add(encoder_bytes)
                                .saturating_add(observed_bytes)
                                .saturating_add(retained);
                            if stable_bytes <= max_bytes {
                                return Ok(Some(LoadedResponse {
                                    kind: LoadedResponseKind::Stable(StableSource {
                                        index: frozen.index,
                                        response: self.response.clone(),
                                        contracts: frozen.contracts.clone(),
                                        observed_rules,
                                        packet: Some(packet),
                                        had_prepared_delivery: message.has_prepared_delivery(),
                                    }),
                                    bytes: stable_bytes,
                                }));
                            }
                            None
                        }
                        Some(PacketPreparation::Guarded(packet, retained))
                            if retained <= max_bytes - bytes =>
                        {
                            bytes += retained;
                            Some(packet)
                        }
                        _ => None,
                    };
                    source = Some(PreparedSource {
                        message,
                        observed_rules,
                        packet,
                    });
                }
            }
        }
        Ok(Some(LoadedResponse {
            kind: LoadedResponseKind::Decoded { encoder, source },
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
    ) -> Result<Option<PacketPreparation>> {
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
        let stable = self.contracts.prefetched_identity_is_committed(&identity)
            && rendered.comparison.passed()
            && guards.iter().all(|guard| guard.is_state_independent());
        let retained = wire_bytes
            .saturating_add(comparison_bytes)
            .saturating_add(identity.retained_bytes());
        let delivery = PacketDelivery {
            bytes,
            comparison: rendered.comparison,
            identity,
        };
        if stable {
            return Ok(Some(PacketPreparation::Stable(delivery, retained)));
        }
        let retained = retained
            .saturating_add(std::mem::size_of::<PreparedPacket>())
            .saturating_add(
                guards.capacity() * std::mem::size_of::<Box<dyn PreparedDeliveryGuard>>(),
            )
            .saturating_add(
                guards
                    .iter()
                    .map(|guard| guard.retained_bytes())
                    .sum::<usize>(),
            );
        Ok(Some(PacketPreparation::Guarded(
            PreparedPacket {
                revision,
                delivery,
                guards,
            },
            retained,
        )))
    }
}

impl LoadedResponse {
    pub fn has_compact_packet(&self) -> bool {
        matches!(&self.kind, LoadedResponseKind::Stable(source) if source.packet.is_some())
    }

    pub fn prefetch_retained_bytes(&self) -> usize {
        self.bytes
    }

    pub fn has_source_preparation(&self) -> bool {
        match &self.kind {
            LoadedResponseKind::Decoded { source, .. } => source.is_some(),
            LoadedResponseKind::Stable(_) => true,
        }
    }

    pub fn has_prepared_delivery(&self) -> bool {
        match &self.kind {
            LoadedResponseKind::Decoded { source, .. } => source
                .as_ref()
                .is_some_and(|source| source.message.has_prepared_delivery()),
            LoadedResponseKind::Stable(source) => source.had_prepared_delivery,
        }
    }

    pub fn has_prefetched_packet(&self) -> bool {
        match &self.kind {
            LoadedResponseKind::Decoded { source, .. } => source
                .as_ref()
                .is_some_and(|source| source.packet.is_some()),
            LoadedResponseKind::Stable(source) => source.packet.is_some(),
        }
    }
}

impl Inventory {
    pub(super) fn owns_stable_source(&self, index: usize, source: &StableSource) -> bool {
        self.event_session
            && index == source.index
            && Arc::ptr_eq(&self.contracts, &source.contracts)
            && Arc::ptr_eq(
                &self.core.exchanges[index].native.response,
                &source.response,
            )
    }

    /// Read a fixed frame only in the Session that established its identity proof.
    pub fn batchable_message_packet<'a>(
        &self,
        index: usize,
        loaded: &'a LoadedResponse,
    ) -> Option<&'a Bytes> {
        let LoadedResponseKind::Stable(source) = &loaded.kind else {
            return None;
        };
        if !self.owns_stable_source(index, source) {
            return None;
        }
        source.packet.as_ref().map(|packet| &packet.bytes)
    }

    pub(super) fn observe_prepared_rules(&self, evaluated: BTreeSet<String>) {
        self.contracts.observe_source_comparison(&Comparison {
            evaluated,
            ..Comparison::default()
        });
    }

    pub fn commit_batched_message(&self, loaded: LoadedResponse) -> Result<()> {
        let LoadedResponseKind::Stable(source) = loaded.kind else {
            anyhow::bail!("message batch has no stable Source packet");
        };
        ensure!(
            self.event_session && Arc::ptr_eq(&self.contracts, &source.contracts),
            "message batch belongs to a different Session"
        );
        let packet = source
            .packet
            .context("message batch has no independent prepared packet")?;
        self.observe_prepared_rules(source.observed_rules);
        self.contracts
            .commit_comparison(packet.comparison, packet.identity)
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

#[cfg(test)]
mod tests;
