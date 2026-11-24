//! Decode an immutable stored response for Replay delivery or read-ahead.
use super::*;
use crate::dependency_index::RecordRef;
use bytes::Bytes;
use traffic_contract::{compare::AnchorClocks, time::ClockPair};
use traffic_policy_value::PreparedMessage;
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
}

pub struct LoadedResponse {
    pub(super) encoder: Arc<dyn MessageEncoder>,
    pub(super) source: Option<PreparedSource>,
    bytes: usize,
}

pub(super) struct PreparedSource {
    pub(super) message: PreparedMessage,
    pub(super) observed_rules: BTreeSet<String>,
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
            let message = crate::value_extensions::prepare_message_with_policy(
                encoder.as_ref(),
                &rules.response,
                policy,
            )?;
            if let Some(prepared_bytes) = message
                .prefetch_retained_bytes()
                .filter(|prepared| *prepared <= max_bytes - bytes)
            {
                let mut clocks = comparison_clocks(frozen.clocks);
                clocks.observation = Some(clocks.delivery);
                let comparison = message.compare_source(clocks, frozen.contracts.metadata());
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
                    source = Some(PreparedSource {
                        message,
                        observed_rules: comparison.evaluated,
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

impl LoadedResponse {
    pub fn prefetch_retained_bytes(&self) -> usize {
        self.bytes
    }

    pub fn has_source_preparation(&self) -> bool {
        self.source.is_some()
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
