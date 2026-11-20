//! Registered protocol facts use the shared inventory, rules and delivery host.
use super::*;
use traffic_model::recording::{CaptureMetadata, ProtocolRef};
use traffic_protocol::{
    ProtocolId,
    connection::{Endpoint, ReplaySessionStep},
};
use traffic_replay::exchange::{ExchangeInventory, SourceContext};

pub mod diagnosis;
mod global_report;
mod report;
pub mod request;
mod stored;
pub use report::ProtocolReport;

#[derive(Debug)]
pub struct Inventory {
    pub inputs: traffic_replay::input::InputActivity,
    pub tls: Option<Arc<dyn traffic_protocol::connection::TlsServer>>,
    pub core: ExchangeInventory<crate::value_extensions::ValueRules>,
    global_usage: BTreeMap<ProtocolId, traffic_replay::report::Usage>,
    pub providers: Arc<crate::protocols::DependencyProviders>,
    pub contracts: Arc<dyn policy::ValueRuleHost>,
    pub order: admission::RequestOrder,
    failures: Vec<report::RequestFailure>,
    failure_counts: BTreeMap<(String, Option<String>), usize>,
    matched: BTreeMap<String, usize>,
    recorded: BTreeMap<(ReplaySource, Option<String>, Uuid, u32), String>,
    captures: BTreeMap<(String, Uuid), Option<usize>>,
    optional_references: BTreeMap<String, BTreeSet<ProtocolRef>>,
}

impl Inventory {
    pub fn new(providers: Arc<crate::protocols::DependencyProviders>) -> Self {
        Self {
            inputs: Default::default(),
            tls: None,
            core: Default::default(),
            global_usage: Default::default(),
            providers,
            contracts: crate::value_extensions::strict_values(),
            order: Default::default(),
            failures: Default::default(),
            matched: Default::default(),
            recorded: Default::default(),
            failure_counts: Default::default(),
            captures: Default::default(),
            optional_references: Default::default(),
        }
    }

    pub fn register(
        &mut self,
        event: &Value,
        source: ReplaySource,
        case: Option<&str>,
        position: usize,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        secrets: &dyn traffic_protocol::evidence::EvidenceSecrets,
    ) -> Result<()> {
        self.register_scoped(event, source, case, position, targets, secrets, None)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_scoped(
        &mut self,
        event: &Value,
        source: ReplaySource,
        case: Option<&str>,
        position: usize,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        secrets: &dyn traffic_protocol::evidence::EvidenceSecrets,
        session_step: Option<ReplaySessionStep>,
    ) -> Result<()> {
        self.register_source(
            event,
            source,
            case,
            position,
            targets,
            secrets,
            None,
            session_step,
        )?;
        Ok(())
    }

    pub fn register_stored_emission(
        &mut self,
        event: &Value,
        source: ReplaySource,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        reference: crate::dependency_index::RecordRef,
        secrets: &dyn traffic_protocol::evidence::EvidenceSecrets,
    ) -> Result<bool> {
        self.register_source(
            event,
            source,
            None,
            reference.location.line,
            targets,
            secrets,
            Some(reference),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_source(
        &mut self,
        event: &Value,
        source: ReplaySource,
        case: Option<&str>,
        position: usize,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        secrets: &dyn traffic_protocol::evidence::EvidenceSecrets,
        stored: Option<crate::dependency_index::RecordRef>,
        session_step: Option<ReplaySessionStep>,
    ) -> Result<bool> {
        let Some(entry) = self.providers.event_provider(event) else {
            ensure!(
                !self.providers.evidence().supports_replay(event),
                "native Replay evidence has no registered connection provider"
            );
            return Ok(false);
        };
        let Some(native) = entry.provider.native_protocol() else {
            ensure!(
                !self.providers.evidence().supports_replay(event),
                "native Replay evidence has no registered session capability"
            );
            return Ok(false);
        };
        let exchange = if let Some(reference) = stored {
            let response = Arc::new(stored::Response {
                reference,
                providers: self.providers.clone(),
                protocol: entry.kind,
                structure: native.recorded_emission_structure(event),
            });
            let Some(exchange) = native.recorded_emission(event, response)? else {
                return Ok(false);
            };
            Some(exchange)
        } else {
            native.recorded_exchange_with_secrets(event, secrets)?
        };
        let Some(mut exchange) = exchange else {
            ensure!(
                event["capture"]["semantic_required"] != true
                    || !self.providers.evidence().supports_replay(event),
                "mandatory native Replay evidence has no executable exchange"
            );
            return Ok(false);
        };
        ensure!(
            self.providers.evidence().supports_replay(event),
            "native exchange has incomplete or unsupported evidence"
        );
        let capture: Option<CaptureMetadata> = event
            .get("capture")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        if let Some(capture) = &capture {
            ensure!(
                capture.protocol_ref == exchange.reference,
                "native exchange disagrees with its capture reference"
            );
            let key = (
                source,
                case.map(ToOwned::to_owned),
                capture.exchange_id,
                capture.effect_index,
            );
            if let Some(previous) = self.recorded.get(&key) {
                ensure!(
                    *previous == crate::policy_evidence::digest(&serde_json::to_vec(event)?),
                    "native Source capture changed between registrations"
                );
                return Ok(true);
            }
            if let Some(case) = case {
                ensure!(
                    !self
                        .captures
                        .contains_key(&(case.into(), capture.exchange_id)),
                    "native request capture has multiple executable exchanges"
                );
            }
        }
        exchange.endpoint.host = normalize_host(&exchange.endpoint.host);
        ensure!(
            !exchange.endpoint.host.is_empty() && exchange.endpoint.port != 0,
            "native exchange endpoint is invalid"
        );
        let target = TargetKey {
            host: exchange.endpoint.host.clone(),
            port: exchange.endpoint.port,
        };
        let protocol = entry.kind;
        let connection_protocol = native
            .recorded_protocol(event)?
            .map(ReplayProtocol::new)
            .unwrap_or_else(|| ReplayProtocol::registered(protocol));
        register_replay_target(targets, &target, connection_protocol)?;
        if let Some(case) = case {
            ensure!(
                !self.is_optional_reference(case, &exchange.reference),
                "native Source reference is ambiguous in its Case inventory"
            );
        }
        if session_step == Some(ReplaySessionStep::Optional) {
            ensure!(
                self.providers.evidence().capture_complete(event),
                "optional native Source capture has incomplete evidence"
            );
            if let Some(case) = case.filter(|_| source == ReplaySource::Case) {
                ensure!(
                    self.core
                        .resolve_reference(case, &exchange.reference)?
                        .is_none(),
                    "native Source reference is ambiguous in its Case inventory"
                );
                self.optional_references
                    .entry(case.into())
                    .or_default()
                    .insert(exchange.reference);
            }
            self.remember_capture(source, case, capture, event, None)?;
            return Ok(false);
        }
        let prepared = self.prepared_messages(
            &exchange,
            case,
            capture.as_ref(),
            self.contracts.as_ref(),
            None,
        )?;
        let rules = self.providers.bindings().for_protocol(protocol.as_str());
        let index = self.core.register(
            protocol.id(),
            exchange,
            SourceContext {
                source,
                case_id: case.map(ToOwned::to_owned),
                position: u64::try_from(position)?,
                capture: capture.clone(),
            },
            crate::value_extensions::replay_rules(rules),
        )?;
        self.core.exchanges[index].request = prepared.0;
        self.core.exchanges[index].response = prepared.1;
        self.core.exchanges[index].session_step = session_step;
        self.remember_capture(source, case, capture, event, Some(index))?;
        Ok(true)
    }

    fn remember_capture(
        &mut self,
        source: ReplaySource,
        case: Option<&str>,
        capture: Option<CaptureMetadata>,
        event: &Value,
        index: Option<usize>,
    ) -> Result<()> {
        if let Some(case) = case
            && let Some(capture) = &capture
        {
            self.captures
                .insert((case.into(), capture.exchange_id), index);
        }
        if let Some(capture) = capture {
            self.recorded.insert(
                (
                    source,
                    case.map(ToOwned::to_owned),
                    capture.exchange_id,
                    capture.effect_index,
                ),
                crate::policy_evidence::digest(&serde_json::to_vec(event)?),
            );
        }
        Ok(())
    }

    fn prepared_messages(
        &self,
        exchange: &traffic_protocol::connection::RecordedExchange,
        case: Option<&str>,
        capture: Option<&CaptureMetadata>,
        contracts: &dyn policy::ValueRuleHost,
        loaded_response: Option<&dyn traffic_protocol::message::MessageEncoder>,
    ) -> Result<(
        Option<traffic_policy_value::PreparedMessage>,
        Option<traffic_policy_value::PreparedMessage>,
    )> {
        let start = capture.map(|capture| capture.started_at);
        let delivered = start.and_then(|start| {
            chrono::Duration::from_std(exchange.response_delay)
                .ok()
                .and_then(|delay| start.checked_add_signed(delay))
        });
        let clocks = contracts.contract_clocks(case, start, None, delivered, None);
        let rules = self
            .providers
            .bindings()
            .for_protocol(exchange.reference.protocol());
        let request_policy = contracts.document_policy(clocks);
        let mut response_clocks = clocks;
        response_clocks.observation = Some(traffic_contract::time::ClockPair {
            source: delivered,
            target: None,
        });
        let response_policy = contracts.document_policy(response_clocks);
        let response = loaded_response.or_else(|| {
            exchange
                .response
                .stored()
                .is_none()
                .then_some(exchange.response.as_ref())
        });
        let prepared = (
            exchange
                .request()
                .map(|request| {
                    crate::value_extensions::prepare_message_with_policy(
                        request,
                        &rules.request,
                        request_policy,
                    )
                })
                .transpose()?,
            response
                .map(|response| {
                    crate::value_extensions::prepare_message_with_policy(
                        response,
                        &rules.response,
                        response_policy,
                    )
                })
                .transpose()?,
        );
        let mut source_clocks = clocks;
        source_clocks.case.target = source_clocks.case.source;
        source_clocks.dependency.target = source_clocks.dependency.source;
        source_clocks.delivery.target = source_clocks.delivery.source;
        let request = prepared
            .0
            .as_ref()
            .zip(exchange.request())
            .map(|(prepared, request)| {
                prepared.compare(request, source_clocks, contracts.metadata())
            })
            .transpose()?;
        let mut response_clocks = source_clocks;
        response_clocks.observation = Some(source_clocks.delivery);
        let response = prepared
            .1
            .as_ref()
            .zip(response)
            .map(|(prepared, response)| {
                prepared.compare(response, response_clocks, contracts.metadata())
            })
            .transpose()?;
        ensure!(
            request.as_ref().is_none_or(|request| request.passed())
                && response.as_ref().is_none_or(|response| response.passed()),
            "Source projected value contract failed: request={:?}, response={:?}",
            request.as_ref().map(|request| &request.differences),
            response.as_ref().map(|response| &response.differences)
        );
        if let Some(request) = &request {
            contracts.observe_source_comparison(request);
        }
        if let Some(response) = &response {
            contracts.observe_source_comparison(response);
        }
        Ok(prepared)
    }

    pub fn install_contracts(&mut self, contracts: Arc<dyn policy::ValueRuleHost>) -> Result<()> {
        let prepared = self
            .core
            .exchanges
            .iter()
            .map(|exchange| {
                self.prepared_messages(
                    &exchange.native,
                    exchange.source.case_id.as_deref(),
                    exchange.source.capture.as_ref(),
                    contracts.as_ref(),
                    None,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        for (exchange, (request, response)) in self.core.exchanges.iter_mut().zip(prepared) {
            exchange.request = request;
            exchange.response = response;
        }
        self.contracts = contracts;
        Ok(())
    }
    pub fn recorded_sequence(&self, index: usize) -> Option<u64> {
        self.core
            .exchanges
            .get(index)?
            .source
            .capture
            .as_ref()
            .map(|capture| capture.sequence)
    }

    pub fn has_in_flight(&self) -> bool {
        self.inputs.has_in_flight()
            || self.core.exchanges.iter().any(|exchange| {
                matches!(
                    self.core
                        .lifecycle
                        .live_status(exchange.index, exchange.status),
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
            })
    }

    pub fn has_case_in_flight(&self) -> bool {
        self.inputs.has_case_in_flight()
            || self.core.exchanges.iter().any(|exchange| {
                exchange.source.source == ReplaySource::Case
                    && matches!(
                        self.core
                            .lifecycle
                            .live_status(exchange.index, exchange.status),
                        ReplayExchangeStatus::Responding
                            | ReplayExchangeStatus::AwaitingClientTermination
                    )
            })
    }

    /// A known optional capture has no Target-delivery slot.
    pub fn resolve(&self, case: &str, exchange_id: Uuid) -> Result<Option<usize>> {
        self.captures
            .get(&(case.into(), exchange_id))
            .copied()
            .context("native capture reference is absent from its Case inventory")
    }

    pub fn is_optional_reference(&self, case: &str, reference: &ProtocolRef) -> bool {
        self.optional_references
            .get(case)
            .is_some_and(|references| references.contains(reference))
    }

    pub fn in_flight_diagnostic(&self) -> Value {
        let pending = self.core.exchanges.iter().filter(|exchange| {
            exchange.source.source == ReplaySource::Case
                && matches!(
                    self.core
                        .lifecycle
                        .live_status(exchange.index, exchange.status),
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        });
        let count = pending.clone().count();
        let rows: Vec<_> = pending.take(4).map(|exchange| serde_json::json!({
            "protocol":exchange.protocol,"case_id":exchange.source.case_id,"reference":exchange.native.reference
        })).collect();
        serde_json::json!({"count":count,"references":rows,"omitted":count.saturating_sub(4)})
    }

    pub fn scope(&self, index: usize) -> String {
        let exchange = &self.core.exchanges[index];
        if let Some(case) = &exchange.source.case_id {
            return case.clone();
        }
        let owner = exchange
            .source
            .capture
            .as_ref()
            .map(|capture| &capture.attribution);
        let identity = crate::policy_evidence::digest(
            &serde_json::to_vec(&owner).expect("capture owner serializes"),
        );
        format!("run:{identity}")
    }

    pub fn clocks(
        &self,
        index: usize,
        observed: DateTime<Utc>,
        delivery: bool,
    ) -> traffic_contract::compare::AnchorClocks {
        let exchange = &self.core.exchanges[index];
        let start = exchange
            .source
            .capture
            .as_ref()
            .map(|capture| capture.started_at);
        let source_delivery = start.and_then(|start| {
            chrono::Duration::from_std(exchange.native.response_delay)
                .ok()
                .and_then(|duration| start.checked_add_signed(duration))
        });
        let delivered_at = Utc::now();
        let mut clocks = self.contracts.contract_clocks(
            exchange.source.case_id.as_deref(),
            start,
            Some(observed),
            source_delivery,
            delivery.then_some(delivered_at),
        );
        if delivery {
            clocks.observation = Some(traffic_contract::time::ClockPair {
                source: source_delivery,
                target: Some(delivered_at),
            });
        }
        clocks
    }
}

pub fn extend_index(
    providers: &crate::protocols::DependencyProviders,
    path: &Path,
    index: &mut crate::dependency_index::FileIndex,
    reader: &mut crate::dependency_index::RecordReader,
) -> Result<()> {
    let mut endpoints = Vec::new();
    for record in index.proof_records.iter().flatten() {
        let Some(entry) = providers.event_provider(&record.selector) else {
            continue;
        };
        let Some(native) = entry.provider.native_protocol() else {
            continue;
        };
        let raw = reader.read(path, &index.stamp, &record.location)?;
        let event = serde_json::from_slice(&raw)?;
        if let Some(endpoint) = native.recorded_endpoint(&event)? {
            endpoints.push((
                normalize_host(&endpoint.host),
                endpoint.port,
                native
                    .recorded_protocol(&event)?
                    .unwrap_or_else(|| entry.kind.id())
                    .as_str()
                    .to_owned(),
            ));
        }
    }
    for (host, port, protocol) in endpoints {
        index.register_endpoint(host, port, protocol);
    }
    Ok(())
}
