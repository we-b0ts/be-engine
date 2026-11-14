//! Registered protocol facts use the shared inventory, rules and delivery host.
use super::*;
use traffic_model::recording::CaptureMetadata;
use traffic_protocol::{ProtocolId, connection::Endpoint};
use traffic_replay::exchange::{ExchangeInventory, SourceContext};

mod connection;
mod report;
mod request;
pub(crate) use connection::handle_connection;
pub(super) use report::ProtocolReport;

#[derive(Debug)]
pub(crate) struct Inventory {
    pub core: ExchangeInventory,
    pub providers: Arc<crate::protocols::DependencyProviders>,
    pub contracts: policy::request_contract::RequestContracts,
    pub order: admission::RequestOrder,
    failures: Vec<report::RequestFailure>,
    failure_counts: BTreeMap<(String, Option<String>), usize>,
    matched: BTreeMap<String, usize>,
    recorded: BTreeMap<(ReplaySource, Option<String>, Uuid, u32), String>,
    captures: BTreeMap<(String, Uuid), usize>,
}

impl Default for Inventory {
    fn default() -> Self {
        Self::new(crate::protocols::default_providers())
    }
}

impl Inventory {
    pub fn new(providers: Arc<crate::protocols::DependencyProviders>) -> Self {
        Self {
            core: Default::default(),
            providers,
            contracts: Default::default(),
            order: Default::default(),
            failures: Default::default(),
            matched: Default::default(),
            recorded: Default::default(),
            failure_counts: Default::default(),
            captures: Default::default(),
        }
    }

    pub fn register(
        &mut self,
        event: &Value,
        source: ReplaySource,
        case: Option<&str>,
        position: usize,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        let Some(entry) = self.providers.event_provider(event) else {
            ensure!(
                !self.providers.evidence().supports_replay(event),
                "native Replay evidence has no registered connection provider"
            );
            return Ok(());
        };
        let Some(native) = entry.provider.native_protocol() else {
            ensure!(
                !self.providers.evidence().supports_replay(event),
                "native Replay evidence has no registered session capability"
            );
            return Ok(());
        };
        let Some(mut exchange) = native.recorded_exchange(event)? else {
            ensure!(
                event["capture"]["semantic_required"] != true
                    || !self.providers.evidence().supports_replay(event),
                "mandatory native Replay evidence has no executable exchange"
            );
            return Ok(());
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
                return Ok(());
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
        register_replay_target(targets, &target, ReplayProtocol::registered(protocol))?;
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
            rules,
        )?;
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
        self.core.exchanges.iter().any(|exchange| {
            matches!(
                self.core
                    .lifecycle
                    .live_status(exchange.index, exchange.status),
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
        })
    }

    pub fn has_case_in_flight(&self) -> bool {
        self.core.exchanges.iter().any(|exchange| {
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

    pub fn resolve(&self, case: &str, exchange_id: Uuid) -> Result<usize> {
        self.captures
            .get(&(case.into(), exchange_id))
            .copied()
            .context("native capture reference is absent from its Case inventory")
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

pub(super) fn extend_index(
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
                entry.kind.as_str().to_owned(),
            ));
        }
    }
    for (host, port, protocol) in endpoints {
        index.register_endpoint(host, port, protocol);
    }
    Ok(())
}
