//! Application assembly for built-in protocol state and native connection drivers.
pub(crate) mod auto_protocol;
pub(crate) mod http;
#[cfg(test)]
pub(crate) mod http_test_support;
#[cfg(test)]
mod native_http_tests;
#[cfg(test)]
pub(crate) use http_test_support::{
    snapshot_http_replay, spawn_coordinator_http_replay, write_http_case,
};

pub(crate) use http::contracts::{
    multipart_witness_matches as http_multipart_witness_matches,
    source_witness as http_source_witness, validate_witness as http_validate_witness,
    witness_metadata_matches as http_witness_metadata_matches, witness_value as http_witness_value,
};
pub(crate) use http::cross_case as http_cross_case;
pub use http::cross_case::HttpCrossCaseSelector;
pub(crate) use http::diagnosis as http_request_diagnosis;
pub use traffic_protocol_redis::key_selector::RedisValueKeySelector;
pub type RedisUnorderedField = traffic_protocol_redis::bindings::LegacyValueLocation<
    traffic_policy_schema::response::ProtobufFieldPath,
    traffic_policy_schema::response::ProtobufRepeatedElementType,
>;
pub type RedisUnorderedSelector =
    traffic_protocol_redis::bindings::LegacyUnorderedSelector<RedisUnorderedField>;
pub(crate) use traffic_protocol_redis::request_identity::request_fingerprint as redis_request_fingerprint;
pub(crate) mod redis_value {
    pub use super::{RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector};
}
pub(crate) fn normalize_redis_expiration(
    command: &str,
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    clocks: traffic_contract::time::ClockPair,
) -> anyhow::Result<Option<Vec<Vec<u8>>>> {
    traffic_protocol_redis::expiration::normalize(
        command,
        source,
        target,
        crate::value_contract::time::DEFAULT_TOLERANCE,
        |scale| {
            let (source, target) = clocks.require()?;
            Ok(if scale == 1000 {
                (source.timestamp_millis(), target.timestamp_millis())
            } else {
                (source.timestamp(), target.timestamp())
            })
        },
    )
}
pub(crate) mod mysql;
pub(crate) use mysql::contracts::automatic::Metadata as MysqlInferenceMetadata;
pub(crate) use mysql::contracts::automatic::validate_source_witness as mysql_validate_global_source_witness;
pub(crate) use mysql::contracts::automatic::validate_witness_with_time_copies as mysql_validate_global_witness_with_time_copies;
pub(crate) use mysql::contracts::source_witness as mysql_source_witness;
pub(crate) use mysql::contracts::time_copies::global::delivered_witness_time_copies as mysql_global_delivered_time_copies;
pub(crate) use mysql::contracts::{
    IdentityPreflight as MysqlIdentityPreflight, mysql_witness_sql_value,
    normalize_identity_witnesses as mysql_normalize_identity_witnesses,
};
pub(crate) use mysql::contracts::{
    request_candidates_related as mysql_request_candidates_related,
    validate_contract_candidate as mysql_validate_contract_candidate,
    validate_contract_witness as mysql_validate_contract_witness,
};
mod inventory;
mod loading;
pub(crate) mod runtime;
pub(crate) type ReplayState = RuntimeState<ReplayProtocols>;
pub(crate) mod report;
pub(crate) mod source;
use crate::policy::runtime::RequestContracts;
use crate::replay::PreparedProtocols;
use crate::replay::ReplayProtocol;
use crate::replay::ReplayTarget;
use crate::replay::RunSequenceReference;
use crate::replay::RuntimeState;
use crate::{MitmCa, replay};
use crate::{replay::protocol_runtime::InFlightScope, replay::protocol_runtime::ReplayProtocolSet};
use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use std::path::Path;
use std::{collections::BTreeMap, sync::Arc};
use tokio::{net::TcpStream, sync::Mutex};
use traffic_protocol::ProtocolId;
use traffic_replay::case::CaseRuntimeProjection;
use traffic_replay::{SequenceBinding, SequenceRuntime};

#[derive(Debug)]
pub(crate) struct ReplayProtocols {
    pub(crate) deferred_identities: Option<
        std::collections::HashMap<
            uuid::Uuid,
            traffic_protocol_mysql::session_identity::DependencyIdentity,
        >,
    >,
    pub(crate) mysql: mysql::MysqlReplayState,
    pub(crate) observations: (),

    pub(crate) changed: Arc<tokio::sync::Notify>,
}

impl ReplayProtocols {
    fn case_projections(&self) -> [&dyn CaseRuntimeProjection; 1] {
        [&self.mysql]
    }
}

impl CaseRuntimeProjection for ReplayProtocols {
    fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.case_projections()
            .iter()
            .any(|projection| projection.case_has_runtime_failure(case))
    }
    fn append_matched_dependency_counts(&self, case: &str, counts: &mut Vec<usize>) {
        for projection in self.case_projections() {
            projection.append_matched_dependency_counts(case, counts);
        }
    }
    fn append_case_failures(
        &self,
        case: &str,
        failures: &mut Vec<serde_json::Value>,
        limit: usize,
    ) {
        for projection in self.case_projections() {
            projection.append_case_failures(case, failures, limit);
        }
    }
}

impl ReplayProtocolSet for ReplayProtocols {
    type Policy = crate::policy::runtime::ReplayPolicyRuntime;
    type SourceLoader = loading::SourceLoader;
    type ReportSnapshot = report::snapshot::NativeSnapshot;
    type PrimaryClosePreparation = ();
    fn primary_close_input(
        case: &replay::ReplayCase,
    ) -> Result<Option<replay::protocol_runtime::primary_close::SourceInput>> {
        crate::primary_protocol::close_timing(case.directory(), case.id())
    }
    fn primary_streams(
        _: &RuntimeState<Self>,
        _: &str,
    ) -> Result<Vec<replay::protocol_runtime::primary_close::SourceStream>> {
        Ok(Vec::new())
    }

    fn prepare_primary_close(_case: &replay::ReplayCase, _source_close_ms: u64) -> Result<()> {
        Ok(())
    }

    fn install_primary_close(&mut self, _case: &str, _: ()) -> Result<()> {
        Ok(())
    }

    fn primary_closed(&mut self, _case: &str) {}

    fn snapshot_report(state: &RuntimeState<Self>) -> Self::ReportSnapshot {
        state.native_report_snapshot()
    }
    fn source_occurrence_rows(
        state: &RuntimeState<Self>,
        report: &serde_json::Value,
    ) -> Vec<replay::report::unused_source::SourceRow> {
        report::unused_source::rows(state, report)
    }
    fn native_events(
        &mut self,
    ) -> &mut dyn replay::protocol_runtime::events::NativeEventProjection {
        &mut self.observations
    }
    fn input_timing(&self) -> &dyn replay::protocol_runtime::input::InputTimingProjection {
        &self.observations
    }
    fn input_timing_mut(
        &mut self,
    ) -> &mut dyn replay::protocol_runtime::input::InputTimingProjection {
        &mut self.observations
    }
    fn resolve_references(
        state: &RuntimeState<Self>,
        case: &str,
        references: &[replay::RecordedReference],
    ) -> Result<Vec<replay::ProtocolExchange>> {
        inventory::resolve(state, case, references)
    }
    fn exchange_status(
        state: &RuntimeState<Self>,
        exchange: replay::ProtocolExchange,
    ) -> Option<replay::ReplayExchangeStatus> {
        inventory::status(state, exchange)
    }
    fn permits_cancelled_omission(
        state: &RuntimeState<Self>,
        exchange: replay::ProtocolExchange,
    ) -> bool {
        inventory::permits_cancelled_omission(state, exchange)
    }
    fn permits_unstarted_omission(
        state: &RuntimeState<Self>,
        exchange: replay::ProtocolExchange,
        shared_initialization: bool,
        strict_reference: bool,
    ) -> bool {
        inventory::permits_unstarted_omission(
            state,
            exchange,
            shared_initialization,
            strict_reference,
        )
    }
    fn shared_initialization(
        state: &RuntimeState<Self>,
        exchange: replay::ProtocolExchange,
        completion: &crate::recorder::async_api::CompletionRequirements,
    ) -> bool {
        inventory::shared_initialization(state, exchange, completion)
    }
    fn can_defer_dispatch(
        state: &RuntimeState<Self>,
        exchange: replay::ProtocolExchange,
        input_at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        exchange.inventory.as_str() == "mysql"
            && state
                .protocol_data()
                .mysql
                .can_defer_autocommit_for_dispatch(exchange.index, input_at)
    }
    fn visit_global_unused(
        state: &RuntimeState<Self>,
        protocol: &str,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        match protocol {
            "mysql" => state.visit_global_mysql_unused(visitor),

            _ => anyhow::bail!("unknown native Global report protocol"),
        }
    }

    fn global_report_extensions(
        &self,
        protocol: &str,
        report: &Path,
    ) -> Result<BTreeMap<String, serde_json::Value>> {
        self.global_report_extensions(protocol, report)
    }
    fn global_report_fallback(
        &self,
        protocol: &str,
        report: &Path,
        pages: crate::dependency_index::PageManifest,
    ) -> Result<serde_json::Value> {
        self.global_report_fallback(protocol, report, pages)
    }

    type SourceRecord = source::DependencyRecord;
    type SourceAppend = source::AppendedSource;
    fn register_source(
        &mut self,
        batch: replay::dependencies::SourceBatch<'_, Self::SourceRecord>,
        native: &mut replay::native::Inventory,
        targets: &mut BTreeMap<replay::TargetKey, ReplayTarget>,
    ) -> Result<Self::SourceAppend> {
        let appended = source::AppendedSource {
            mysql_start: self.mysql.source_len(),
        };
        let mut identities = self
            .deferred_identities
            .as_ref()
            .context("deferred native Source identities are absent")?
            .clone();
        source::register_dependency_records(
            batch.path,
            batch.records,
            batch.skip,
            batch.source,
            batch.case,
            &mut self.mysql,
            targets,
            &mut identities,
            batch.process_rules,
            batch.cleanup,
            native,
        )?;
        Ok(appended)
    }
    fn index_source(&mut self, _: &Self::SourceAppend) {}

    fn observe_source(
        &self,
        appended: &Self::SourceAppend,
        policy: &mut crate::policy::runtime::ReplayPolicyRuntime,
    ) {
        self.mysql
            .observe_registered_policy_exchanges(policy, appended.mysql_start, None);
    }

    fn release_payloads(&mut self, cases: &BTreeMap<String, replay::ReplayCase>) {
        self.mysql.release_consumed_payloads(cases);
    }

    fn case_is_dirty(&self, case: &str) -> bool {
        self.mysql.case_is_dirty(case)
    }

    fn pending_diagnostic(&self) -> BTreeMap<String, serde_json::Value> {
        BTreeMap::from([("mysql".into(), self.mysql.case_in_flight_diagnostic())])
    }

    fn prepare_candidates(&mut self) {
        self.mysql.prepare_candidates();
    }

    fn prepare_case(
        &mut self,
        case: &str,
        _ordered: bool,
        contracts: Option<&RequestContracts>,
    ) -> Result<PreparedProtocols> {
        Ok(BTreeMap::from([(
            ProtocolId::new("mysql"),
            self.mysql.prepare_case(case, contracts)?,
        )]))
    }

    fn run_sequence_refs(&mut self) -> Result<BTreeMap<ProtocolId, Vec<RunSequenceReference>>> {
        Ok(BTreeMap::from([(
            ProtocolId::new("mysql"),
            self.mysql.prepare_run_sequence()?,
        )]))
    }

    fn bind_case_sequence(
        &mut self,
        mut bindings: BTreeMap<ProtocolId, SequenceBinding>,
        _: &[Arc<SequenceRuntime>],
    ) {
        self.mysql.lifecycle.sequence = bindings
            .remove(&ProtocolId::new("mysql"))
            .unwrap_or_default();
    }

    fn attach_run_sequence(&mut self, bindings: &BTreeMap<ProtocolId, SequenceBinding>) {
        if let Some(binding) = bindings.get(&ProtocolId::new("mysql")) {
            self.mysql.lifecycle.sequence.attach_run(binding.clone());
        }
    }

    fn activate_case(&mut self, _: Option<&str>) {}

    fn begin_case(&mut self, _case: &str) {}

    fn close_case(&mut self, _case: &str) {}

    fn try_close_case(&self, _: &str) -> bool {
        true
    }

    fn io_changed(&self) -> Arc<tokio::sync::Notify> {
        self.changed.clone()
    }

    fn startup_counts(&mut self, close: bool) -> BTreeMap<String, traffic_replay::StartupCounts> {
        BTreeMap::from([("mysql".into(), self.mysql.startup_counts(close))])
    }

    fn close_startup(&mut self) {}

    fn initialize_connections(&mut self, _: Option<&str>) {}

    fn start(_state: Arc<Mutex<RuntimeState<Self>>>) {}

    fn has_in_flight(&self, scope: InFlightScope, _: Option<&str>) -> bool {
        match scope {
            InFlightScope::All => self.mysql.has_in_flight(),
            InFlightScope::Case => self.mysql.has_case_in_flight(),
        }
    }

    fn serve(
        stream: TcpStream,
        peer_addr: SocketAddr,
        mut target: Option<ReplayTarget>,
        state: Arc<Mutex<RuntimeState<Self>>>,
        ca: Arc<MitmCa>,
        providers: Arc<super::DependencyProviders>,
    ) -> traffic_protocol::connection::NativeFuture<'static, ()> {
        Box::pin(async move {
            if target
                .as_ref()
                .is_some_and(|target| target.protocol == ReplayProtocol::Auto)
            {
                let Some(protocol) =
                    auto_protocol::detect_with_providers(&stream, &providers).await?
                else {
                    return Ok(());
                };
                target
                    .as_mut()
                    .context("auto replay target missing")?
                    .protocol = protocol;
            }
            match target.as_ref().map(|target| target.protocol) {
                Some(ReplayProtocol::Mysql) => {
                    let endpoint = target.map(|target| traffic_protocol::connection::Endpoint {
                        host: target.host,
                        port: target.port,
                    });
                    mysql::handle_connection(stream, peer_addr, endpoint, state, ca).await
                }
                Some(_) => {
                    replay::native::handle_connection(
                        stream,
                        peer_addr,
                        target.context("native replay target missing")?,
                        state,
                    )
                    .await
                }
                None => {
                    #[cfg(test)]
                    {
                        mysql::handle_connection(stream, peer_addr, None, state, ca).await
                    }
                    #[cfg(not(test))]
                    {
                        Err(anyhow!("native replay connection has no registered target"))
                    }
                }
            }
        })
    }
}

#[allow(non_upper_case_globals)]
impl ReplayProtocol {
    pub const Mysql: Self = Self::new(traffic_protocol::ProtocolId::new("mysql"));
    pub const Http: Self = Self::new(traffic_protocol::ProtocolId::new("http"));
    pub const Https: Self = Self::new(traffic_protocol::ProtocolId::new("https"));
    pub const Redis: Self = Self::new(traffic_protocol::ProtocolId::new("redis"));

    pub(crate) fn resolve(
        value: &str,
        providers: &crate::protocols::DependencyProviders,
    ) -> Result<Self> {
        let known = [
            Self::Auto,
            Self::Mysql,
            Self::Http,
            Self::Https,
            Self::Redis,
        ];
        known
            .into_iter()
            .find(|protocol| protocol.id().as_str() == value)
            .or_else(|| {
                providers
                    .registrations()
                    .iter()
                    .find(|entry| entry.kind.as_str() == value)
                    .map(|entry| Self::registered(entry.kind))
            })
            .context("dependency protocol has no registered implementation")
    }
}

/// Historical snapshot plans require a stateful capability beyond finite native Replay.
pub(crate) fn inspect_case_source_snapshot_overlay(
    _case_source: &Path,
    _policy: &Path,
    _rule_name: &str,
) -> Result<crate::replay::report::command::CommandSnapshotOverlayReport> {
    anyhow::bail!("Redis snapshot overlays require an installed native snapshot capability")
}
