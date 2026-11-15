//! Application assembly for built-in protocol state and native connection drivers.
pub(crate) mod auto_protocol;
pub(crate) mod http;
pub(crate) mod kafka;
pub(crate) mod memcached;
pub(crate) mod motan;
pub(crate) use http::contracts::{
    multipart_witness_matches as http_multipart_witness_matches,
    source_witness as http_source_witness, validate_witness as http_validate_witness,
    witness_metadata_matches as http_witness_metadata_matches, witness_value as http_witness_value,
};
pub(crate) use http::cross_case as http_cross_case;
pub use http::cross_case::HttpCrossCaseSelector;
pub(crate) use http::diagnosis as http_request_diagnosis;
#[cfg(test)]
pub(crate) use http::tests::{
    snapshot_http_replay, spawn_coordinator_http_replay, write_http_case,
};
pub(crate) use http::unordered as http_unordered;
pub(crate) mod redis;
pub(crate) use redis::expiration::normalize as normalize_redis_expiration;
pub(crate) use redis::request_fingerprint as redis_request_fingerprint;
pub(crate) use redis::snapshot_overlay::inspect_case_source_snapshot_overlay;
pub(crate) use redis::value as redis_value;
pub use redis::value::{RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector};
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
    pub(crate) redis: redis::RedisReplayState,
    pub(crate) memcached: crate::protocols::replay::memcached::MemcachedReplayState,
    pub(crate) kafka: crate::protocols::replay::kafka::KafkaReplayState,
    pub(crate) motan: crate::protocols::replay::motan::MotanReplayState,
    pub(crate) http_exchanges: Vec<http::ReplayHttpExchange>,
    pub(crate) http_case_exchange_index: replay::CaseExchangeIndex,
    pub(crate) http_candidates: http::candidates::Candidates,
    pub(crate) http_blackholes: Vec<http::ReplayHttpBlackhole>,
    pub(crate) http_events: http::HttpReplayEvents,
    pub(crate) http_sequence: replay::sequence::Binding,
    pub(crate) http_sequence_claims: BTreeMap<usize, traffic_replay::SequenceClaim>,
    pub(crate) http_ingress: http::ingress::HttpIngress,
    pub(crate) http_ignore_query_params: Vec<String>,
    pub(crate) allowed_unused_http: Option<runtime::ReplayAllowedUnusedHttpConfig>,
}

impl ReplayProtocols {
    fn case_projections(&self) -> [&dyn CaseRuntimeProjection; 6] {
        [
            &self.mysql,
            &self.http_events,
            &self.redis,
            &self.kafka,
            &self.memcached,
            &self.motan,
        ]
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
    type PrimaryClosePreparation = Vec<Vec<u8>>;
    fn primary_close_input(
        case: &replay::ReplayCase,
    ) -> Result<Option<replay::protocol_runtime::primary_close::SourceInput>> {
        crate::primary_protocol::close_timing(case.directory(), case.id())
    }
    fn primary_streams(
        state: &RuntimeState<Self>,
        case: &str,
    ) -> Result<Vec<replay::protocol_runtime::primary_close::SourceStream>> {
        http::input_timing::source_streams(state, case)
    }
    fn prepare_primary_close(
        case: &replay::ReplayCase,
        source_close_ms: u64,
    ) -> Result<Self::PrimaryClosePreparation> {
        redis::append::cancelled::load(case, source_close_ms)
    }
    fn install_primary_close(
        &mut self,
        case: &str,
        prepared: Self::PrimaryClosePreparation,
    ) -> Result<()> {
        self.redis.prepare_cancelled_caches(case, prepared)
    }
    fn primary_closed(&mut self, case: &str) {
        self.redis.confirm_cancelled_caches(case);
    }
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
        &mut self.redis
    }
    fn input_timing(&self) -> &dyn replay::protocol_runtime::input::InputTimingProjection {
        &self.redis
    }
    fn input_timing_mut(
        &mut self,
    ) -> &mut dyn replay::protocol_runtime::input::InputTimingProjection {
        &mut self.redis
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
        let protocols = state.protocol_data();
        match protocol {
            "mysql" => state.visit_global_mysql_unused(visitor),
            "http" => state.visit_global_http_unused(visitor),
            "redis" => protocols.redis.visit_global_regular_unused(visitor),
            "memcached" => protocols.memcached.visit_global_unused(visitor),
            "kafka" => protocols.kafka.visit_global_unused(visitor),
            "motan" => protocols.motan.visit_global_unused(visitor),
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
            http_start: self.http_exchanges.len(),
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
            &mut self.http_exchanges,
            &mut self.http_blackholes,
            &mut self.redis,
            &mut self.memcached,
            &mut self.kafka,
            &mut self.motan,
            targets,
            &mut identities,
            batch.process_rules,
            batch.cleanup,
            native,
        )?;
        Ok(appended)
    }
    fn index_source(&mut self, appended: &Self::SourceAppend) {
        http::extend_case_exchange_index(
            &mut self.http_case_exchange_index,
            &self.http_exchanges,
            appended.http_start,
        );
        self.http_ingress
            .register(&self.http_exchanges[appended.http_start..]);
    }
    fn observe_source(
        &self,
        appended: &Self::SourceAppend,
        policy: &mut crate::policy::runtime::ReplayPolicyRuntime,
    ) {
        self.mysql
            .observe_registered_policy_exchanges(policy, appended.mysql_start, None);
        http::observe_recorded_policy_exchanges(
            policy,
            &self.http_exchanges[appended.http_start..],
        );
        crate::protocols::replay::memcached::observe_recorded_policy_exchanges(
            policy,
            &self.memcached,
        );
    }
    fn release_payloads(&mut self, cases: &BTreeMap<String, replay::ReplayCase>) {
        self.mysql.release_consumed_payloads(cases);
        http::release_consumed_payloads(&mut self.http_exchanges, cases);
        self.memcached.release_consumed_payloads(cases);
        self.motan.release_consumed_payloads(cases);
        self.kafka.release_consumed_payloads(cases);
    }

    fn case_is_dirty(&self, case: &str) -> bool {
        let dirty = self.mysql.case_is_dirty(case)
            || http::case_is_dirty(
                &self.http_exchanges,
                &self.http_case_exchange_index,
                &self.http_ingress,
                &self.http_events,
                self.allowed_unused_http.as_ref(),
                case,
            )
            || self.redis.case_is_dirty(case)
            || self.memcached.case_is_dirty(case)
            || self.kafka.case_is_dirty(case)
            || self.motan.case_is_dirty(case);
        #[cfg(test)]
        {
            debug_assert_eq!(
                self.redis.case_is_dirty(case),
                self.redis.snapshot().case_is_dirty(case)
            );
            debug_assert_eq!(
                self.memcached.case_is_dirty(case),
                self.memcached.snapshot().case_is_dirty(case)
            );
            debug_assert_eq!(
                self.kafka.case_is_dirty(case),
                self.kafka.snapshot().case_is_dirty(case)
            );
            debug_assert_eq!(
                self.motan.case_is_dirty(case),
                self.motan.snapshot().case_is_dirty(case)
            );
        }
        dirty
    }
    fn pending_diagnostic(&self) -> BTreeMap<String, serde_json::Value> {
        BTreeMap::from([
            ("mysql".into(), self.mysql.case_in_flight_diagnostic()),
            (
                "http".into(),
                http::case_in_flight_diagnostic(&self.http_exchanges),
            ),
            (
                "http_ingress".into(),
                self.http_ingress.pending_diagnostic(),
            ),
            ("redis".into(), self.redis.case_in_flight_diagnostic()),
            (
                "memcached".into(),
                self.memcached.has_case_in_flight().into(),
            ),
            ("kafka".into(), self.kafka.has_case_in_flight().into()),
            ("motan".into(), self.motan.has_case_in_flight().into()),
        ])
    }

    fn prepare_candidates(&mut self) {
        self.http_candidates.register(&self.http_exchanges);
        self.mysql.prepare_candidates();
        self.redis.prepare_candidates();
    }
    fn prepare_case(
        &mut self,
        case: &str,
        ordered: bool,
        contracts: Option<&RequestContracts>,
    ) -> anyhow::Result<PreparedProtocols> {
        let redis = self.redis.prepare_case(case, ordered)?;
        let mysql = self.mysql.prepare_case(case, contracts)?;
        let http =
            http::preparation::prepare_case(&mut self.http_candidates, &self.http_exchanges, case);
        Ok(BTreeMap::from([
            (ProtocolId::new("http"), http),
            (ProtocolId::new("redis"), redis),
            (ProtocolId::new("mysql"), mysql),
        ]))
    }
    fn run_sequence_refs(
        &mut self,
    ) -> anyhow::Result<BTreeMap<ProtocolId, Vec<RunSequenceReference>>> {
        let http = http::preparation::prepare_run_sequence(
            &mut self.http_candidates,
            &self.http_exchanges,
        )?;
        let redis = self.redis.prepare_run_sequence();
        let mysql = self.mysql.prepare_run_sequence()?;
        Ok(BTreeMap::from([
            (ProtocolId::new("http"), http),
            (ProtocolId::new("redis"), redis),
            (ProtocolId::new("mysql"), mysql),
        ]))
    }
    fn bind_case_sequence(
        &mut self,
        mut bindings: BTreeMap<ProtocolId, SequenceBinding>,
        run: &[Arc<SequenceRuntime>],
    ) {
        self.http_sequence_claims
            .retain(|_, claim| run.iter().any(|runtime| claim.belongs_to(runtime)));
        self.http_sequence = bindings
            .remove(&ProtocolId::new("http"))
            .unwrap_or_default();
        self.mysql.lifecycle.sequence = bindings
            .remove(&ProtocolId::new("mysql"))
            .unwrap_or_default();
        self.redis.lifecycle.sequence = bindings
            .remove(&ProtocolId::new("redis"))
            .unwrap_or_default();
    }
    fn attach_run_sequence(&mut self, bindings: &BTreeMap<ProtocolId, SequenceBinding>) {
        for (protocol, binding) in bindings {
            match protocol.as_str() {
                "http" => self.http_sequence.attach_run(binding.clone()),
                "mysql" => self.mysql.lifecycle.sequence.attach_run(binding.clone()),
                "redis" => self.redis.lifecycle.sequence.attach_run(binding.clone()),
                _ => {}
            }
        }
    }
    fn activate_case(&mut self, case: Option<&str>) {
        self.http_ingress.activate_case(case);
    }
    fn begin_case(&mut self, case: &str) {
        self.redis.begin_case(case);
    }
    fn close_case(&mut self, case: &str) {
        self.redis.close_case(case);
    }
    fn try_close_case(&self, case: &str) -> bool {
        self.http_ingress.try_close_case(case)
    }
    fn io_changed(&self) -> Arc<tokio::sync::Notify> {
        self.http_ingress.changed.clone()
    }

    fn startup_counts(&mut self, close: bool) -> BTreeMap<String, traffic_replay::StartupCounts> {
        BTreeMap::from([
            ("mysql".into(), self.mysql.startup_counts(close)),
            (
                "http".into(),
                http::startup_counts(&mut self.http_exchanges, close),
            ),
            ("redis".into(), self.redis.startup_counts(close)),
            ("memcached".into(), self.memcached.startup_counts(close)),
            ("motan".into(), self.motan.startup_counts(close)),
            ("kafka".into(), self.kafka.startup_counts(close)),
        ])
    }

    fn close_startup(&mut self) {
        self.http_ingress.close_startup();
    }

    fn initialize_connections(&mut self, active: Option<&str>) {
        self.http_ingress.register(&self.http_exchanges);
        self.http_ingress.activate_case(active);
    }

    fn start(state: Arc<Mutex<RuntimeState<Self>>>) {
        redis::pubsub::ingress::start(state.clone());
        redis::pubsub::native_clock::start(state);
    }

    fn has_in_flight(&self, scope: InFlightScope, active_case: Option<&str>) -> bool {
        match scope {
            InFlightScope::All => {
                self.mysql.has_in_flight()
                    || self.redis.has_in_flight()
                    || self.memcached.has_in_flight()
                    || self.kafka.has_in_flight()
                    || self.motan.has_in_flight()
                    || http::has_in_flight(&self.http_exchanges, &self.http_ingress, None)
            }
            InFlightScope::Case => {
                self.mysql.has_case_in_flight()
                    || self.redis.has_case_in_flight()
                    || self.memcached.has_case_in_flight()
                    || self.kafka.has_case_in_flight()
                    || self.motan.has_case_in_flight()
                    || http::has_in_flight(
                        &self.http_exchanges,
                        &self.http_ingress,
                        Some(active_case),
                    )
            }
        }
    }

    fn serve(
        stream: TcpStream,
        peer_addr: SocketAddr,
        target: Option<ReplayTarget>,
        state: Arc<Mutex<RuntimeState<Self>>>,
        ca: Arc<MitmCa>,
        providers: Arc<super::DependencyProviders>,
    ) -> traffic_protocol::connection::NativeFuture<'static, ()> {
        Box::pin(async move {
            match target.as_ref().map(|target| target.protocol) {
                Some(ReplayProtocol::Auto) => {
                    let target = target.context("auto replay connection has no target")?;
                    match auto_protocol::detect_with_providers(&stream, &providers).await? {
                        Some(ReplayProtocol::Redis) => {
                            redis::handle_connection(stream, target, state).await
                        }
                        Some(ReplayProtocol::Memcached) => {
                            crate::protocols::replay::memcached::handle_connection(
                                stream, target, state,
                            )
                            .await
                        }
                        Some(protocol @ (ReplayProtocol::Http | ReplayProtocol::Https)) => {
                            let mut target = target.clone();
                            target.protocol = protocol;
                            http::handle_http_replay_connection(
                                stream, peer_addr, target, state, ca,
                            )
                            .await
                        }
                        Some(protocol)
                            if providers.registrations().iter().any(|entry| {
                                entry.kind.id() == protocol.id()
                                    && entry.provider.native_protocol().is_some()
                            }) =>
                        {
                            let mut target = target;
                            target.protocol = protocol;
                            replay::native::handle_connection(stream, peer_addr, target, state)
                                .await
                        }
                        Some(protocol) => Err(anyhow!(
                            "auto replay target resolved to unsupported protocol {protocol:?}"
                        )),
                        None => Ok(()),
                    }
                }
                Some(ReplayProtocol::Http) | Some(ReplayProtocol::Https) => {
                    http::handle_http_replay_connection(
                        stream,
                        peer_addr,
                        target.context("HTTP replay connection has no target")?,
                        state,
                        ca,
                    )
                    .await
                }
                Some(ReplayProtocol::Redis) => {
                    redis::handle_connection(
                        stream,
                        target.context("Redis replay connection has no target")?,
                        state,
                    )
                    .await
                }
                Some(ReplayProtocol::Memcached) => {
                    crate::protocols::replay::memcached::handle_connection(
                        stream,
                        target.context("Memcached replay connection has no target")?,
                        state,
                    )
                    .await
                }
                Some(ReplayProtocol::Kafka) => {
                    crate::protocols::replay::kafka::handle_connection(
                        stream,
                        target.context("Kafka replay connection has no target")?,
                        state,
                    )
                    .await
                }
                Some(ReplayProtocol::Motan) => {
                    crate::protocols::replay::motan::handle_connection(
                        stream,
                        target.context("Motan replay connection has no target")?,
                        state,
                    )
                    .await
                }
                Some(ReplayProtocol::Mysql) => {
                    let target = target.map(|target| traffic_protocol::connection::Endpoint {
                        host: target.host,
                        port: target.port,
                    });
                    mysql::handle_connection(stream, peer_addr, target, state, ca).await
                }
                Some(_) => {
                    replay::native::handle_connection(
                        stream,
                        peer_addr,
                        target.context("native replay connection has no target")?,
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
    pub const Memcached: Self = Self::new(traffic_protocol::ProtocolId::new("memcached"));
    pub const Kafka: Self = Self::new(traffic_protocol::ProtocolId::new("kafka"));
    pub const Motan: Self = Self::new(traffic_protocol::ProtocolId::new("motan"));

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
            Self::Memcached,
            Self::Kafka,
            Self::Motan,
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
