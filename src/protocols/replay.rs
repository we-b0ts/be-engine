//! Application assembly for built-in protocol state and native connection drivers.
pub(crate) mod auto_protocol;
pub(crate) mod report;
pub(crate) mod source;
use crate::{MitmCa, replay};
use anyhow::{Context, Result, anyhow};
use replay::protocol_runtime::{InFlightScope, ReplayProtocolSet};
use replay::{
    PreparedProtocols, ReplayProtocol, ReplayTarget, RequestContracts, RunSequenceReference,
    RuntimeState,
};
use std::net::SocketAddr;
use std::path::Path;
use std::{collections::BTreeMap, sync::Arc};
use tokio::{net::TcpStream, sync::Mutex};
use traffic_protocol::ProtocolId;
use traffic_replay::{SequenceBinding, SequenceRuntime};

#[derive(Debug)]
pub(crate) struct ReplayProtocols {
    pub(crate) deferred_identities: Option<
        std::collections::HashMap<
            uuid::Uuid,
            traffic_protocol_mysql::session_identity::DependencyIdentity,
        >,
    >,
    pub(crate) mysql: replay::mysql::MysqlReplayState,
    pub(crate) redis: replay::redis::RedisReplayState,
    pub(crate) memcached: replay::memcached::MemcachedReplayState,
    pub(crate) kafka: replay::kafka::KafkaReplayState,
    pub(crate) motan: replay::motan::MotanReplayState,
    pub(crate) http_exchanges: Vec<replay::http::ReplayHttpExchange>,
    pub(crate) http_case_exchange_index: replay::CaseExchangeIndex,
    pub(crate) http_candidates: replay::http::candidates::Candidates,
    pub(crate) http_blackholes: Vec<replay::http::ReplayHttpBlackhole>,
    pub(crate) http_events: replay::http::HttpReplayEvents,
    pub(crate) http_sequence: replay::sequence::Binding,
    pub(crate) http_sequence_claims: BTreeMap<usize, traffic_replay::SequenceClaim>,
    pub(crate) http_input_timing: Option<Arc<replay::HttpInputTimeline>>,
    pub(crate) http_ingress: replay::http::ingress::HttpIngress,
    pub(crate) http_ignore_query_params: Vec<String>,
    pub(crate) allowed_unused_http: Option<replay::ReplayAllowedUnusedHttpConfig>,
}

impl ReplayProtocolSet for ReplayProtocols {
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
        replay::http::extend_case_exchange_index(
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
        policy: &mut replay::ReplayPolicyRuntime,
    ) {
        self.mysql
            .observe_registered_policy_exchanges(policy, appended.mysql_start);
        replay::http::observe_recorded_policy_exchanges(
            policy,
            &self.http_exchanges[appended.http_start..],
        );
        replay::memcached::observe_recorded_policy_exchanges(policy, &self.memcached);
    }
    fn release_payloads(&mut self, cases: &BTreeMap<String, replay::ReplayCase>) {
        self.mysql.release_consumed_payloads(cases);
        replay::http::release_consumed_payloads(&mut self.http_exchanges, cases);
        self.memcached.release_consumed_payloads(cases);
        self.motan.release_consumed_payloads(cases);
        self.kafka.release_consumed_payloads(cases);
    }

    fn case_is_dirty(&self, case: &str) -> bool {
        let dirty = self.mysql.case_is_dirty(case)
            || replay::http::case_is_dirty(
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
                replay::http::case_in_flight_diagnostic(&self.http_exchanges),
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
        let http = replay::http::preparation::prepare_case(
            &mut self.http_candidates,
            &self.http_exchanges,
            case,
        );
        Ok(BTreeMap::from([
            (ProtocolId::new("http"), http),
            (ProtocolId::new("redis"), redis),
            (ProtocolId::new("mysql"), mysql),
        ]))
    }
    fn run_sequence_refs(
        &mut self,
    ) -> anyhow::Result<BTreeMap<ProtocolId, Vec<RunSequenceReference>>> {
        let http = replay::http::preparation::prepare_run_sequence(
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
        if let Some(timeline) = self.http_input_timing.take() {
            timeline.abort();
        }
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
                replay::http::startup_counts(&mut self.http_exchanges, close),
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

    fn has_in_flight(&self, scope: InFlightScope, active_case: Option<&str>) -> bool {
        match scope {
            InFlightScope::All => {
                self.mysql.has_in_flight()
                    || self.redis.has_in_flight()
                    || self.memcached.has_in_flight()
                    || self.kafka.has_in_flight()
                    || self.motan.has_in_flight()
                    || replay::http::has_in_flight(&self.http_exchanges, &self.http_ingress, None)
            }
            InFlightScope::Case => {
                self.mysql.has_case_in_flight()
                    || self.redis.has_case_in_flight()
                    || self.memcached.has_case_in_flight()
                    || self.kafka.has_case_in_flight()
                    || self.motan.has_case_in_flight()
                    || replay::http::has_in_flight(
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
                            replay::redis::handle_connection(stream, target, state).await
                        }
                        Some(ReplayProtocol::Memcached) => {
                            replay::memcached::handle_connection(stream, target, state).await
                        }
                        Some(protocol @ (ReplayProtocol::Http | ReplayProtocol::Https)) => {
                            let mut target = target.clone();
                            target.protocol = protocol;
                            replay::http::handle_http_replay_connection(
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
                    replay::http::handle_http_replay_connection(
                        stream,
                        peer_addr,
                        target.context("HTTP replay connection has no target")?,
                        state,
                        ca,
                    )
                    .await
                }
                Some(ReplayProtocol::Redis) => {
                    replay::redis::handle_connection(
                        stream,
                        target.context("Redis replay connection has no target")?,
                        state,
                    )
                    .await
                }
                Some(ReplayProtocol::Memcached) => {
                    replay::memcached::handle_connection(
                        stream,
                        target.context("Memcached replay connection has no target")?,
                        state,
                    )
                    .await
                }
                Some(ReplayProtocol::Kafka) => {
                    replay::kafka::handle_connection(
                        stream,
                        target.context("Kafka replay connection has no target")?,
                        state,
                    )
                    .await
                }
                Some(ReplayProtocol::Motan) => {
                    replay::motan::handle_connection(
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
                    replay::mysql::handle_connection(stream, peer_addr, target, state, ca).await
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
                        replay::mysql::handle_connection(stream, peer_addr, None, state, ca).await
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
