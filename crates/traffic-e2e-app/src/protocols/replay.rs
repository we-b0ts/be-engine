//! Application assembly for built-in protocol state and native connection drivers.
pub(crate) mod auto_protocol;
pub(crate) mod http;
#[cfg(test)]
pub(crate) mod http_test_support;
#[cfg(test)]
mod native_http_tests;
#[cfg(test)]
mod native_mysql_tests;
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
pub(crate) mod redis_value {}
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
pub(crate) fn mysql_source_witness(
    event: &serde_json::Value,
    surface: crate::policy::Surface,
) -> anyhow::Result<Vec<u8>> {
    traffic_protocol_mysql::witness::source_payload(event, surface.dependency_side()?)
}
pub(crate) fn mysql_witness_sql_value(
    raw: &[u8],
    surface: crate::policy::Surface,
    database: Option<&str>,
    index: usize,
) -> anyhow::Result<Option<serde_json::Value>> {
    let mut value = traffic_protocol_mysql::witness::sql_value(
        raw,
        surface.dependency_side()?,
        database,
        index,
    )?;
    if let Some(value) = &mut value
        && let Some(text) = value["value"].as_str()
        && let Some(codec) =
            crate::value_codec::try_recognize(text.as_bytes(), &traffic_value::Value::Null)?
        && let Ok(decoded) = codec.decode(text.as_bytes())
        && (decoded.logical.is_object() || decoded.logical.is_array())
    {
        value["json"] = decoded.logical;
    }
    Ok(value)
}
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
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::Path;
use std::{collections::BTreeMap, sync::Arc};
use tokio::{net::TcpStream, sync::Mutex};
use traffic_protocol::ProtocolId;
use traffic_replay::case::CaseRuntimeProjection;
use traffic_replay::{SequenceBinding, SequenceRuntime};

#[derive(Debug)]
pub(crate) struct ReplayProtocols {
    pub(crate) observations: (),

    pub(crate) changed: Arc<tokio::sync::Notify>,
}

impl CaseRuntimeProjection for ReplayProtocols {
    fn case_has_runtime_failure(&self, _: &str) -> bool {
        false
    }
    fn append_matched_dependency_counts(&self, _: &str, _: &mut Vec<usize>) {}
    fn append_case_failures(&self, _: &str, _: &mut Vec<serde_json::Value>, _: usize) {}
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
        _state: &RuntimeState<Self>,
        _report: &serde_json::Value,
    ) -> Vec<replay::report::unused_source::SourceRow> {
        Vec::new()
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
        _state: &RuntimeState<Self>,
        _case: &str,
        references: &[replay::RecordedReference],
    ) -> Result<Vec<replay::ProtocolExchange>> {
        anyhow::ensure!(
            references.is_empty(),
            "reference has no specialized inventory"
        );
        Ok(Vec::new())
    }
    fn exchange_status(
        _state: &RuntimeState<Self>,
        _exchange: replay::ProtocolExchange,
    ) -> Option<replay::ReplayExchangeStatus> {
        None
    }
    fn permits_cancelled_omission(
        _state: &RuntimeState<Self>,
        _exchange: replay::ProtocolExchange,
    ) -> bool {
        false
    }
    fn permits_unstarted_omission(
        _state: &RuntimeState<Self>,
        _exchange: replay::ProtocolExchange,
        _shared_initialization: bool,
        _strict_reference: bool,
    ) -> bool {
        false
    }
    fn shared_initialization(
        _state: &RuntimeState<Self>,
        _exchange: replay::ProtocolExchange,
        _completion: &crate::recorder::async_api::CompletionRequirements,
    ) -> bool {
        false
    }
    fn can_defer_dispatch(
        _state: &RuntimeState<Self>,
        _exchange: replay::ProtocolExchange,
        _input_at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        false
    }
    fn visit_global_unused(
        _state: &RuntimeState<Self>,
        _protocol: &str,
        _visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        anyhow::bail!("unknown specialized Global report protocol")
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
    type SourceAppend = ();
    fn register_source(
        &mut self,
        batch: replay::dependencies::SourceBatch<'_, Self::SourceRecord>,
        native: &mut replay::native::Inventory,
        targets: &mut BTreeMap<replay::TargetKey, ReplayTarget>,
    ) -> Result<Self::SourceAppend> {
        source::register_dependency_records(
            batch.path,
            batch.records,
            batch.skip,
            batch.source,
            batch.case,
            targets,
            batch.process_rules,
            batch.cleanup,
            native,
        )
    }
    fn index_source(&mut self, _: &Self::SourceAppend) {}

    fn observe_source(
        &self,
        _appended: &Self::SourceAppend,
        _policy: &mut crate::policy::runtime::ReplayPolicyRuntime,
    ) {
    }

    fn release_payloads(&mut self, _cases: &BTreeMap<String, replay::ReplayCase>) {}

    fn case_is_dirty(&self, _case: &str) -> bool {
        false
    }

    fn pending_diagnostic(&self) -> BTreeMap<String, serde_json::Value> {
        BTreeMap::new()
    }

    fn prepare_candidates(&mut self) {}

    fn prepare_case(
        &mut self,
        _case: &str,
        _ordered: bool,
        _contracts: Option<&RequestContracts>,
    ) -> Result<PreparedProtocols> {
        Ok(BTreeMap::new())
    }

    fn run_sequence_refs(&mut self) -> Result<BTreeMap<ProtocolId, Vec<RunSequenceReference>>> {
        Ok(BTreeMap::new())
    }

    fn bind_case_sequence(
        &mut self,
        _bindings: BTreeMap<ProtocolId, SequenceBinding>,
        _: &[Arc<SequenceRuntime>],
    ) {
    }

    fn attach_run_sequence(&mut self, _bindings: &BTreeMap<ProtocolId, SequenceBinding>) {}

    fn activate_case(&mut self, _: Option<&str>) {}

    fn begin_case(&mut self, _case: &str) {}

    fn close_case(&mut self, _case: &str) {}

    fn try_close_case(&self, _: &str) -> bool {
        true
    }

    fn io_changed(&self) -> Arc<tokio::sync::Notify> {
        self.changed.clone()
    }

    fn startup_counts(&mut self, _close: bool) -> BTreeMap<String, traffic_replay::StartupCounts> {
        BTreeMap::new()
    }

    fn close_startup(&mut self) {}

    fn initialize_connections(&mut self, _: Option<&str>) {}

    fn start(_state: Arc<Mutex<RuntimeState<Self>>>) {}

    fn has_in_flight(&self, _scope: InFlightScope, _: Option<&str>) -> bool {
        false
    }

    fn serve(
        stream: TcpStream,
        peer_addr: SocketAddr,
        mut target: Option<ReplayTarget>,
        state: Arc<Mutex<RuntimeState<Self>>>,
        _ca: Arc<MitmCa>,
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
            replay::native::handle_connection(
                stream,
                peer_addr,
                target.context("native replay target missing")?,
                state,
            )
            .await
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
