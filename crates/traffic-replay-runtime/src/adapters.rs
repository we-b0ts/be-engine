pub use traffic_engine::protocols::replay::*;
pub(crate) mod loading;
pub(crate) mod report;
pub mod runtime;
#[allow(dead_code)]
pub(crate) type ReplayState = crate::replay::RuntimeState<ReplayProtocols>;
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

mod report_snapshot;

#[cfg(any(test, feature = "test-support"))]
pub(crate) mod http;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod http_test_support;
#[cfg(test)]
mod native_http_tests;
#[cfg(test)]
mod native_mysql_tests;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use http_test_support::{
    snapshot_http_replay, spawn_coordinator_http_replay, write_http_case,
};

#[cfg(test)]
mod native_protocol_tests;
