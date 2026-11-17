//! Application protocol state is supplied through lifecycle and connection ports.
use super::*;
pub(crate) mod events;
pub(crate) mod input;
pub(crate) mod loading;
pub(crate) mod primary_close;

#[derive(Clone, Copy)]
pub(crate) enum InFlightScope {
    All,
    Case,
}

pub(crate) trait ReplayProtocolSet:
    std::fmt::Debug
    + Send
    + Sized
    + traffic_replay::report::GlobalReportRuntime
    + traffic_replay::case::CaseRuntimeProjection
    + 'static
{
    type Policy: ReplayPolicy;
    type SourceLoader: loading::ProtocolSourceLoader<Protocols = Self>;
    type ReportSnapshot: traffic_replay::report::SessionSnapshot;
    fn snapshot_report(state: &RuntimeState<Self>) -> Self::ReportSnapshot;
    fn source_occurrence_rows(
        state: &RuntimeState<Self>,
        report: &Value,
    ) -> Vec<report::unused_source::SourceRow>;
    fn native_events(&mut self) -> &mut dyn events::NativeEventProjection;
    fn input_timing(&self) -> &dyn input::InputTimingProjection;
    fn input_timing_mut(&mut self) -> &mut dyn input::InputTimingProjection;
    type PrimaryClosePreparation: Send + 'static;
    fn primary_close_input(case: &ReplayCase) -> Result<Option<primary_close::SourceInput>>;
    fn primary_streams(
        state: &RuntimeState<Self>,
        case: &str,
    ) -> Result<Vec<primary_close::SourceStream>>;
    fn prepare_primary_close(
        case: &ReplayCase,
        source_close_ms: u64,
    ) -> Result<Self::PrimaryClosePreparation>;
    fn install_primary_close(
        &mut self,
        case: &str,
        prepared: Self::PrimaryClosePreparation,
    ) -> Result<()>;
    fn primary_closed(&mut self, case: &str);
    fn resolve_references(
        state: &RuntimeState<Self>,
        case: &str,
        references: &[RecordedReference],
    ) -> Result<Vec<adapters::ProtocolExchange>>;
    fn exchange_status(
        state: &RuntimeState<Self>,
        exchange: adapters::ProtocolExchange,
    ) -> Option<ReplayExchangeStatus>;
    fn permits_cancelled_omission(
        state: &RuntimeState<Self>,
        exchange: adapters::ProtocolExchange,
    ) -> bool;
    fn permits_unstarted_omission(
        state: &RuntimeState<Self>,
        exchange: adapters::ProtocolExchange,
        shared_initialization: bool,
        strict_reference: bool,
    ) -> bool;
    fn shared_initialization(
        state: &RuntimeState<Self>,
        exchange: adapters::ProtocolExchange,
        completion: &crate::recorder::async_api::CompletionRequirements,
    ) -> bool;
    fn can_defer_dispatch(
        state: &RuntimeState<Self>,
        exchange: adapters::ProtocolExchange,
        input_at: DateTime<Utc>,
    ) -> bool;
    fn visit_global_unused(
        state: &RuntimeState<Self>,
        protocol: &str,
        visitor: &mut dyn FnMut(Value) -> Result<()>,
    ) -> Result<()>;
    fn global_report_extensions(
        &self,
        protocol: &str,
        report: &Path,
    ) -> Result<BTreeMap<String, Value>>;
    fn global_report_fallback(
        &self,
        protocol: &str,
        report: &Path,
        pages: crate::dependency_index::PageManifest,
    ) -> Result<Value>;
    type SourceRecord: serde::de::DeserializeOwned + Send + 'static;
    fn validate_source_record(value: &Value) -> Result<()> {
        dependencies::validate_outcome(value)?;
        let _: Self::SourceRecord = serde_json::from_value(value.clone())?;
        Ok(())
    }

    type SourceAppend;
    fn register_source(
        &mut self,
        batch: dependencies::SourceBatch<'_, Self::SourceRecord>,
        native: &mut native::Inventory,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<Self::SourceAppend>;
    fn index_source(&mut self, appended: &Self::SourceAppend);
    fn observe_source(&self, appended: &Self::SourceAppend, policy: &mut Self::Policy);
    fn release_payloads(&mut self, cases: &BTreeMap<String, ReplayCase>);

    fn case_is_dirty(&self, case: &str) -> bool;
    fn pending_diagnostic(&self) -> BTreeMap<String, Value>;
    fn prepare_candidates(&mut self);
    fn prepare_case(
        &mut self,
        case: &str,
        ordered: bool,
        contracts: Option<&<Self::Policy as ReplayPolicy>::Contracts>,
    ) -> Result<PreparedProtocols>;
    fn run_sequence_refs(
        &mut self,
    ) -> Result<BTreeMap<traffic_protocol::ProtocolId, Vec<RunSequenceReference>>>;
    fn bind_case_sequence(
        &mut self,
        bindings: BTreeMap<traffic_protocol::ProtocolId, sequence::Binding>,
        run: &[Arc<traffic_replay::SequenceRuntime>],
    );
    fn attach_run_sequence(
        &mut self,
        bindings: &BTreeMap<traffic_protocol::ProtocolId, sequence::Binding>,
    );
    fn activate_case(&mut self, case: Option<&str>);
    fn begin_case(&mut self, case: &str);
    fn close_case(&mut self, case: &str);
    fn try_close_case(&self, case: &str) -> bool;
    fn io_changed(&self) -> Arc<tokio::sync::Notify>;

    fn startup_counts(&mut self, close: bool) -> BTreeMap<String, traffic_replay::StartupCounts>;
    fn close_startup(&mut self);
    fn initialize_connections(&mut self, active: Option<&str>);
    fn start(state: Arc<Mutex<RuntimeState<Self>>>);
    fn has_in_flight(&self, scope: InFlightScope, active_case: Option<&str>) -> bool;
    fn serve(
        stream: TcpStream,
        peer: SocketAddr,
        target: Option<ReplayTarget>,
        state: Arc<Mutex<RuntimeState<Self>>>,
        ca: Arc<MitmCa>,
        providers: Arc<crate::protocols::DependencyProviders>,
    ) -> traffic_protocol::connection::NativeFuture<'static, ()>;
}

impl<P: ReplayProtocolSet> RuntimeState<P> {
    pub(crate) fn protocol_data(&self) -> &P {
        &self.protocols
    }

    pub(crate) fn set_active_case(&mut self, case: Option<String>) {
        if self.active_case_id != case {
            self.activate_sequence(case.as_deref());
        }
        self.protocols.activate_case(case.as_deref());
        self.active_case_id = case;
    }

    pub(crate) fn has_protocol_io(&self, scope: InFlightScope) -> bool {
        self.protocols
            .has_in_flight(scope, self.active_case_id.as_deref())
            || match scope {
                InFlightScope::All => self.native.has_in_flight(),
                InFlightScope::Case => self.native.has_case_in_flight(),
            }
            || self.connect_failures.has_in_flight()
    }

    pub(crate) async fn serve_connection(
        stream: TcpStream,
        peer: SocketAddr,
        target: Option<ReplayTarget>,
        state: Arc<Mutex<Self>>,
        ca: Arc<MitmCa>,
    ) -> Result<()> {
        let providers = state.lock().await.providers.clone();
        P::serve(stream, peer, target, state, ca, providers).await
    }
}
