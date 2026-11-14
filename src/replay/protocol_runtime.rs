//! Application protocol state is supplied through lifecycle and connection ports.
use super::*;

#[derive(Clone, Copy)]
pub(crate) enum InFlightScope {
    All,
    Case,
}

pub(crate) trait ReplayProtocolSet: std::fmt::Debug + Send + Sized + 'static {
    fn case_is_dirty(&self, case: &str) -> bool;
    fn pending_diagnostic(&self) -> BTreeMap<String, Value>;
    fn prepare_candidates(&mut self);
    fn prepare_case(
        &mut self,
        case: &str,
        ordered: bool,
        contracts: Option<&RequestContracts>,
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
    pub(in crate::replay) fn set_active_case(&mut self, case: Option<String>) {
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
