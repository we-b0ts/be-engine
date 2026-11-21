use std::path::Path;
pub use traffic_engine_config::test_support::*;
pub mod recording;

pub async fn wait_for_no_active_case(
    state: &crate::AppState,
    timeout: std::time::Duration,
) -> bool {
    state
        .inner
        .active_cases
        .wait_for_no_active_case(timeout)
        .await
}

pub async fn serve_recording_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    state: crate::AppState,
) -> anyhow::Result<()> {
    crate::tcp_gateway::connection::handle_connection(stream, peer, state).await
}

pub async fn close_bootstrap(
    state: &crate::AppState,
    reason: &'static str,
) -> anyhow::Result<bool> {
    state.close_bootstrap(reason).await
}
pub fn close_admission(state: &crate::AppState) {
    state.inner.active_cases.close_admission();
}
pub fn record_dependency(
    state: &crate::AppState,
    reference: crate::dependency::observation::ProtocolRef,
    event: crate::protocols::recording::events::RecorderEvent,
) {
    let targets = state.capture_dependency_start(reference);
    state.record_event_for_targets(event, targets);
}
pub fn record_unattributed_observation(
    state: &crate::AppState,
    event: crate::protocols::recording::events::RecorderEvent,
) {
    let targets = state.inner.active_cases.unattributed_observation_targets();
    state.record_event_for_targets(event, targets);
}
pub fn install_recording_upstream(
    state: &crate::AppState,
    host: &str,
    port: u16,
    upstream: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let mut routes = crate::recording_upstream::RecordingUpstreams::default();
    routes.insert(host, port, upstream)?;
    state.install_recording_upstreams(routes)
}
pub async fn serve_recording_gateway(
    state: crate::AppState,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    crate::gateway::http::run_with_listener(state, listener).await
}
pub async fn observe_accessed_endpoint(
    recorder: &crate::recorder::Recorder,
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    recorder.observe_accessed_endpoint(host, port).await
}
pub fn generate_encryption_key() -> anyhow::Result<String> {
    crate::request_headers::generate_encryption_key()
}
pub fn load_or_create_encryption_key(root: &Path) -> anyhow::Result<String> {
    crate::platform::encryption_key::load_or_create(root)
}
pub fn legacy_case_inventory_id(root: &Path) -> anyhow::Result<String> {
    crate::case_group::legacy_case_inventory_id(root)
}
pub const LOCAL_ENCRYPTION_KEY_FROM_LOCAL: &str =
    crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL;
pub const LOCAL_ENCRYPTION_KEY_PATH: &str = crate::repository::LOCAL_ENCRYPTION_KEY_PATH;
pub const LOCAL_TARGET_ENV_PATH: &str = crate::repository::LOCAL_TARGET_ENV_PATH;
pub const LOCAL_STARTUP_MOUNTS_ROOT: &str = crate::repository::LOCAL_STARTUP_MOUNTS_ROOT;

pub struct TestActiveCaseGuard(crate::active_case::ActiveCaseGuard);
impl TestActiveCaseGuard {
    pub fn activate_dependencies(&self) -> anyhow::Result<()> {
        self.0
            .activate_dependencies()
            .map_err(|error| anyhow::anyhow!("{error:?}"))
    }
}
pub fn reserve_active_case(
    state: &crate::AppState,
    case: crate::recorder::CaseContext,
) -> anyhow::Result<TestActiveCaseGuard> {
    state
        .try_reserve_active_case(case)
        .map(TestActiveCaseGuard)
        .map_err(|error| anyhow::anyhow!("{error:?}"))
}
