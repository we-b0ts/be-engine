//! Application fixtures using the real project and Source loaders.
use std::{fs, path::Path};

pub fn install_project_config(
    target_root: &Path,
    pr_base: &str,
    recorder: crate::config::AppConfig,
    _quality_gates: Option<serde_json::Value>,
) {
    let target = serde_json::json!({
        "dockerfile": ".traffic-e2e/Dockerfile.target",
        "startup": {},
    });
    let document = serde_json::json!({
        "version": 18,
        "project": {
            "policy": ".traffic-e2e/policy.yaml",
            "source": { "snapshot": ".traffic-e2e/local/source" },
            "target": target,
            "replay": {},
            "delivery": { "pr_base": pr_base },
            "state": { "runtime_root": "local/runtime" }
        },
        "recorder": recorder,
    });
    let directory = target_root.join(".traffic-e2e");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("project.yaml"),
        serde_yaml::to_string(&document).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("policy.yaml"),
        crate::config::native_policy::empty_policy().unwrap(),
    )
    .unwrap();
}

pub fn set_managed_paths(target_root: &Path, paths: &[&str]) {
    let path = target_root.join(".traffic-e2e/project.yaml");
    let mut document: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    document["project"]["delivery"]["managed_paths"] = serde_yaml::to_value(paths).unwrap();
    fs::write(path, serde_yaml::to_string(&document).unwrap()).unwrap();
}

pub fn managed_test_recorder() -> crate::config::AppConfig {
    let mut recorder = crate::config::AppConfig::default();
    recorder.http_gateway.ready.enabled = true;
    recorder.http_gateway.ready.path = "/healthz".to_string();
    recorder.http_gateway.ready.success_status = 404;
    recorder.http_gateway.rules = vec![crate::config::HttpGatewayRuleConfig {
        name: Some("http-rule".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/".to_string()],
        ..Default::default()
    }];
    recorder
}

pub fn install_source_snapshot(target_root: &Path) -> String {
    crate::source_snapshot::test_fixture::install(target_root)
}

pub fn configured_target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    install_project_config(target.path(), "master", managed_test_recorder(), None);
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    for args in [
        vec!["init", "-q", "-b", "master"],
        vec!["config", "user.email", "test@example.com"],
        vec!["config", "user.name", "Traffic E2E Test"],
        vec!["add", "."],
        vec!["commit", "-q", "-m", "baseline"],
        vec!["switch", "-q", "-c", "feature"],
    ] {
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    target
}

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
