//! Standalone Source supervision, recording gateways and capture lifecycle.
pub use dns_mock::{FakeDnsEntry, FakeDnsRegistry, FakeDnsUpstreamProtocol};
pub use network_probe::PreflightProbeKind;
pub use recorder::{BodyCapture, Recorder, capture_body};
pub use recording_control::{
    RecordingReadiness, RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready,
};
pub use traffic_engine_config::config::*;
pub use traffic_engine_config::recording_api::RecordingApi;
pub use traffic_engine_config::{
    access_policy, breeze, config, json_value, motan, mysql, path_pattern, recording_api, redis,
};
pub use traffic_engine_environment::{
    TRAFFIC_PROCESS_GID, TRAFFIC_PROCESS_UID, TRAFFIC_PROCESS_USER, command_output, engine_binary,
    repository, source_snapshot, startup,
};
pub use traffic_engine_evidence::{
    ArtifactOwner, api_trigger, artifact_owner, case_group, dependency, dependency_index,
    policy_evidence, request_headers,
};
pub use traffic_engine_replay::{MitmCa, replay, tls};
pub use traffic_engine_verification::{policy, value_codec};
pub use traffic_model::DependencyExchangeOutcome;
pub use traffic_recording_model::*;
pub mod active_case;
pub mod dns_mock;
pub mod gateway;
pub mod http;
pub mod local_interception;
pub mod network_probe;
pub mod platform;
pub mod protocols;
pub mod proxy;
pub mod record_service;
pub mod recorder;
pub mod recording_case;
pub mod recording_completion;
pub mod recording_control;
pub mod recording_dispatch;
pub mod recording_network;
pub mod recording_runtime;
pub mod recording_stream_tail;
pub mod recording_upstream;
pub mod tcp_gateway;
pub mod tcp_listener;
pub mod udp_gateway;
use crate::access_policy::{AccessDecision, OperationClass, decide};
use crate::active_case::{
    ActiveCaseActivationError, ActiveCaseGuard, ActiveCaseRegistry, ActiveCaseRejection,
    DependencyTargets,
};
use crate::dns_mock::DomainMatcher;
use crate::http::rewrite::KubectlProxyManager;
use crate::protocols::recording::background::BackgroundDependencyMatcher;
use crate::recorder::CaseInvalidation;
use crate::recorder::cache_snapshot::{CacheSnapshotReservation, CacheSnapshotStore};
use crate::recorder::connections::DependencyConnections;
#[cfg(test)]
use crate::recorder::readiness::PostReadyWaitOutcome;
use crate::recording_control::RecordingLifecycle;
use anyhow::{Context, Result};
use hyper_util::client::legacy::Client;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};
use uuid::Uuid;

type ProxyClient = Client<http::client::ObservedConnector, http_body_util::Full<bytes::Bytes>>;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: AppConfig,
    providers: Arc<protocols::DependencyProviders>,
    recording_apis: Vec<RecordingApi>,
    recorder: Recorder,
    dns_registry: FakeDnsRegistry,
    dns_bypass_matcher: DomainMatcher,
    recording_upstreams: std::sync::OnceLock<recording_upstream::RecordingUpstreams>,
    ca: MitmCa,
    client: ProxyClient,
    forwarded_http_client: ProxyClient,
    upstream_tls_config: Arc<ClientConfig>,
    active_cases: ActiveCaseRegistry,
    interactions: gateway::http::interaction::Sessions,
    dependency_connections: DependencyConnections,
    kubectl_proxy_manager: KubectlProxyManager,
    response_rewrites: http::rewrite::CompiledRewrites,
    recording_lifecycle: RecordingLifecycle,
    process_owned_dependencies: BackgroundDependencyMatcher,
    #[allow(dead_code)]
    cache_snapshots: CacheSnapshotStore,
    preflight_probe: Option<PreflightProbeKind>,
    preflight_probe_recorded: AtomicBool,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        Self::new_with_run_id(config, None).await
    }

    pub async fn new_with_providers(
        config: AppConfig,
        providers: Arc<protocols::DependencyProviders>,
    ) -> Result<Self> {
        Self::new_with_recording_options_and_providers(
            config,
            None,
            Vec::new(),
            None,
            None,
            providers,
        )
        .await
    }

    pub fn dependency_providers(&self) -> &protocols::DependencyProviders {
        &self.inner.providers
    }

    pub async fn new_with_run_id(config: AppConfig, run_id: Option<String>) -> Result<Self> {
        Self::new_with_recording_apis(config, run_id, Vec::new()).await
    }

    pub async fn new_with_recording_apis(
        config: AppConfig,
        run_id: Option<String>,
        recording_apis: Vec<RecordingApi>,
    ) -> Result<Self> {
        Self::new_with_recording_apis_and_artifact_owner(config, run_id, recording_apis, None).await
    }

    pub async fn new_with_recording_apis_and_artifact_owner(
        config: AppConfig,
        run_id: Option<String>,
        recording_apis: Vec<RecordingApi>,
        artifact_owner: Option<ArtifactOwner>,
    ) -> Result<Self> {
        Self::new_with_recording_options(config, run_id, recording_apis, artifact_owner, None).await
    }

    pub async fn new_with_recording_options(
        config: AppConfig,
        run_id: Option<String>,
        recording_apis: Vec<RecordingApi>,
        artifact_owner: Option<ArtifactOwner>,
        preflight_probe: Option<PreflightProbeKind>,
    ) -> Result<Self> {
        Self::new_with_recording_options_and_providers(
            config,
            run_id,
            recording_apis,
            artifact_owner,
            preflight_probe,
            protocols::default_providers(),
        )
        .await
    }

    pub async fn new_with_recording_options_and_providers(
        config: AppConfig,
        run_id: Option<String>,
        recording_apis: Vec<RecordingApi>,
        artifact_owner: Option<ArtifactOwner>,
        preflight_probe: Option<PreflightProbeKind>,
        providers: Arc<protocols::DependencyProviders>,
    ) -> Result<Self> {
        config
            .validate()
            .context("invalid recorder configuration")?;
        recording_api::validate_selection(&recording_apis, &config.http_gateway.rules)
            .context("invalid recording API selection")?;
        let background_rules = config.process_owned_dependencies.clone();
        let process_owned_dependencies = tokio::task::spawn_blocking(move || {
            BackgroundDependencyMatcher::from_rules(&background_rules)
        })
        .await
        .context("process-owned dependency initializer task failed")?
        .context("failed to initialize process-owned dependency rules")?;
        let cache_snapshots = CacheSnapshotStore::new(&config.recording);
        let dns_bypass_matcher = DomainMatcher::from_config(&config.dns_mock)
            .context("failed to initialize DNS bypass matcher")?;
        for route in &config.upstream_routes {
            anyhow::ensure!(
                !dns_bypass_matcher.matches(&route.host),
                "upstream route for {} conflicts with DNS bypass",
                route.host
            );
        }
        let recording_output_dir = config.recording_output_dir();
        let recording_api_limits = recording_apis
            .iter()
            .map(|api| {
                (
                    api.to_string(),
                    config
                        .http_gateway
                        .per_api_case_limits
                        .limit_for(api.path_pattern()),
                )
            })
            .collect();
        let recorder = Recorder::new_with_recording_config_at_and_run_id(
            &config.recording,
            recording_output_dir,
            run_id,
            recording_api_limits,
            artifact_owner,
            Arc::new(providers.evidence().clone()),
        )
        .await
        .context("failed to initialize JSONL recorder")?
        .with_global_preparation_and_providers(&config, providers.clone())
        .await?;
        let dns_registry = FakeDnsRegistry::load_or_new(
            &config.dns_mock.fake_cidr,
            Some(&config.dns_mock.registry_path),
            &config.dns_mock.bypass_domains,
        )
        .context("failed to initialize fake DNS registry")?;
        let ca = MitmCa::load_or_generate(&config.tls.ca_cert_path, &config.tls.ca_key_path)
            .context("failed to initialize MITM CA")?;
        let upstream_tls_config = build_upstream_tls_config(&ca)?;
        let response_rewrites =
            http::rewrite::CompiledRewrites::new(&config.http_response_rewrite)?;
        let client = http::client::new_proxy_client();
        let forwarded_http_client = http::client::new_unpooled_proxy_client();

        let case_matching_ready =
            !(config.http_gateway.enabled && config.http_gateway.ready.enabled);
        let recording_lifecycle = RecordingLifecycle::from_config(&config);
        let capture_registry = recorder.capture.clone();
        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                providers,
                recording_apis,
                recorder,
                dns_registry,
                dns_bypass_matcher,
                recording_upstreams: std::sync::OnceLock::new(),
                ca,
                client,
                forwarded_http_client,
                upstream_tls_config,
                active_cases: ActiveCaseRegistry::new(case_matching_ready)
                    .with_capture(capture_registry),
                interactions: gateway::http::interaction::Sessions::default(),
                dependency_connections: DependencyConnections::default(),
                kubectl_proxy_manager: KubectlProxyManager::default(),
                response_rewrites,
                recording_lifecycle,
                process_owned_dependencies,
                cache_snapshots,
                preflight_probe,
                preflight_probe_recorded: AtomicBool::new(false),
            }),
        })
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn recorder(&self) -> &Recorder {
        &self.inner.recorder
    }

    pub fn should_record_api(&self, method: &hyper::Method, uri: &hyper::Uri) -> bool {
        self.inner.recording_apis.is_empty() || self.recording_api_pattern(method, uri).is_some()
    }

    pub fn recording_api_pattern(&self, method: &hyper::Method, uri: &hyper::Uri) -> Option<&str> {
        self.inner
            .recording_apis
            .iter()
            .find(|api| api.matches(method, uri))
            .map(RecordingApi::path_pattern)
    }

    pub fn access_decision(&self, operation: OperationClass) -> AccessDecision {
        decide(self.config().recording.access_policy, operation)
    }

    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub async fn record_access_policy_allow(
        &self,
        rule: impl Into<String>,
        protocol: &str,
        operation_class: OperationClass,
        operations: Vec<String>,
        resources: Vec<String>,
        client_addr: Option<String>,
        target: Option<String>,
        reason: impl Into<String>,
    ) {
        let rule = rule.into();
        let reason = reason.into();
        let access_policy = self.config().recording.access_policy.as_str();
        info!(
            access_policy,
            rule,
            protocol,
            operation_class = operation_class.as_str(),
            operations = ?operations,
            resources = ?resources,
            target = target.as_deref(),
            "recording access rule allowed request"
        );
        let event = RecorderEvent::AccessPolicyAllow(AccessPolicyAllowEvent {
            id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            access_policy: access_policy.to_string(),
            rule,
            protocol: protocol.to_string(),
            operation_class: operation_class.as_str().to_string(),
            operations,
            resources,
            client_addr,
            target,
            reason,
        });
        if let Err(error) = self.recorder().record(event).await {
            warn!(error = %error, "failed to record access policy allow event");
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_readonly_rejection(
        &self,
        protocol: &str,
        operation_class: OperationClass,
        operation: impl Into<String>,
        client_addr: Option<String>,
        target: Option<String>,
        reason: impl Into<String>,
    ) {
        let operation = operation.into();
        let reason = reason.into();
        let access_policy = self.config().recording.access_policy.as_str();
        let target_label = target.as_deref().unwrap_or("unknown target");
        let invalidated_case = self.inner.active_cases.invalidate_current_case(
            CaseInvalidation::new(
                "recording_access_policy_rejection",
                format!(
                    "access policy {access_policy} rejected {protocol} {} operation {operation} targeting {target_label}: {reason}",
                    operation_class.as_str()
                ),
            ),
        );
        warn!(
            access_policy,
            protocol,
            operation_class = operation_class.as_str(),
            operation,
            target = target.as_deref(),
            reason,
            "recording access policy rejected request"
        );
        if let Some(case) = &invalidated_case {
            warn!(
                case_id = %case.id,
                rule = %case.rule_name,
                "active recording case invalidated by access policy rejection"
            );
        }
        let event = RecorderEvent::ReadonlyRejection(ReadonlyRejectionEvent {
            id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            access_policy: access_policy.to_string(),
            protocol: protocol.to_string(),
            operation_class: operation_class.as_str().to_string(),
            operation,
            client_addr,
            target,
            reason,
        });
        let mut targets = self.capture_dependency_targets();
        targets.bootstrap_open = false;
        self.record_event_for_targets(event, targets);
    }

    pub fn dns_registry(&self) -> &FakeDnsRegistry {
        &self.inner.dns_registry
    }

    pub fn dns_bypass_matcher(&self) -> &DomainMatcher {
        &self.inner.dns_bypass_matcher
    }

    pub fn response_rewrites(&self) -> &http::rewrite::CompiledRewrites {
        &self.inner.response_rewrites
    }

    pub fn kubectl_proxy_manager(&self) -> &KubectlProxyManager {
        &self.inner.kubectl_proxy_manager
    }

    pub fn ca(&self) -> &MitmCa {
        &self.inner.ca
    }

    fn client(&self) -> &ProxyClient {
        &self.inner.client
    }

    fn upstream_tls_config(&self) -> Arc<ClientConfig> {
        self.inner.upstream_tls_config.clone()
    }

    pub fn dependency_connections(&self) -> &DependencyConnections {
        &self.inner.dependency_connections
    }

    #[allow(dead_code)]
    pub fn matching_redis_snapshot_rule(
        &self,
        target_port: u16,
        command: &str,
        args: &[Vec<u8>],
    ) -> Option<&str> {
        self.inner
            .process_owned_dependencies
            .matching_redis_snapshot_rule(target_port, command, args)
    }

    pub fn has_redis_snapshot_port(&self, port: u16) -> bool {
        self.inner
            .process_owned_dependencies
            .has_redis_snapshot_port(port)
    }

    #[allow(dead_code)]
    pub async fn reserve_cache_snapshot(&self, key: Vec<u8>) -> Result<CacheSnapshotReservation> {
        self.inner.cache_snapshots.reserve(key).await
    }

    #[allow(dead_code)]
    pub async fn complete_cache_snapshot(
        &self,
        key: &[u8],
        response: bytes::Bytes,
        reusable: bool,
    ) -> Result<()> {
        self.inner
            .cache_snapshots
            .complete(key, response, reusable)
            .await
    }

    #[allow(dead_code)]
    pub async fn abort_cache_snapshot(&self, key: &[u8], reason: &str) {
        self.inner.cache_snapshots.abort(key, reason).await;
    }
}

fn build_upstream_tls_config(ca: &MitmCa) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
        .add(ca.ca_cert_der())
        .context("failed to add recorder CA to upstream TLS roots")?;
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

#[cfg(test)]
mod app_state_tests;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub mod interaction;
pub use replay::ReplayEgressCounterReader;

pub use replay::ReplayEgressCounterSnapshot;
pub use traffic_model::DiscoveredTcpTarget;

pub use traffic_engine_verification::{primary_protocol, recorded_request};
pub use traffic_model::{
    DependencyTermination, TerminationKind, TerminationScope, TerminationSide,
};
pub use traffic_recorder::CaseContext;
