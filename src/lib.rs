mod access_policy;
mod active_case;
mod case_group;
mod case_kind;
mod comparison_recording;
mod config;
mod dependency;
mod dns_mock;
mod e2e_run;
mod gateway;
mod http;
mod kafka;
mod memcached;
mod motan;
mod mysql;
mod path_pattern;
mod proxy;
mod recorder;
mod recording_api;
mod recording_control;
mod redis;
mod replay;
mod repository;
mod request_headers;
mod tcp_gateway;
mod tls;
mod udp_gateway;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use crate::access_policy::{AccessDecision, OperationClass, decide};
use crate::active_case::{
    ActiveCaseActivationError, ActiveCaseGuard, ActiveCaseRegistry, ActiveCaseRejection,
    DependencyDrainResult, DependencyTargets,
};
use crate::dns_mock::DomainMatcher;
use crate::http::rewrite::KubectlProxyManager;
use crate::recorder::http::case::CaseInvalidation;
use crate::recording_control::{RecordingControlServer, RecordingLifecycle, RecordingListener};

pub use case_group::{
    CaseGroupEnsureResult, CaseGroupOptions, CaseGroupStatus, PatternOutcome, PatternOutcomeStatus,
    ensure_case_group,
};
pub use comparison_recording::{
    ComparisonRecordingRunOptions, ComparisonVerificationApi, ComparisonVerificationApiCounts,
    ComparisonVerificationCase, ComparisonVerificationClassification, ComparisonVerificationCounts,
    ComparisonVerificationOptions, ComparisonVerificationReport, run as run_comparison_recording,
    run_with_duration as run_comparison_recording_with_duration,
    run_with_options as run_comparison_recording_with_options, verify_comparison_recording,
};
pub use config::{
    AllowedUnusedHttpHostFeedback, AllowedUnusedHttpHostPlan, AllowedUnusedHttpHostReport,
    AppConfig, ArtifactsConfig, BackgroundDependencyFeedback, BackgroundDependencyPlan,
    BackgroundDependencyReport, BackgroundDependencyRuleConfig, CasePathPatternAuthority,
    CasePathPatternFeedback, CasePathPatternPlan, CasePathPatternReport, ComparisonRecordingConfig,
    DEFAULT_FAKE_CIDR, DEFAULT_RECORDING_RULE, DnsBypassStrategyConfig, DnsMockConfig, HttpConfig,
    HttpGatewayCaseLimitsConfig, HttpGatewayConfig, HttpGatewayFallbackMode,
    HttpGatewayFixedResponseConfig, HttpGatewayReadyConfig, HttpGatewayRuleConfig,
    HttpResponseRewriteConfig, HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig,
    MysqlConfig, MysqlRouteConfig, RecorderConfigInitOptions, RecorderConfigInitResult,
    RecordingAccessPolicy, RecordingAccessRuleConfig, RecordingAccessRuleEffect, RecordingConfig,
    TcpApplicationProtocol, TcpGatewayConfig, TcpProtocolDetectionConfig,
    TcpProtocolOverrideConfig, TlsConfig, TrafficJsonlMode, UdpGatewayConfig,
    initialize_recorder_config, plan_allowed_unused_http_hosts, plan_background_dependency,
    plan_case_path_pattern_feedback,
};
pub use dependency::{DependencyExchangeOutcome, DiscoveredTcpTarget};
pub use dns_mock::{FakeDnsEntry, FakeDnsRegistry, FakeDnsUpstreamProtocol};
pub use e2e_run::{
    E2eApiRunResult, E2eFocusedApiStatus, E2eRunContext, E2eRunInitOptions, E2eRunInitResult,
    E2eRunPrepareOptions, E2eRunPrepareResult, E2eRunResult, E2eRunStatus, abort_e2e_run,
    initialize_e2e_run, initialize_standard_e2e_project,
    initialize_standard_e2e_project_with_force, prepare_e2e_run, recover_e2e_run, run_e2e_api,
    run_e2e_round, status_e2e_run,
};
pub use mysql::operation::MysqlWriteOperation;
pub use recorder::{
    AccessPolicyAllowEvent, ArtifactOwner, BodyCapture, CaseBodyCapture, CaseContext,
    HeaderMapSnapshot, HttpExchangeEvent, KafkaConnectionEvent, KafkaDeliveryEvent,
    KafkaFetchEvent, KafkaHeaderCapture, KafkaProduceEvent, MemcachedConnectionEvent,
    MemcachedExchangeEvent, MotanConnectionEvent, MotanExchangeEvent, MysqlColumn,
    MysqlConnectionEvent, MysqlExchangeEvent, MysqlExchangeResponse, MysqlPacketEvent,
    MysqlQueryEvent, MysqlResponseEvent, MysqlResponsePacket, MysqlTlsRejectedEvent, MysqlValue,
    ProxyErrorEvent, ReadonlyRejectionEvent, Recorder, RecorderEvent, RedisConnectionEvent,
    RedisExchangeEvent, TcpGatewayConnectionEvent, UdpDatagramEvent, capture_body,
    capture_body_with_original_len, capture_case_body, redact_headers,
};
pub use recording_api::RecordingApi;
pub use recording_control::{
    RecordingReadiness, RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready,
};
pub use replay::{
    ComparisonResponseRuleFeedback, DynamicResponseRuleFeedback, DynamicResponseRulePlan,
    DynamicResponseRuleReport, MysqlReplayConfig, MysqlReplayControlConfig, ReplayAggregateOptions,
    ReplayAggregateReport, ReplayAllowedUnusedHttpConfig, ReplayConfig, ReplayControlConfig,
    ReplayPolicyInitOptions, ReplayPolicyInitResult, ReplayPolicyValidationReport,
    ResponseRuleFeedback, ResponseRuleKind, ResponseRulePlan, ResponseRuleReport,
    aggregate_replay_reports, aggregate_replay_reports_with_options, initialize_replay_policy,
    plan_comparison_response_rule, plan_dynamic_response_rule, plan_response_rule,
    run_mysql_replay, run_mysql_replay_control, run_replay, run_replay_control,
    validate_replay_policy,
};
pub use tls::MitmCa;

type ProxyClient = Client<HttpsConnector<HttpConnector>, http_body_util::Full<bytes::Bytes>>;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: AppConfig,
    recording_apis: Vec<RecordingApi>,
    recorder: Recorder,
    dns_registry: FakeDnsRegistry,
    dns_bypass_matcher: DomainMatcher,
    ca: MitmCa,
    client: ProxyClient,
    upstream_tls_config: Arc<ClientConfig>,
    active_cases: ActiveCaseRegistry,
    kubectl_proxy_manager: KubectlProxyManager,
    recording_lifecycle: RecordingLifecycle,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        Self::new_with_run_id(config, None).await
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
        config
            .validate()
            .context("invalid recorder configuration")?;
        recording_api::validate_selection(&recording_apis, &config.http_gateway.rules)
            .context("invalid recording API selection")?;
        let dns_bypass_matcher = DomainMatcher::from_config(&config.dns_mock)
            .context("failed to initialize DNS bypass matcher")?;
        let recording_output_dir = config.recording_output_dir();
        let recorder = Recorder::new_with_recording_config_at_and_run_id(
            &config.recording,
            recording_output_dir,
            run_id,
            recording_apis.iter().map(ToString::to_string).collect(),
            artifact_owner,
        )
        .await
        .context("failed to initialize JSONL recorder")?;
        let dns_registry = FakeDnsRegistry::load_or_new(
            &config.dns_mock.fake_cidr,
            Some(&config.dns_mock.registry_path),
            &config.dns_mock.bypass_domains,
        )
        .context("failed to initialize fake DNS registry")?;
        let ca = MitmCa::load_or_generate(&config.tls.ca_cert_path, &config.tls.ca_key_path)
            .context("failed to initialize MITM CA")?;
        let upstream_tls_config = build_upstream_tls_config(&ca)?;
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        let case_matching_ready = !config.http_gateway.ready.enabled;
        let recording_lifecycle = RecordingLifecycle::from_config(&config);
        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                recording_apis,
                recorder,
                dns_registry,
                dns_bypass_matcher,
                ca,
                client,
                upstream_tls_config,
                active_cases: ActiveCaseRegistry::new(case_matching_ready),
                kubectl_proxy_manager: KubectlProxyManager::default(),
                recording_lifecycle,
            }),
        })
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn recorder(&self) -> &Recorder {
        &self.inner.recorder
    }

    pub(crate) fn should_record_api(&self, method: &hyper::Method, uri: &hyper::Uri) -> bool {
        self.inner.recording_apis.is_empty() || self.recording_api_pattern(method, uri).is_some()
    }

    pub(crate) fn recording_api_pattern(
        &self,
        method: &hyper::Method,
        uri: &hyper::Uri,
    ) -> Option<&str> {
        self.inner
            .recording_apis
            .iter()
            .find(|api| api.matches(method, uri))
            .map(RecordingApi::path_pattern)
    }

    pub(crate) fn access_decision(&self, operation: OperationClass) -> AccessDecision {
        decide(self.config().recording.access_policy, operation)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_access_policy_allow(
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
    pub(crate) async fn record_readonly_rejection(
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

    pub(crate) fn dns_bypass_matcher(&self) -> &DomainMatcher {
        &self.inner.dns_bypass_matcher
    }

    pub(crate) fn kubectl_proxy_manager(&self) -> &KubectlProxyManager {
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

    pub(crate) fn try_reserve_active_case(
        &self,
        case: CaseContext,
    ) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        self.inner.active_cases.try_reserve(case)
    }

    pub(crate) async fn close_bootstrap(&self, reason: &'static str) -> Result<bool> {
        let closed = self.inner.active_cases.close_bootstrap();
        if !closed {
            return Ok(false);
        }
        info!(reason, "bootstrap dependency window closed");
        self.seal_bootstrap_dependencies(reason).await?;
        if !self.inner.active_cases.enable_case_matching() {
            return Ok(false);
        }
        self.inner.recording_lifecycle.mark_source_ready();
        Ok(true)
    }

    pub(crate) async fn seal_bootstrap_dependencies(&self, reason: &'static str) -> Result<()> {
        if self.inner.active_cases.is_bootstrap_sealed() {
            return Ok(());
        }
        self.inner
            .active_cases
            .wait_for_bootstrap_dependencies()
            .await;
        if let Err(error) = self.recorder().seal_bootstrap_dependencies().await {
            self.inner.recording_lifecycle.mark_failed(&error);
            return Err(error).context("failed to seal bootstrap dependencies");
        }
        self.inner.active_cases.mark_bootstrap_sealed();
        info!(reason, "bootstrap dependencies sealed");
        Ok(())
    }

    pub(crate) fn activate_case_dependencies(
        &self,
        guard: &ActiveCaseGuard,
    ) -> Result<(), ActiveCaseActivationError> {
        guard.activate_dependencies()
    }

    pub(crate) fn is_bootstrap_open(&self) -> bool {
        self.inner.active_cases.is_bootstrap_open()
    }

    pub(crate) fn begin_case_quiescing(&self) -> bool {
        self.inner.active_cases.begin_quiescing()
    }

    pub(crate) fn recording_lifecycle_phase(&self) -> &'static str {
        if self.inner.active_cases.is_quiescing() {
            "quiescing"
        } else {
            "running"
        }
    }

    pub(crate) fn mark_recording_listener_ready(&self, listener: RecordingListener) {
        self.inner.recording_lifecycle.mark_listener_ready(listener);
    }

    pub(crate) fn mark_recording_source_settling(&self) {
        self.inner.recording_lifecycle.mark_source_settling();
    }

    pub(crate) async fn wait_for_active_case_shutdown_drain(&self) -> bool {
        self.inner
            .active_cases
            .wait_for_no_active_case(Duration::from_millis(
                self.config().recording.shutdown_case_drain_timeout_ms,
            ))
            .await
    }

    pub(crate) fn active_case_invalidation(&self, case_id: Uuid) -> Option<CaseInvalidation> {
        self.inner.active_cases.invalidation_for(case_id)
    }

    pub(crate) fn invalidate_active_case(
        &self,
        case_id: Uuid,
        invalidation: CaseInvalidation,
    ) -> Option<CaseContext> {
        self.inner
            .active_cases
            .invalidate_case(case_id, invalidation)
    }

    pub(crate) async fn drain_active_case_dependencies(
        &self,
        case_id: Uuid,
    ) -> Option<CaseInvalidation> {
        let post_response_window = Duration::from_millis(
            self.config()
                .recording
                .case_dependency_post_response_window_ms,
        );
        let timeout =
            Duration::from_millis(self.config().recording.case_dependency_drain_timeout_ms);
        let result = self
            .inner
            .active_cases
            .drain_case_dependencies(case_id, post_response_window, timeout)
            .await;
        match result {
            DependencyDrainResult::Drained => None,
            DependencyDrainResult::TimedOut => {
                warn!(
                    case_id = %case_id,
                    post_response_window_ms = post_response_window.as_millis(),
                    timeout_ms = timeout.as_millis(),
                    "recording case in-flight dependency drain timed out"
                );
                Some(CaseInvalidation::new(
                    "dependency_drain_timeout",
                    format!(
                        "case dependencies accepted during the {} ms post-response window did not complete within {} ms after dependency admission closed",
                        post_response_window.as_millis(),
                        timeout.as_millis()
                    ),
                ))
            }
        }
    }

    pub(crate) fn capture_dependency_targets(&self) -> DependencyTargets {
        self.inner.active_cases.current_targets_for_event()
    }

    pub(crate) fn record_event(&self, event: RecorderEvent) {
        let targets = self.capture_dependency_targets();
        self.record_event_for_targets(event, targets);
    }

    pub(crate) fn record_event_for_targets(
        &self,
        event: RecorderEvent,
        targets: DependencyTargets,
    ) {
        let background_rule_name = self
            .config()
            .recording
            .background_dependencies
            .iter()
            .find(|rule| rule.matches(&event))
            .map(|rule| rule.name().to_string());
        let event_type = event.kind();
        if let Err(err) = self
            .recorder()
            .try_record_event(event, targets, background_rule_name)
        {
            warn!(
                error = %err,
                event_type,
                "failed to enqueue recorder event"
            );
            if let Some(case) =
                self.inner
                    .active_cases
                    .invalidate_current_case(CaseInvalidation::new(
                        "recording_writer_failure",
                        format!("failed to enqueue {event_type} recorder event: {err}"),
                    ))
            {
                warn!(
                    case_id = %case.id,
                    rule = %case.rule_name,
                    "active recording case invalidated by recorder writer failure"
                );
            }
        }
    }

    pub async fn run(self) -> Result<()> {
        self.run_with_control_socket(None).await
    }

    pub async fn run_with_control_socket(self, control_socket: Option<PathBuf>) -> Result<()> {
        let control_server = match control_socket {
            Some(path) => Some(
                RecordingControlServer::start(self.inner.recording_lifecycle.clone(), path).await?,
            ),
            None => None,
        };
        let mut tasks = JoinSet::new();

        if self.config().http.enabled {
            let http_state = self.clone();
            tasks.spawn(async move { proxy::http::run(http_state).await });
        }

        if self.config().dns_mock.enabled {
            let dns_state = self.clone();
            tasks.spawn(async move { dns_mock::run(dns_state).await });
        }

        if self.config().tcp_gateway.enabled {
            let tcp_gateway_state = self.clone();
            tasks.spawn(async move { tcp_gateway::run(tcp_gateway_state).await });
        }

        if self.config().udp_gateway.enabled {
            let udp_gateway_state = self.clone();
            tasks.spawn(async move { udp_gateway::run(udp_gateway_state).await });
        }

        if self.config().http_gateway.enabled {
            let gateway_state = self.clone();
            tasks.spawn(async move { gateway::http::run(gateway_state).await });
        }

        if self.config().mysql.enabled {
            let mysql_state = self.clone();
            tasks.spawn(async move { recorder::mysql::run(mysql_state).await });
        }

        info!(
            access_policy = self.config().recording.access_policy.as_str(),
            access_rules = self.config().recording.access_rules.len(),
            http_enabled = self.config().http.enabled,
            http_listen = %self.config().http.listen,
            dns_mock_enabled = self.config().dns_mock.enabled,
            tcp_gateway_enabled = self.config().tcp_gateway.enabled,
            udp_gateway_enabled = self.config().udp_gateway.enabled,
            http_gateway_enabled = self.config().http_gateway.enabled,
            mysql_enabled = self.config().mysql.enabled,
            "traffic recorder proxy started"
        );

        let mut registry_flush_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + dns_mock::REGISTRY_FLUSH_INTERVAL,
            dns_mock::REGISTRY_FLUSH_INTERVAL,
        );
        registry_flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);
        let run_result = loop {
            tokio::select! {
                result = &mut shutdown => {
                    if let Err(error) = result {
                        break Err(error);
                    }
                    self.inner.recording_lifecycle.mark_stopping();
                    let newly_quiescing = self.begin_case_quiescing();
                    let timeout_ms = self.config().recording.shutdown_case_drain_timeout_ms;
                    info!(
                        newly_quiescing,
                        timeout_ms,
                        "shutdown signal received; draining active recording case"
                    );
                    if self.wait_for_active_case_shutdown_drain().await {
                        info!("active recording case shutdown drain completed");
                    } else {
                        warn!(
                            timeout_ms,
                            "active recording case shutdown drain timed out"
                        );
                    }
                    break Ok(());
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let Some(joined) = joined else {
                        continue;
                    };
                    break match joined {
                        Ok(result) => result,
                        Err(error) => Err(error).context("proxy task panicked"),
                    };
                }
                _ = registry_flush_interval.tick() => {
                    match self.dns_registry().flush_if_dirty().await {
                        Ok(true) => info!("flushed fake DNS registry"),
                        Ok(false) => {}
                        Err(error) => {
                            warn!(
                                error = %error,
                                "failed to flush fake DNS registry; pending updates will be retried"
                            );
                        }
                    }
                }
            }
        };
        if let Err(error) = &run_result {
            self.inner.recording_lifecycle.mark_failed(error);
        }
        let runtime_succeeded = run_result.is_ok();

        tasks.abort_all();
        while let Some(joined) = tasks.join_next().await {
            if let Err(error) = joined
                && !error.is_cancelled()
            {
                warn!(error = %error, "proxy task failed while shutting down");
            }
        }
        self.kubectl_proxy_manager().shutdown().await;
        let finish_run_result = self
            .recorder()
            .finish_run_after_runtime(runtime_succeeded)
            .await
            .context("failed to finalize recording run");
        let registry_flush_result = self
            .dns_registry()
            .flush_if_dirty()
            .await
            .context("failed to flush fake DNS registry during shutdown");

        let result = async {
            let has_failed_cases = finish_run_result?;
            if has_failed_cases {
                warn!(
                    "recording run finalized with failed cases; published cases remain available"
                );
            }
            run_result?;
            registry_flush_result?;
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            self.inner.recording_lifecycle.mark_failed(error);
        }
        let control_result = match control_server {
            Some(server) => server.shutdown().await,
            None => Ok(()),
        };
        result.and(control_result)
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
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
mod tests {
    use chrono::Utc;

    use super::*;

    fn http_dependency(authority: &str, uri: &str) -> RecorderEvent {
        let response = vec![b'x'; 314_066];
        RecorderEvent::HttpExchange(HttpExchangeEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            client_addr: None,
            scheme: "fake_ip_http".to_string(),
            method: "GET".to_string(),
            uri: uri.to_string(),
            authority: Some(authority.to_string()),
            request_headers: Default::default(),
            request_body: capture_body(&[], 1),
            response_status: Some(200),
            response_headers: Some(Default::default()),
            response_body: Some(capture_body(&response, response.len())),
            discovered_tcp_targets: Vec::new(),
            duration_ms: 10,
            error: None,
        })
    }

    #[tokio::test]
    async fn background_http_stays_in_traffic_but_not_case_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.recording.traffic_jsonl = TrafficJsonlMode::Full;
        config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
            name: "config-refresh".to_string(),
            authorities: vec!["config.api.demo.test".to_string()],
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/1/config/service".to_string()],
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }];
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        config.dns_mock.registry_path = temp.path().join("fake-dns.json");
        config.http_gateway.ready.enabled = false;
        let state = AppState::new(config).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };
        let guard = state.try_reserve_active_case(case.clone()).unwrap();
        state.activate_case_dependencies(&guard).unwrap();

        let background = http_dependency(
            "config.api.demo.test",
            "/1/config/service?action=lookup&group=reload.properties",
        );
        state.record_event(background);
        drop(guard);
        state.recorder().publish_case(&case).await.unwrap();
        state.recorder().finish_run().await.unwrap();

        let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
        assert!(traffic.contains("config.api.demo.test"));
        assert!(traffic.contains("\"stored_len\":314066"));
        let dependencies =
            tokio::fs::read_to_string(state.recorder().case_dir(&case).join("dependencies.jsonl"))
                .await
                .unwrap();
        assert!(dependencies.is_empty());
    }
}
