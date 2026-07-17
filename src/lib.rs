mod access_policy;
mod active_case;
mod case_group;
mod config;
mod dns_mock;
mod e2e_run;
mod gateway;
mod http;
mod kafka;
mod memcached;
mod mysql;
mod path_pattern;
mod process_lookup;
mod proxy;
mod recorder;
mod redis;
mod replay;
mod tcp_gateway;
mod tls;
mod udp_gateway;

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
    ActiveCaseGuard, ActiveCaseRegistry, ActiveCaseRejection, DependencyDrainResult,
    DependencyTargets,
};
use crate::http::rewrite::KubectlProxyManager;
use crate::recorder::http::case::CaseInvalidation;

pub use case_group::{
    CaseGroupEnsureResult, CaseGroupOptions, CaseGroupStatus, PatternOutcome, PatternOutcomeStatus,
    ensure_case_group,
};
pub use config::{
    AllowedUnusedHttpHostFeedback, AllowedUnusedHttpHostPlan, AllowedUnusedHttpHostReport,
    AppConfig, CasePathPatternAuthority, CasePathPatternFeedback, CasePathPatternPlan,
    CasePathPatternReport, DnsMockConfig, HttpConfig, HttpGatewayConfig, HttpGatewayReadyConfig,
    HttpGatewayRuleConfig, HttpResponseRewriteConfig, HttpResponseRewritePluginConfig,
    HttpResponseRewriteRuleConfig, MysqlConfig, MysqlRouteConfig, RecordingAccessPolicy,
    RecordingAccessRuleConfig, RecordingAccessRuleEffect, RecordingConfig, TcpApplicationProtocol,
    TcpGatewayConfig, TcpProtocolDetectionConfig, TcpProtocolOverrideConfig, TlsConfig,
    UdpGatewayConfig, VerifiedApiExclude, VerifiedApiExcludeEnsureReport,
    VerifiedApiExcludeEnsureStatus, VerifiedApiExcludeFeedback, VerifiedApiExcludePlan,
    VerifiedApiExcludeReport, VerifiedApiExcludesConfig, ensure_verified_api_exclude,
    plan_allowed_unused_http_hosts, plan_case_path_pattern_feedback, plan_verified_api_exclude,
};
pub use dns_mock::{FakeDnsEntry, FakeDnsRegistry, FakeDnsUpstreamProtocol};
pub use e2e_run::{
    E2eApiRunResult, E2eFocusedApiStatus, E2eRunContext, E2eRunInitOptions, E2eRunInitResult,
    E2eRunPrepareOptions, E2eRunPrepareResult, E2eRunResult, E2eRunStatus, abort_e2e_run,
    initialize_e2e_run, prepare_e2e_run, recover_e2e_run, run_e2e_api, run_e2e_round,
    status_e2e_run,
};
pub use mysql::operation::MysqlWriteOperation;
pub use recorder::{
    AccessPolicyAllowEvent, BodyCapture, CaseBodyCapture, CaseContext, HeaderMapSnapshot,
    HttpExchangeEvent, KafkaConnectionEvent, KafkaDeliveryEvent, KafkaHeaderCapture,
    KafkaProduceEvent, MemcachedConnectionEvent, MemcachedExchangeEvent, MysqlColumn,
    MysqlConnectionEvent, MysqlExchangeEvent, MysqlExchangeResponse, MysqlPacketEvent,
    MysqlQueryEvent, MysqlResponseEvent, MysqlResponsePacket, MysqlTlsRejectedEvent, MysqlValue,
    ProxyErrorEvent, ReadonlyRejectionEvent, Recorder, RecorderEvent, RedisConnectionEvent,
    RedisExchangeEvent, TcpGatewayConnectionEvent, UdpDatagramEvent, capture_body,
    capture_body_with_original_len, capture_case_body, redact_headers,
};
pub use replay::{
    MysqlReplayConfig, MysqlReplayControlConfig, ReplayAggregateOptions, ReplayAggregateReport,
    ReplayAllowedUnusedHttpConfig, ReplayConfig, ReplayControlConfig, ReplayPolicyValidationReport,
    aggregate_replay_reports, aggregate_replay_reports_with_options, run_mysql_replay,
    run_mysql_replay_control, run_replay, run_replay_control, validate_replay_policy,
};
pub use tls::MitmCa;

type ProxyClient = Client<HttpsConnector<HttpConnector>, http_body_util::Full<bytes::Bytes>>;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: AppConfig,
    recorder: Recorder,
    dns_registry: FakeDnsRegistry,
    ca: MitmCa,
    client: ProxyClient,
    upstream_tls_config: Arc<ClientConfig>,
    active_cases: ActiveCaseRegistry,
    kubectl_proxy_manager: KubectlProxyManager,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        config
            .validate()
            .context("invalid recorder configuration")?;
        let recorder = Recorder::new_with_access_policy(
            &config.recording.output_dir,
            config.recording.access_policy,
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
        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                recorder,
                dns_registry,
                ca,
                client,
                upstream_tls_config,
                active_cases: ActiveCaseRegistry::new(case_matching_ready),
                kubectl_proxy_manager: KubectlProxyManager::default(),
            }),
        })
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn recorder(&self) -> &Recorder {
        &self.inner.recorder
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
        client_process: Option<crate::recorder::ProcessInfo>,
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
            client_process,
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
        client_process: Option<crate::recorder::ProcessInfo>,
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
            client_process,
            target,
            reason,
        });
        if let Err(error) = self.recorder().record(event.clone()).await {
            warn!(error = %error, "failed to record access policy rejection");
        }
        self.record_active_case_dependency_if_relevant(&event).await;
    }

    pub fn dns_registry(&self) -> &FakeDnsRegistry {
        &self.inner.dns_registry
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

    pub(crate) fn try_register_active_case(
        &self,
        case: CaseContext,
        upstream_pid: Option<u32>,
    ) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        let bootstrap_was_open = self.inner.active_cases.is_bootstrap_open();
        let guard = self.inner.active_cases.try_register(case, upstream_pid)?;
        if bootstrap_was_open {
            self.schedule_bootstrap_dependency_summary("first active case");
        }
        Ok(guard)
    }

    pub(crate) fn close_bootstrap(&self, reason: &'static str) -> bool {
        let closed = self.inner.active_cases.close_bootstrap();
        if closed {
            info!(reason, "bootstrap dependency window closed");
            self.schedule_bootstrap_dependency_summary(reason);
        }
        closed
    }

    fn schedule_bootstrap_dependency_summary(&self, reason: &'static str) {
        let recorder = self.recorder().clone();
        let active_cases = self.inner.active_cases.clone();
        tokio::spawn(async move {
            active_cases.wait_for_bootstrap_dependencies().await;
            if let Err(err) = recorder.finalize_bootstrap_dependency_summary().await {
                warn!(error = %err, reason, "failed to finalize bootstrap dependency summary");
            }
        });
    }

    pub(crate) fn is_bootstrap_open(&self) -> bool {
        self.inner.active_cases.is_bootstrap_open()
    }

    pub(crate) fn active_case_invalidation(&self, case_id: Uuid) -> Option<CaseInvalidation> {
        self.inner.active_cases.invalidation_for(case_id)
    }

    pub(crate) async fn drain_active_case_dependencies(
        &self,
        case_id: Uuid,
    ) -> Option<CaseInvalidation> {
        let quiet_period =
            Duration::from_millis(self.config().recording.case_dependency_quiet_period_ms);
        let timeout =
            Duration::from_millis(self.config().recording.case_dependency_drain_timeout_ms);
        let result = self
            .inner
            .active_cases
            .drain_case_dependencies(case_id, quiet_period, timeout)
            .await;
        match result {
            DependencyDrainResult::Drained => None,
            DependencyDrainResult::TimedOut => {
                warn!(
                    case_id = %case_id,
                    quiet_period_ms = quiet_period.as_millis(),
                    timeout_ms = timeout.as_millis(),
                    "recording case dependency drain timed out"
                );
                Some(CaseInvalidation::new(
                    "dependency_drain_timeout",
                    format!(
                        "case dependencies did not become idle for {} ms within {} ms",
                        quiet_period.as_millis(),
                        timeout.as_millis()
                    ),
                ))
            }
        }
    }

    pub(crate) fn capture_dependency_targets(&self, event_pid: Option<u32>) -> DependencyTargets {
        self.inner.active_cases.current_targets_for_event(event_pid)
    }

    pub(crate) async fn record_dependency_if_relevant(&self, event: &RecorderEvent) {
        let event_pid = event.client_pid();
        let targets = self.capture_dependency_targets(event_pid);
        self.record_dependency_for_targets(event, &targets).await;
    }

    pub(crate) async fn record_dependency_for_targets(
        &self,
        event: &RecorderEvent,
        targets: &DependencyTargets,
    ) {
        if targets.bootstrap_open
            && let Err(err) = self
                .recorder()
                .append_bootstrap_dependency(event, "bootstrap_window")
                .await
        {
            warn!(
                error = %err,
                "failed to append bootstrap dependency"
            );
        }
        self.record_case_dependencies(event, targets).await;
    }

    async fn record_active_case_dependency_if_relevant(&self, event: &RecorderEvent) {
        let event_pid = event.client_pid();
        let targets = self.capture_dependency_targets(event_pid);
        self.record_case_dependencies(event, &targets).await;
    }

    async fn record_case_dependencies(&self, event: &RecorderEvent, targets: &DependencyTargets) {
        if targets.ambiguous_active_cases > 0 {
            warn!(
                active_cases = targets.ambiguous_active_cases,
                event_type = event.kind(),
                "skipping case dependency because active case ownership is ambiguous"
            );
        }
        for (case, matched_by) in &targets.cases {
            if let Err(err) = self
                .recorder()
                .append_case_dependency(case, event, matched_by)
                .await
            {
                warn!(
                    error = %err,
                    case_id = %case.id,
                    rule = %case.rule_name,
                    matched_by,
                    "failed to append case dependency"
                );
            }
        }
    }

    pub async fn run(self) -> Result<()> {
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

        let run_result = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                Ok(())
            }
            Some(joined) = tasks.join_next() => {
                joined.context("proxy task panicked")?
            }
        };

        self.kubectl_proxy_manager().shutdown().await;
        let has_failed_cases = self
            .recorder()
            .finish_run()
            .await
            .context("failed to finalize recording run")?;
        run_result?;
        if has_failed_cases {
            anyhow::bail!("recording run finished with failed cases");
        }
        Ok(())
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
