mod access_policy;
mod active_case;
mod artifact_file;
mod breeze;
mod build_info;
mod case_group;
mod case_kind;
mod comparison_recording;
mod config;
mod dependency;
mod dns_mock;
mod e2e_run;
mod engine_binary;
mod gateway;
mod http;
mod internal_runtime;
mod kafka;
mod memcached;
mod motan;
mod mysql;
mod network_probe;
mod path_pattern;
mod platform;
mod proxy;
mod recorded_request;
mod recorder;
mod recording_api;
mod recording_completion;
mod recording_control;
mod recording_runtime;
mod redis;
mod replay;
mod repository;
mod request_headers;
mod rewrite;
mod startup;
mod target_container;
mod tcp_gateway;
mod tls;
mod udp_gateway;
mod verification_progress;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use tracing::{info, warn};
use uuid::Uuid;

use crate::access_policy::{AccessDecision, OperationClass, decide};
use crate::active_case::{
    ActiveCaseActivationError, ActiveCaseGuard, ActiveCaseRegistry, ActiveCaseRejection,
    DependencyDrainResult, DependencyTargets,
};
use crate::dns_mock::DomainMatcher;
use crate::http::rewrite::KubectlProxyManager;
use crate::recorder::CaseInvalidation;
use crate::recorder::background::BackgroundDependencyMatcher;
use crate::recorder::cache_snapshot::{CacheSnapshotReservation, CacheSnapshotStore};
use crate::recorder::readiness::PostReadyWaitOutcome;
use crate::recording_control::{RecordingLifecycle, RecordingListener};

/// Numeric UID used by every containerized process whose dependency traffic is intercepted.
pub const TRAFFIC_PROCESS_UID: u32 = 998;
/// Numeric GID used by every containerized process whose dependency traffic is intercepted.
pub const TRAFFIC_PROCESS_GID: u32 = 998;
/// OCI user specification for containerized processes whose dependency traffic is intercepted.
pub const TRAFFIC_PROCESS_USER: &str = "998:998";

pub use build_info::BINARY_VERSION;

pub use case_group::{
    CaseGroupEnsureResult, CaseGroupOptions, CaseGroupStatus, PatternOutcome, PatternOutcomeStatus,
    ensure_case_group, resolve_recording_api_member,
};
pub use comparison_recording::{
    ComparisonRecordingRunOptions, ComparisonRepresentativeDifference,
    ComparisonRepresentativePolicyMismatch, ComparisonVerificationApi,
    ComparisonVerificationApiCounts, ComparisonVerificationCase,
    ComparisonVerificationClassification, ComparisonVerificationCounts,
    ComparisonVerificationOptions, ComparisonVerificationReport, MatchedSourceObservation,
    run as run_comparison_recording, run_with_duration as run_comparison_recording_with_duration,
    run_with_options as run_comparison_recording_with_options, update_comparison_progress,
    verify_comparison_recording,
};
pub use config::{
    AllowedUnusedHttpHostFeedback, AllowedUnusedHttpHostPlan, AllowedUnusedHttpHostReport,
    AppConfig, ArtifactsConfig, BackgroundDependencyFeedback, BackgroundDependencyPlan,
    BackgroundDependencyReport, BackgroundDependencyRuleConfig, BreezeEndpointCaptureFeedback,
    BreezeMemcachedBackgroundDependencyFeedback, BreezeMemcachedBackgroundDependencyPlan,
    BreezeMemcachedBackgroundDependencyReport, BreezeResourceCaptureFeedback,
    BreezeResourceCapturePlan, BreezeResourceCaptureReport, CasePathPatternAuthority,
    CasePathPatternFeedback, CasePathPatternPlan, CasePathPatternReport, ComparisonRecordingConfig,
    DEFAULT_FAKE_CIDR, DEFAULT_HTTP_GATEWAY_PORT, DEFAULT_RECORDING_RULE, DnsBypassStrategyConfig,
    DnsMockConfig, HttpConfig, HttpGatewayCaseLimitsConfig, HttpGatewayConfig,
    HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig, HttpGatewayReadyConfig,
    HttpGatewayRuleConfig, HttpResponseRewriteConfig, HttpResponseRewritePluginConfig,
    HttpResponseRewriteRuleConfig, InspectedContainer, MotanBackgroundDependencyFeedback,
    MotanBackgroundDependencyPlan, MotanBackgroundDependencyReport, MotanGatewayConfig,
    MotanGatewayRuleConfig, MotanProtocolConfigOptions, MotanProtocolConfigResult, MysqlConfig,
    MysqlRouteConfig, RecorderConfigInitOptions, RecorderConfigInitResult, RecordingAccessPolicy,
    RecordingAccessRuleConfig, RecordingAccessRuleEffect, RecordingConfig,
    RedisBackgroundDependencyFeedback, RedisBackgroundDependencyPlan,
    RedisBackgroundDependencyReport, RedisKeyPatternConfig, RepositoryConfigInitOptions,
    RepositoryConfigInitResult, TcpApplicationProtocol, TcpGatewayConfig,
    TcpProtocolDetectionConfig, TcpProtocolOverrideConfig, TlsConfig, TrafficJsonlMode,
    UdpGatewayConfig, enable_repository_motan_protocol, initialize_recorder_config,
    initialize_repository_config, plan_allowed_unused_http_hosts, plan_background_dependency,
    plan_breeze_endpoint_capture, plan_breeze_memcached_background_dependency,
    plan_breeze_resource_capture, plan_case_path_pattern_feedback,
    plan_motan_background_dependency, plan_redis_background_dependency,
};
pub use dependency::{DependencyExchangeOutcome, DiscoveredTcpTarget};
pub use dns_mock::{FakeDnsEntry, FakeDnsRegistry, FakeDnsUpstreamProtocol};
pub use e2e_run::{
    E2eApiRunResult, E2eCaseResponseDifference, E2eCaseResponseDifferences,
    E2eDependencyCorrelation, E2eDependencyDifference, E2eDependencyEndpoint, E2eDependencyGate,
    E2eDependencyObservation, E2eDependencyRepresentative, E2eDiagnosis, E2eDiagnosisCounts,
    E2eDirtyCluster, E2eDirtyCounts, E2eFailureCluster, E2eFocusedApiStatus, E2eReplayGate,
    E2eRepresentativeDifference, E2eResponseDifferenceDiagnosis, E2eResponseGate,
    E2eResponseRuleEvidence, E2eRunContext, E2eRunInitOptions, E2eRunInitResult,
    E2eRunPrepareOptions, E2eRunPrepareResult, E2eRunResult, E2eRunStatus, E2eSourcePreReadiness,
    E2eSourcePreReadinessEndpoint, E2eSourceValueCount, E2eSourceVariation, E2eValueObservation,
    E2eValuePresence, E2eVerificationGates, abort_e2e_run, initialize_e2e_run,
    initialize_standard_e2e_project, initialize_standard_e2e_project_with_force, prepare_e2e_run,
    query_e2e_case_response_differences, query_e2e_dependency_correlation, query_e2e_dirty_counts,
    query_e2e_source_variation, recover_e2e_run, resolve_e2e_response_rule_evidence,
    resolve_single_e2e_response_rule_evidence, run_e2e_api, run_e2e_round, status_e2e_run,
};
pub use mysql::operation::MysqlWriteOperation;
pub use network_probe::PreflightProbeKind;
pub use platform::{
    ManagedMotanPreflightResult, ManagedMotanRecordingResult, ManagedRecordingInputCompletion,
    ManagedRecordingInputOptions, ManagedRecordingInputResult, ManagedRecordingOperation,
    ManagedRecordingOptions, ManagedRecordingPreflightOptions,
    ManagedRecordingPreflightRecordingResult, ManagedRecordingPreflightResult,
    ManagedRecordingRecoveryResult, ManagedRecordingResult, ManagedReplayNetworkPreflightResult,
    MotanPreflightStatus, ReplayDirectEgressProbeResult, ReplayNegativeProbeResult,
    ReplayPositiveProbeResult, drive_managed_recording_input, recover_managed_recording,
    run_managed_recording, run_managed_recording_preflight,
};
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
    RecordingReadiness, RecordingWaitConfig, notify_recording_input_complete,
    wait_for_recording_listeners, wait_for_recording_ready,
};
pub use replay::{
    ComparisonResponseRuleFeedback, ComparisonSourceMatch, ComparisonVerificationPolicy,
    DynamicResponseMechanism, DynamicResponseRuleFeedback, DynamicResponseRulePlan,
    DynamicResponseRuleReport, MysqlReplayConfig, MysqlReplayControlConfig, ReplayAggregateOptions,
    ReplayAggregateReport, ReplayAllowedUnusedHttpConfig, ReplayConfig, ReplayControlConfig,
    ReplayPolicyInitOptions, ReplayPolicyInitResult, ReplayPolicyValidationReport,
    ResponseDifference, ResponseDifferenceKind, ResponseRuleFeedback, ResponseRuleKind,
    ResponseRulePlan, ResponseRuleReport, aggregate_replay_reports,
    aggregate_replay_reports_with_options, initialize_replay_policy, plan_comparison_response_rule,
    plan_dynamic_response_rule, plan_response_rule, run_mysql_replay, run_mysql_replay_control,
    run_replay, run_replay_control, validate_replay_policy,
};
pub use rewrite::{
    RewriteAction, RewriteActionEnvelope, RewriteApiInventoryDetails, RewriteApiInventoryView,
    RewriteApiProgress, RewriteApiStatus, RewriteApplicableRulePlanner, RewriteCapturePreview,
    RewriteCaseDependenciesOptions, RewriteCaseDependenciesReport,
    RewriteCaseDependencyProtocolDetail, RewriteCaseDependencyTarget,
    RewriteCaseDependencyTargetSummary, RewriteCommandSpec, RewriteContext,
    RewriteDependencyRulePlanOptions, RewriteDependencyRuleReport, RewriteDependencyRuleSelector,
    RewriteEvidenceCommand, RewriteEvidenceReport, RewriteFocusedE2eExecution,
    RewriteFocusedE2eExecutionMode, RewriteInputRequiredReason, RewriteInventoryReport,
    RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewriteMemcachedExchangeDetail,
    RewriteMemcachedOperationDetail, RewriteNextOptions, RewritePhase,
    RewriteRecorderCapturePlanOptions, RewriteRecorderCaptureReport,
    RewriteRecordingExecutionReport, RewriteRecordingInputCandidate,
    RewriteRecordingInputCandidateDisposition, RewriteRecordingInputDiagnosis,
    RewriteRecordingInputMode, RewriteRecordingInputRejections, RewriteRecordingKind,
    RewriteRecordingReason, RewriteRecordingRequestOptions, RewriteRecordingStartReport,
    RewriteRecordingStartState, RewriteRecoveryReport, RewriteRedisExchangeDetail,
    RewriteRedisOperationDetail, RewriteRepairAcceptanceKind, RewriteRevalidationRequestOptions,
    RewriteRevalidationRequestReport, RewriteRouteOptions, RewriteRouteReport,
    RewriteRulePlanOptions, RewriteRuleReport, RewriteSourceProcessBackgroundRuleView,
    RewriteSourceProcessBackgroundView, RewriteSourceProcessObservationView,
    RewriteSourceProcessRedisSnapshotEndpointView, RewriteSourceProcessRedisSnapshotView,
    RewriteSourceProcessTrafficScopeView, RewriteSourceProcessTrafficView, RewriteStatusReport,
    RewriteTargetQualityOptions, RewriteTrafficOperationKind, RewriteTrafficOperationView,
    RewriteWorkerBlockingReason, RewriteWorkerConfirmOptions, RewriteWorkerDispatchState,
    RewriteWorkerDispatchView, RewriteWorkerTransferOptions, RewriteWorkflowView,
    apply_rewrite_dependency_rule, apply_rewrite_recorder_capture, apply_rewrite_rule,
    confirm_rewrite_worker, execute_rewrite_recording_worker, inventory_rewrite, next_rewrite,
    plan_rewrite_dependency_rule, plan_rewrite_recorder_capture, plan_rewrite_rule,
    query_rewrite_case_dependencies, query_rewrite_evidence, recover_rewrite,
    request_rewrite_recording, request_rewrite_revalidation, resume_rewrite_replay_planning,
    route_rewrite, run_rewrite_target_quality, start_rewrite_recording, status_rewrite,
    status_rewrite_for_api, transfer_rewrite_worker, verify_rewrite_repair,
};
pub use startup::{StartupConfig, StartupSnapshotReport};
pub use target_container::{TargetContainerChecks, TargetContainerPreflightResult, TargetImage};
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
    background_dependencies: BackgroundDependencyMatcher,
    cache_snapshots: CacheSnapshotStore,
    preflight_probe: Option<PreflightProbeKind>,
    preflight_probe_recorded: AtomicBool,
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
        Self::new_with_recording_options(config, run_id, recording_apis, artifact_owner, None).await
    }

    pub async fn new_with_recording_options(
        config: AppConfig,
        run_id: Option<String>,
        recording_apis: Vec<RecordingApi>,
        artifact_owner: Option<ArtifactOwner>,
        preflight_probe: Option<PreflightProbeKind>,
    ) -> Result<Self> {
        config
            .validate()
            .context("invalid recorder configuration")?;
        recording_api::validate_selection(&recording_apis, &config.http_gateway.rules)
            .context("invalid recording API selection")?;
        let background_rules = config.recording.background_dependencies.clone();
        let background_dependencies = tokio::task::spawn_blocking(move || {
            BackgroundDependencyMatcher::from_rules(&background_rules)
        })
        .await
        .context("background dependency initializer task failed")?
        .context("failed to initialize background dependency rules")?;
        let cache_snapshots = CacheSnapshotStore::new(&config.recording);
        let dns_bypass_matcher = DomainMatcher::from_config(&config.dns_mock)
            .context("failed to initialize DNS bypass matcher")?;
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
                background_dependencies,
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

    pub(crate) fn has_background_initial_loads(&self) -> bool {
        self.inner.background_dependencies.has_initial_loads()
    }

    pub(crate) async fn wait_for_background_initial_loads(&self) -> Result<()> {
        self.inner
            .background_dependencies
            .ensure_resources_resolved()?;
        self.inner
            .background_dependencies
            .wait_for_initial_loads()
            .await;
        Ok(())
    }

    pub(crate) fn record_redis_cache_request(&self) {
        self.inner
            .background_dependencies
            .record_redis_cache_request();
    }

    pub(crate) async fn wait_for_post_ready_admission(
        &self,
        ready_at: tokio::time::Instant,
    ) -> Result<PostReadyWaitOutcome> {
        let maximum_wait = self.config().recording.post_ready_max_wait();
        let maximum_deadline = ready_at + maximum_wait;
        if tokio::time::timeout_at(maximum_deadline, self.wait_for_background_initial_loads())
            .await
            .is_err()
        {
            return Ok(PostReadyWaitOutcome::MaximumWaitElapsed);
        }
        Ok(self
            .inner
            .background_dependencies
            .wait_for_redis_cache_quiet_period(
                ready_at,
                self.config().recording.post_ready_quiet_period(),
                maximum_wait,
            )
            .await)
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

    pub(crate) fn matching_redis_snapshot_rule(
        &self,
        target_port: u16,
        command: &str,
        args: &[Vec<u8>],
    ) -> Option<&str> {
        self.inner
            .background_dependencies
            .matching_redis_snapshot_rule(target_port, command, args)
    }

    pub(crate) fn has_redis_snapshot_port(&self, port: u16) -> bool {
        self.inner
            .background_dependencies
            .has_redis_snapshot_port(port)
    }

    pub(crate) async fn reserve_cache_snapshot(
        &self,
        key: Vec<u8>,
    ) -> Result<CacheSnapshotReservation> {
        self.inner.cache_snapshots.reserve(key).await
    }

    pub(crate) async fn complete_cache_snapshot(
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

    pub(crate) async fn abort_cache_snapshot(&self, key: &[u8], reason: &str) {
        self.inner.cache_snapshots.abort(key, reason).await;
    }

    pub(crate) fn record_event_for_targets(
        &self,
        event: RecorderEvent,
        targets: DependencyTargets,
    ) {
        let background_match = self.inner.background_dependencies.matching_rule(&event);
        let (probe_attribution, suppress_default_global) = self.preflight_probe_attribution(&event);
        let background_attributed =
            probe_attribution.is_none() && !suppress_default_global && background_match.is_some();
        let global_attribution = probe_attribution.or_else(|| {
            (!suppress_default_global)
                .then(|| {
                    background_match.as_ref().map(|matched| {
                        crate::recorder::GlobalDependencyAttribution {
                            reason: "background_rule",
                            phase: if targets.bootstrap_open {
                                "bootstrap"
                            } else {
                                "runtime"
                            },
                            matched_by: matched.rule_name().to_string(),
                        }
                    })
                })
                .flatten()
        });
        let event_type = event.kind();
        if let Err(err) = self.recorder().try_record_event(
            event,
            targets,
            global_attribution,
            suppress_default_global,
        ) {
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
        } else if background_attributed && let Some(matched) = &background_match {
            self.inner
                .background_dependencies
                .record_completed_match(matched);
        }
    }

    fn preflight_probe_attribution(
        &self,
        event: &RecorderEvent,
    ) -> (Option<crate::recorder::GlobalDependencyAttribution>, bool) {
        let Some(kind) = self.inner.preflight_probe else {
            return (None, false);
        };
        let Some(successful) = kind.classify_recording_event(event) else {
            return (None, false);
        };
        if !successful
            || self
                .inner
                .preflight_probe_recorded
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return (None, true);
        }
        (
            Some(crate::recorder::GlobalDependencyAttribution {
                reason: "preflight_probe",
                phase: "runtime",
                matched_by: kind.matched_by().to_string(),
            }),
            true,
        )
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
