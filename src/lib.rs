mod replay_exports;
pub use replay_exports::*;
mod access_policy;
mod active_case;
mod api_trigger;
mod artifact_file;
mod artifact_owner;
mod breeze;
mod build_info;
mod case_group;
pub mod command_output;
mod config;
mod dependency;
mod dependency_index;
mod dependency_provider;
pub use api_trigger::mysql_plan::{ApiTriggeredMysqlSelector, plan_api_triggered_mysql};
pub use api_trigger::plan::{
    ApiTriggeredDependencyPlan, ApiTriggeredDependencyReport, ApiTriggeredMysqlPlan,
    ApiTriggeredMysqlReport, ApiTriggeredRedisPlan, ApiTriggeredRedisReport,
    ApiTriggeredRedisSelector, plan_api_triggered_redis,
};
pub use dependency_index::DependencyIndexReport;

pub fn prepare_dependency_index(source: &std::path::Path) -> anyhow::Result<DependencyIndexReport> {
    dependency_index::store::prepare(source, replay::validate_index_record)
        .map(|(_, report)| report)
}
pub use replay::{GlobalDependencyPage, read_global_dependency_page};
mod dns_mock;
mod e2e_run;
mod engine_binary;
mod gateway;
mod http;
mod interaction;
mod internal_runtime;
mod json_value;
mod kafka;
pub mod local_interception;
mod memcached;
mod motan;
mod mysql;
mod network_probe;
mod path_pattern;
mod platform;
pub mod policy;
pub(crate) mod policy_evidence;
mod primary_protocol;
mod protocol_contract;
mod proxy;
pub mod record_service;
mod recorded_request;
mod recorder;
mod recording_api;
mod recording_case;
mod recording_completion;
mod recording_control;
mod recording_network;
mod recording_runtime;
mod recording_stream_tail;
mod recording_upstream;
mod redis;
mod replay;
mod repository;
mod request_headers;
pub mod request_rules;
mod rewrite;
mod runtime_output;
mod source_snapshot;
mod startup;
mod target_container;
mod tcp_gateway;
mod tcp_listener;
mod tls;
mod udp_gateway;
pub(crate) mod value_codec;
pub(crate) mod value_contract;
mod value_limits;
mod verification_progress;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use hyper_util::client::legacy::Client;
use rustls::{ClientConfig, RootCertStore};
use tracing::{info, warn};
use uuid::Uuid;

use crate::access_policy::{AccessDecision, OperationClass, decide};
use crate::active_case::{
    ActiveCaseActivationError, ActiveCaseGuard, ActiveCaseRegistry, ActiveCaseRejection,
    DependencyTargets,
};
use crate::dns_mock::DomainMatcher;
use crate::http::rewrite::KubectlProxyManager;
use crate::recorder::CaseInvalidation;
use crate::recorder::background::BackgroundDependencyMatcher;
use crate::recorder::cache_snapshot::{CacheSnapshotReservation, CacheSnapshotStore};
use crate::recorder::connections::DependencyConnections;
#[cfg(test)]
use crate::recorder::readiness::PostReadyWaitOutcome;
use crate::recording_control::RecordingLifecycle;

/// Numeric UID used by every containerized process whose dependency traffic is intercepted.
pub const TRAFFIC_PROCESS_UID: u32 = 998;
/// Numeric GID used by every containerized process whose dependency traffic is intercepted.
pub const TRAFFIC_PROCESS_GID: u32 = 998;
/// OCI user specification for containerized processes whose dependency traffic is intercepted.
pub const TRAFFIC_PROCESS_USER: &str = "998:998";

pub use artifact_owner::ArtifactOwner;
pub use build_info::BINARY_VERSION;

pub use case_group::{
    CaseGroupEnsureResult, CaseGroupOptions, CaseGroupStatus, PatternOutcome, PatternOutcomeStatus,
    ensure_case_group, resolve_recording_api_case_ids, resolve_recording_api_member,
};
pub use config::{
    AllowedUnusedHttpHostFeedback, AllowedUnusedHttpHostPlan, AllowedUnusedHttpHostReport,
    ApiCaptureOperation, ApiCaptureProtocol, ApiTriggerCapture, ApiTriggerKind,
    ApiTriggerRedisScript, ApiTriggerSource, AppConfig, ArtifactsConfig,
    BackgroundDependencyFeedback, BackgroundDependencyPlan, BackgroundDependencyReport,
    BackgroundDependencyRuleConfig, BreezeEndpointCaptureFeedback,
    BreezeMemcachedBackgroundDependencyFeedback, BreezeMemcachedBackgroundDependencyPlan,
    BreezeMemcachedBackgroundDependencyReport, BreezeResourceCaptureFeedback,
    BreezeResourceCapturePlan, BreezeResourceCaptureReport, CaptureConfig, CaptureProtocol,
    CasePathPatternAuthority, CasePathPatternFeedback, CasePathPatternPlan, CasePathPatternReport,
    DEFAULT_DNS_MOCK_LISTEN, DEFAULT_DNS_MOCK_PORT, DEFAULT_FAKE_CIDR, DEFAULT_HTTP_BACKEND_PORT,
    DEFAULT_HTTP_GATEWAY_PORT, DEFAULT_TCP_GATEWAY_LISTEN, DEFAULT_TCP_GATEWAY_PORT,
    DEFAULT_UDP_GATEWAY_LISTEN, DEFAULT_UDP_GATEWAY_PORT, DnsBypassStrategyConfig, DnsMockConfig,
    HttpConfig, HttpGatewayCaseLimitsConfig, HttpGatewayConfig, HttpGatewayFallbackMode,
    HttpGatewayFixedResponseConfig, HttpGatewayReadyConfig, HttpGatewayRuleConfig,
    HttpResponseRewriteConfig, HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig,
    MotanBackgroundDependencyFeedback, MotanBackgroundDependencyPlan,
    MotanBackgroundDependencyReport, MotanGatewayConfig, MotanGatewayRuleConfig,
    MotanProtocolConfigOptions, MotanProtocolConfigResult, MysqlBackgroundDependencyFeedback,
    MysqlBackgroundDependencyPlan, MysqlBackgroundDependencyReport, MysqlBackgroundSelector,
    MysqlBackgroundTableSeries, MysqlConfig, MysqlRouteConfig, MysqlTableSeries,
    RecordingAccessPolicy, RecordingAccessRuleConfig, RecordingAccessRuleEffect, RecordingConfig,
    RedisBackgroundDependencyFeedback, RedisBackgroundDependencyPlan,
    RedisBackgroundDependencyReport, RedisKeyPatternConfig, RepositoryConfigInitOptions,
    RepositoryConfigInitResult, TcpApplicationProtocol, TcpGatewayConfig,
    TcpProtocolDetectionConfig, TcpProtocolOverrideConfig, TlsConfig, TrafficJsonlMode,
    UdpGatewayConfig, enable_repository_motan_protocol, initialize_repository_config,
    plan_allowed_unused_http_hosts, plan_background_dependency, plan_breeze_endpoint_capture,
    plan_breeze_memcached_background_dependency, plan_breeze_resource_capture,
    plan_case_path_pattern_feedback, plan_motan_background_dependency,
    plan_mysql_background_dependency, plan_redis_background_dependency,
    resolve_unified_policy_path,
};
pub use config::{KubernetesConfig, UpstreamRouteConfig, UpstreamTransportConfig};
pub use dependency::attribution::{AttributionDecision, AttributionProof, DependencyOwner};
pub use dependency::{
    DependencyExchangeOutcome, DependencyTermination, DiscoveredTcpTarget, TerminationKind,
    TerminationScope, TerminationSide,
};
pub use dns_mock::{FakeDnsEntry, FakeDnsRegistry, FakeDnsUpstreamProtocol};
pub use e2e_run::{
    DEFAULT_MAX_FAILED_CASES_PER_API, E2eApiRunResult, E2eCaseResponseDifference,
    E2eCaseResponseDifferences, E2eDependencyCorrelation, E2eDependencyDifference,
    E2eDependencyEndpoint, E2eDependencyGate, E2eDependencyObservation,
    E2eDependencyRepresentative, E2eDependencyTargetMatch, E2eDiagnosis, E2eDiagnosisCounts,
    E2eDirtyCluster, E2eDirtyCounts, E2eFailureCluster, E2eFocusedApiStatus, E2eReplayGate,
    E2eRepresentativeDifference, E2eResponseDifferenceDiagnosis, E2eResponseGate,
    E2eResponseRuleEvidence, E2eResponseUnavailableReason, E2eRunContext, E2eRunInitOptions,
    E2eRunInitResult, E2eRunPrepareOptions, E2eRunPrepareResult, E2eRunResult, E2eRunStatus,
    E2eSourcePreReadiness, E2eSourcePreReadinessEndpoint, E2eSourceValueCount, E2eSourceVariation,
    E2eTargetLog, E2eTargetRuntimeDiagnostics, E2eValueObservation, E2eValuePresence,
    E2eVerificationGates, SourceUpgradeOptions, SourceUpgradeResult, StartupMountChange,
    StartupMountChangeStatus, StartupMountEntry, StartupMountList, StartupMountPresence,
    StartupSnapshotRecaptureOptions, StartupSnapshotRecaptureResult, abort_e2e_run,
    ensure_startup_mount, initialize_e2e_run, list_startup_mounts, prepare_e2e_run,
    query_e2e_case_response_differences, query_e2e_dependency_correlation, query_e2e_dirty_counts,
    query_e2e_source_variation, query_e2e_target_runtime_diagnostics, recapture_startup_snapshot,
    recover_e2e_run, resolve_e2e_response_rule_evidence, resolve_single_e2e_response_rule_evidence,
    run_e2e_api, run_e2e_round, startup_mount_exists, status_e2e_run, upgrade_source_snapshot,
};
pub use http::stream::{ResponseChunk as HttpResponseChunk, ResponseStream as HttpResponseStream};
pub use interaction::policy::{
    CompletionRule, CorrelationRule, EventCompletion, InteractionPolicy, StreamTerminal,
};
pub use mysql::operation::MysqlWriteOperation;
pub use network_probe::PreflightProbeKind;
pub use platform::{
    ManagedRecordingPreflightOptions, ManagedRecordingPreflightRecordingResult,
    ManagedRecordingPreflightResult, ManagedReplayNetworkPreflightResult,
    ManagedTargetImagePreflightChecks, ManagedTargetImagePreflightResult,
    ManagedTargetRuntimePreflightChecks, ManagedTargetRuntimePreflightResult,
    ReplayDirectEgressProbeResult, ReplayNegativeProbeResult, ReplayPositiveProbeResult,
    run_managed_recording_preflight,
};
pub use recorder::{
    AccessPolicyAllowEvent, BodyCapture, CaseBodyCapture, CaseContext,
    DependencyConnectFailureEvent, HeaderMapSnapshot, HttpExchangeEvent, KafkaConnectionEvent,
    KafkaDeliveryEvent, KafkaFetchEvent, KafkaHeaderCapture, KafkaProduceEvent,
    MemcachedConnectionEvent, MemcachedExchangeEvent, MotanConnectionEvent, MotanExchangeEvent,
    MysqlColumn, MysqlConnectionEvent, MysqlExchangeEvent, MysqlExchangeResponse, MysqlPacketEvent,
    MysqlQueryEvent, MysqlResponseEvent, MysqlResponsePacket, MysqlTlsRejectedEvent, MysqlValue,
    ProxyErrorEvent, ReadonlyRejectionEvent, Recorder, RecorderEvent, RedisConnectionEvent,
    RedisExchangeEvent, TcpGatewayConnectionEvent, UdpDatagramEvent, capture_body,
    capture_body_with_original_len, capture_case_body, redact_headers,
};
pub use recording_api::RecordingApi;
pub use recording_control::{
    RecordingReadiness, RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready,
};
pub use rewrite::{
    AttributionCommandOptions, AttributionReviewContext, AttributionRuleBinding,
    AttributionSubmission, ClaimRejection, ForeignUnusedClaim, ForeignUnusedSubmission,
    InvestigationOutcome, InvestigationResolution, ProposedAttribution, TargetInvestigation,
    TargetInvestigationResolutionSubmission, TargetInvestigationSubmission, VerificationImpact,
    VerificationRequirement, VerificationScope, apply_dependency_attribution, claim_foreign_unused,
    compact_rewrite_decision_history, dependency_attribution_api_information,
    dependency_attribution_batch_information, dependency_attribution_candidates,
    dependency_attribution_context, dependency_attribution_hypotheses,
    dependency_attribution_rules, dependency_attribution_source_information,
    dependency_attribution_target, investigate_unmatched_dependency, resolve_target_investigation,
    retry_dependency_batch, verify_dependency_obligation, verify_rewrite_decision_history,
};

pub use rewrite::{
    GroupReplayKind, GroupReplayResult, GroupReplayRound, GroupReplaySummary,
    ImplementerConfirmOptions, ImplementerDelivery, ImplementerDispatch, ImplementerHandoffOptions,
    ImplementerPoolView, ImplementerReassignOptions, ImplementerReplaceRuntimeOptions,
    ImplementerReportOptions, ImplementerSlotView, ImplementerTask, IntegrationHandoffSelection,
    JwtRulePlanOptions, RepositoryAnalysisApplyOptions, RepositoryAnalysisContext,
    RepositoryAnalysisContextOptions, RepositoryAnalysisSnapshot, RewriteAction,
    RewriteActionEnvelope, RewriteAdvanceKind, RewriteApiInventoryDetails, RewriteApiInventoryItem,
    RewriteApiInventoryView, RewriteApiProgress, RewriteApiSelector, RewriteApiStatus,
    RewriteApplicableRulePlanner, RewriteCapturePreview, RewriteCaseDependenciesOptions,
    RewriteCaseDependenciesReport, RewriteCaseDependencyProtocolDetail,
    RewriteCaseDependencySourceReference, RewriteCaseDependencyTarget,
    RewriteCaseDependencyTargetSummary, RewriteCaseGroupRebuildOptions,
    RewriteCaseGroupRebuildReport, RewriteCommandSpec, RewriteContext, RewriteCoordinationDetails,
    RewriteDependencyCaptureDetail, RewriteDependencyOwnership,
    RewriteDependencyPayloadRulePlanOptions, RewriteDependencyPayloadRulePlanReport,
    RewriteDependencyRulePlanOptions, RewriteDependencyRulePlanReport, RewriteDependencyRuleReport,
    RewriteDependencyRuleSelector, RewriteEvidenceCommand, RewriteEvidenceContext,
    RewriteEvidenceReport, RewriteExecutionMode, RewriteExpertApiCommands, RewriteExpertApiView,
    RewriteExpertCloseOptions, RewriteExpertCommands, RewriteExpertDeliveryOptions,
    RewriteExpertInventoryItem, RewriteExpertOptions, RewriteExpertPrepareOptions,
    RewriteExpertState, RewriteExpertView, RewriteFocusedE2eExecution,
    RewriteFocusedE2eExecutionMode, RewriteHttpResponseCapturePlanOptions,
    RewriteHttpResponseCaptureReport, RewriteInputRequiredReason, RewriteIntegrationBatchDelivery,
    RewriteIntegrationBatchOptions, RewriteIntegrationBatchReport, RewriteInventoryReport,
    RewriteIpCaptureReport, RewriteIssue, RewriteIssueKind, RewriteIssueOwner,
    RewriteMemcachedExchangeDetail, RewriteMemcachedOperationDetail, RewriteMysqlExchangeDetail,
    RewriteMysqlOperationDetail, RewriteMysqlParameterDetail, RewriteNextOptions, RewritePhase,
    RewriteRecorderCapturePlanOptions, RewriteRecorderCaptureReport,
    RewriteRecordingInputCandidate, RewriteRecordingInputCandidateDisposition,
    RewriteRecordingInputDiagnosis, RewriteRecordingInputRejections, RewriteRecordingReason,
    RewriteRecoveryReport, RewriteRedisExchangeDetail, RewriteRedisOperationDetail,
    RewriteRegressionBeginOptions, RewriteRegressionBeginReport, RewriteRepairAcceptanceKind,
    RewriteRepairCancelOptions, RewriteReplayRetryOptions, RewriteRevalidationRequestOptions,
    RewriteRevalidationRequestReport, RewriteReviewOptions, RewriteReviewReport, RewriteRouteCause,
    RewriteRouteOptions, RewriteRouteOutcome, RewriteRouteReport, RewriteRuleHint,
    RewriteRulePlanOptions, RewriteRuleReport, RewriteSourceProcessObservationView,
    RewriteSourceProcessOwnedRuleView, RewriteSourceProcessOwnedView,
    RewriteSourceProcessRedisSnapshotEndpointView, RewriteSourceProcessRedisSnapshotView,
    RewriteSourceProcessTrafficScopeView, RewriteSourceProcessTrafficView, RewriteStatusReport,
    RewriteTargetQualityOptions, RewriteTrafficOperationKind, RewriteTrafficOperationView,
    RewriteUnifiedRulePlanOptions, RewriteWaitOptions, RewriteWorkScope, RewriteWorkerActivity,
    RewriteWorkerBlockingReason, RewriteWorkerConfirmOptions, RewriteWorkerCoverageState,
    RewriteWorkerDispatchState, RewriteWorkerDispatchView, RewriteWorkerInventoryItem,
    RewriteWorkerMissingQuery, RewriteWorkerReportOptions, RewriteWorkerTransferOptions,
    RewriteWorkflowView, accept_rewrite_review, apply_repository_analysis,
    apply_rewrite_dependency_rule, apply_rewrite_recorder_capture, apply_rewrite_rule,
    archive_unmanaged_rewrite_case_groups, begin_rewrite_regression,
    cancel_misrouted_rewrite_repair, check_batch_rewrite_review, check_rewrite_pre_revalidation,
    check_rewrite_review, check_rewrite_review_batch_file, close_rewrite_expert,
    confirm_rewrite_expert, confirm_rewrite_implementer, confirm_rewrite_worker,
    execute_rewrite_operation, export_rewrite_integration_batch, handoff_rewrite_implementer,
    inventory_rewrite, next_rewrite, plan_rewrite_dependency_payload_rule,
    plan_rewrite_dependency_rule, plan_rewrite_http_response_capture,
    plan_rewrite_recorder_capture, plan_rewrite_rule, plan_rewrite_unified_rule,
    prepare_rewrite_expert, query_rewrite_case_dependencies,
    query_rewrite_case_dependency_exchange, query_rewrite_evidence,
    query_rewrite_evidence_for_scope, query_rewrite_redis_argument_for_scope,
    query_rewrite_witness_for_scope, reassign_rewrite_implementer, rebuild_rewrite_case_groups,
    recover_rewrite, recover_rewrite_rule_plan, replace_rewrite_implementer_runtime,
    report_rewrite_expert_delivery, report_rewrite_implementer, report_rewrite_worker,
    repository_analysis_context, request_rewrite_revalidation, resume_rewrite_replay_planning,
    retry_rewrite_operation, retry_rewrite_replay_after_out_of_band_run, rework_rewrite_review,
    rework_rewrite_review_with_report, route_rewrite, run_rewrite_target_quality,
    show_rewrite_review, start_rewrite_next, start_rewrite_target_quality, status_rewrite,
    status_rewrite_for_api, status_rewrite_for_selector, transfer_rewrite_worker,
    verify_rewrite_repair, wait_rewrite,
};
pub use runtime_output::RuntimeOutputLocation;
pub use source_snapshot::{
    ContainerSourceOptions, KubernetesSourceOptions, SourceIgnoredMount, SourceImage,
    SourceOptions, SourceProviderEvidence, SourceSnapshotReport,
    capture_kubernetes_source_snapshot, capture_source_snapshot,
};

pub fn source_environment_value(
    target_root: &std::path::Path,
    name: &str,
) -> anyhow::Result<String> {
    source_snapshot::environment_value(target_root, name)
}
pub use startup::{
    StartupConfig, StartupEnvironmentChange, StartupEnvironmentChangeStatus,
    StartupEnvironmentComparison, StartupEnvironmentImport, StartupEnvironmentList,
    StartupEnvironmentPresence, StartupEnvironmentValidation, StartupSnapshotReport,
    ensure_startup_environment, import_startup_environment, initialize_startup_environment,
    list_startup_environment, remove_startup_environment, startup_environment_equals,
    startup_environment_exists, validate_startup_environment,
};
pub use target_container::TargetImage;
pub use tls::MitmCa;

type ProxyClient = Client<http::client::ObservedConnector, http_body_util::Full<bytes::Bytes>>;

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
                    if api.method().as_str() == "MOTAN" {
                        config.motan_gateway.max_cases_per_api
                    } else {
                        config
                            .http_gateway
                            .per_api_case_limits
                            .limit_for(api.path_pattern())
                    },
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
        .context("failed to initialize JSONL recorder")?
        .with_global_preparation(&config)
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

        let case_matching_ready = !(config.http_gateway.enabled
            && config.http_gateway.ready.enabled
            || config.motan_gateway.enabled);
        let recording_lifecycle = RecordingLifecycle::from_config(&config);
        let capture_registry = recorder.capture.clone();
        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
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

    pub(crate) fn should_record_api(&self, method: &hyper::Method, uri: &hyper::Uri) -> bool {
        self.inner.recording_apis.is_empty() || self.recording_api_pattern(method, uri).is_some()
    }

    pub(crate) fn should_record_motan_api(&self, api_pattern: &str) -> bool {
        let method = "MOTAN".parse().expect("MOTAN is a valid HTTP token");
        let uri = api_pattern
            .parse()
            .expect("generated Motan API path is a valid URI");
        self.should_record_api(&method, &uri)
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

    pub(crate) fn response_rewrites(&self) -> &http::rewrite::CompiledRewrites {
        &self.inner.response_rewrites
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

    pub(crate) fn dependency_connections(&self) -> &DependencyConnections {
        &self.inner.dependency_connections
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
            .process_owned_dependencies
            .matching_redis_snapshot_rule(target_port, command, args)
    }

    pub(crate) fn has_redis_snapshot_port(&self, port: u16) -> bool {
        self.inner
            .process_owned_dependencies
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
        mut targets: DependencyTargets,
    ) {
        if targets.process_rule_ids.is_empty() {
            let rules = self
                .inner
                .process_owned_dependencies
                .matching_capture_rules(&event);
            targets = crate::recorder::process_classification::classify(
                targets,
                rules,
                &self.config().process_dependency_tasks,
            );
        }
        let background_match = self.inner.process_owned_dependencies.matching_rule(&event);
        let (probe_attribution, suppress_default_global) = self.preflight_probe_attribution(&event);
        let background_attributed =
            probe_attribution.is_none() && !suppress_default_global && background_match.is_some();
        let api_idle = if targets.cases.is_empty() && !targets.bootstrap_open {
            self.inner
                .process_owned_dependencies
                .matching_api_candidate(&event)
        } else {
            None
        };
        let global_attribution = probe_attribution.or_else(|| {
            (!suppress_default_global)
                .then(|| {
                    targets
                        .process_owned_rule
                        .as_deref()
                        .or_else(|| background_match.as_ref().map(|matched| matched.rule_name()))
                        .map(|rule_name| crate::recorder::GlobalDependencyAttribution {
                            reason: "background_rule",
                            phase: if targets.bootstrap_open {
                                "bootstrap"
                            } else {
                                "runtime"
                            },
                            matched_by: rule_name.to_string(),
                        })
                })
                .flatten()
        });
        let global_attribution = global_attribution.or_else(|| {
            (!suppress_default_global)
                .then_some(api_idle)
                .flatten()
                .map(|name| crate::recorder::GlobalDependencyAttribution {
                    reason: "api_trigger_candidate",
                    phase: "runtime",
                    matched_by: name.to_string(),
                })
        });
        // A later callback can reference an idle RPC publisher. Preserve that
        // finite protocol witness alongside the callback even without a Case.
        let global_attribution = global_attribution.or_else(|| {
            (targets.cases.is_empty()
                && !suppress_default_global
                && !targets.bootstrap_open
                && targets.ambiguous_active_cases == 0
                && matches!(&event, RecorderEvent::RedisExchange(exchange)
                    if exchange.rpc_callback_capture.as_deref() == Some("bounded_window")))
            .then(|| crate::recorder::GlobalDependencyAttribution {
                reason: "rpc_publisher",
                phase: "runtime",
                matched_by: "socketio_rpc_protocol".to_owned(),
            })
        });
        let event_type = event.kind();
        self.inner.active_cases.observe_async_dependency_event(
            &event,
            &targets,
            global_attribution.is_none(),
        );
        self.inner.active_cases.observe_stream_tail_event(
            &event,
            &targets,
            global_attribution.is_none(),
        );
        let target_case_ids: Vec<_> = targets.cases.iter().map(|(case, _)| case.id).collect();
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
            let invalidation = CaseInvalidation::new(
                "recording_writer_failure",
                format!("failed to enqueue {event_type} recorder event: {err}"),
            );
            let invalidated = if target_case_ids.is_empty() {
                self.inner
                    .active_cases
                    .invalidate_current_case(invalidation)
                    .into_iter()
                    .collect()
            } else {
                target_case_ids
                    .into_iter()
                    .filter_map(|id| {
                        self.inner
                            .active_cases
                            .invalidate_case(id, invalidation.clone())
                    })
                    .collect::<Vec<_>>()
            };
            for case in invalidated {
                warn!(
                    case_id = %case.id,
                    rule = %case.rule_name,
                    "active recording case invalidated by recorder writer failure"
                );
            }
        } else if background_attributed && let Some(matched) = &background_match {
            self.inner
                .process_owned_dependencies
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
