pub use traffic_engine_e2e_run::{CleanupFuture, ExecutionDriver, ExecutionFuture, execute};
pub use traffic_engine_evidence::coordination;
mod replay_exports;
pub use replay_exports::*;
pub use traffic_engine_config::access_policy;
pub use traffic_engine_config::breeze;
pub use traffic_engine_e2e_run::build_info;
pub use traffic_engine_environment::command_output;
pub use traffic_engine_evidence::api_trigger;
pub use traffic_engine_evidence::artifact_owner;
pub use traffic_engine_evidence::case_group;
pub use traffic_engine_recording::active_case;
pub mod config;
pub use api_trigger::mysql_plan::{ApiTriggeredMysqlSelector, plan_api_triggered_mysql};
pub use api_trigger::plan::{
    ApiTriggeredDependencyPlan, ApiTriggeredDependencyReport, ApiTriggeredMysqlPlan,
    ApiTriggeredMysqlReport, ApiTriggeredRedisPlan, ApiTriggeredRedisReport,
    ApiTriggeredRedisSelector, plan_api_triggered_redis,
};
pub use dependency_index::DependencyIndexReport;
pub use traffic_engine_evidence::dependency;
pub use traffic_engine_evidence::dependency_index;
pub use traffic_engine_evidence::session;
pub use traffic_engine_verification::dependency_provider;

pub fn prepare_dependency_index(source: &std::path::Path) -> anyhow::Result<DependencyIndexReport> {
    dependency_index::store::prepare(source, protocols::replay::source::validate_index_record)
        .map(|(_, report)| report)
}
pub use crate::replay::GlobalDependencyPage;
pub use e2e_run::{
    E2eEventSessionOptions, E2eEventSessionProgress, E2eEventSessionResult, E2eEventSessionState,
    E2eEventSessionStatus, run_e2e_event_session, status_e2e_event_session,
};
pub use protocols::replay::report::artifacts::read_global_dependency_page;
pub use traffic_engine_config::json_value;
pub use traffic_engine_e2e_run::e2e_run;
pub use traffic_engine_e2e_run::execution_identity;
pub use traffic_engine_environment::engine_binary;
pub use traffic_engine_environment::internal_runtime;
pub use traffic_engine_evidence::attribution_defaults;
pub use traffic_engine_evidence::attribution_review;
pub use traffic_engine_recording::dns_mock;
pub use traffic_engine_recording::gateway;
pub use traffic_engine_recording::http;
pub use traffic_engine_recording::interaction;

pub use traffic_engine_config::mysql;
pub use traffic_engine_config::path_pattern;
pub use traffic_engine_e2e_run::platform;
pub use traffic_engine_recording::local_interception;
pub use traffic_engine_recording::network_probe;
pub mod policy;
pub use traffic_engine_config::protocol_contract;
pub use traffic_engine_evidence::policy_evidence;
pub use traffic_engine_evidence::process_ownership;
pub use traffic_engine_verification::primary_protocol;
pub mod protocols;
pub use traffic_engine_config::recording_api;
pub use traffic_engine_config::redis;
pub use traffic_engine_config::value_limits;
pub use traffic_engine_environment::repository;
pub use traffic_engine_environment::runtime_output;
pub use traffic_engine_environment::source_snapshot;
pub use traffic_engine_environment::startup;
pub use traffic_engine_evidence::request_headers;
pub use traffic_engine_evidence::verification_progress;
pub use traffic_engine_recording::proxy;
pub use traffic_engine_recording::record_service;
pub use traffic_engine_recording::recorder;
pub use traffic_engine_recording::recording_case;
pub use traffic_engine_recording::recording_completion;
pub use traffic_engine_recording::recording_control;
pub use traffic_engine_recording::recording_dispatch;
pub use traffic_engine_recording::recording_network;
pub use traffic_engine_recording::recording_runtime;
pub use traffic_engine_recording::recording_stream_tail;
pub use traffic_engine_recording::recording_upstream;
pub use traffic_engine_recording::tcp_gateway;
pub use traffic_engine_recording::tcp_listener;
pub use traffic_engine_recording::udp_gateway;
pub use traffic_engine_replay::replay;
pub use traffic_engine_replay::tls;
pub use traffic_engine_replay::value_extensions;
pub use traffic_engine_verification::recorded_request;
pub use traffic_engine_verification::request_rules;
pub use traffic_engine_verification::value_codec;
pub use traffic_engine_verification::value_contract;

pub use artifact_owner::ArtifactOwner;
pub use build_info::BINARY_VERSION;
pub use traffic_engine_environment::{
    TRAFFIC_PROCESS_GID, TRAFFIC_PROCESS_UID, TRAFFIC_PROCESS_USER,
};
pub use traffic_engine_recording::AppState;

pub use crate::protocols::recording::events::{
    AccessPolicyAllowEvent, CaseBodyCapture, DependencyConnectFailureEvent, HeaderMapSnapshot,
    HttpExchangeEvent, KafkaConnectionEvent, KafkaDeliveryEvent, KafkaFetchEvent,
    KafkaHeaderCapture, KafkaProduceEvent, MemcachedConnectionEvent, MemcachedExchangeEvent,
    MotanConnectionEvent, MotanExchangeEvent, MysqlColumn, MysqlConnectionEvent,
    MysqlExchangeEvent, MysqlExchangeResponse, MysqlPacketEvent, MysqlQueryEvent,
    MysqlResponseEvent, MysqlResponsePacket, MysqlTlsRejectedEvent, MysqlValue, ProxyErrorEvent,
    ReadonlyRejectionEvent, RecorderEvent, RedisConnectionEvent, RedisExchangeEvent,
    TcpGatewayConnectionEvent, UdpDatagramEvent, capture_case_body, redact_headers,
};
pub use case_group::{
    CaseGroupEnsureResult, CaseGroupOptions, CaseGroupStatus, PatternOutcome, PatternOutcomeStatus,
    ensure_case_group, resolve_recording_api_case_ids, resolve_recording_api_member,
};
pub use config::{
    AllowedUnusedHttpHostFeedback, AllowedUnusedHttpHostPlan, AllowedUnusedHttpHostReport,
    ApiCaptureOperation, ApiCaptureProtocol, ApiTriggerCapture, ApiTriggerKind,
    ApiTriggerRedisScript, ApiTriggerSource, AppConfig, ArtifactsConfig,
    BackgroundDependencyFeedback, BackgroundDependencyPlan, BackgroundDependencyReport,
    BackgroundDependencyRuleConfig, BreezeMemcachedBackgroundDependencyFeedback,
    BreezeMemcachedBackgroundDependencyPlan, BreezeMemcachedBackgroundDependencyReport,
    CaptureConfig, CaptureProtocol, CasePathPatternAuthority, CasePathPatternFeedback,
    CasePathPatternPlan, CasePathPatternReport, DEFAULT_DNS_MOCK_LISTEN, DEFAULT_DNS_MOCK_PORT,
    DEFAULT_FAKE_CIDR, DEFAULT_HTTP_BACKEND_PORT, DEFAULT_HTTP_GATEWAY_PORT,
    DEFAULT_TCP_GATEWAY_LISTEN, DEFAULT_TCP_GATEWAY_PORT, DEFAULT_UDP_GATEWAY_LISTEN,
    DEFAULT_UDP_GATEWAY_PORT, DnsMockConfig, HttpConfig, HttpGatewayCaseLimitsConfig,
    HttpGatewayConfig, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig,
    HttpGatewayReadyConfig, HttpGatewayRuleConfig, HttpResponseRewriteConfig,
    HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig,
    MysqlBackgroundDependencyFeedback, MysqlBackgroundDependencyPlan,
    MysqlBackgroundDependencyReport, MysqlBackgroundSelector, MysqlBackgroundTableSeries,
    MysqlConfig, MysqlRouteConfig, MysqlTableSeries, RecordingAccessPolicy,
    RecordingAccessRuleConfig, RecordingAccessRuleEffect, RecordingConfig,
    RedisBackgroundDependencyFeedback, RedisBackgroundDependencyPlan,
    RedisBackgroundDependencyReport, RedisKeyPatternConfig, RepositoryConfigInitOptions,
    RepositoryConfigInitResult, TcpApplicationProtocol, TcpGatewayConfig,
    TcpProtocolDetectionConfig, TcpProtocolOverrideConfig, TlsConfig, TrafficJsonlMode,
    UdpGatewayConfig, initialize_repository_config, plan_allowed_unused_http_hosts,
    plan_background_dependency, plan_breeze_memcached_background_dependency,
    plan_case_path_pattern_feedback, plan_mysql_background_dependency,
    plan_redis_background_dependency, resolve_unified_policy_path,
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
    BodyCapture, CaseContext, Recorder, capture_body, capture_body_with_original_len,
};
pub use recording_api::RecordingApi;
pub use recording_control::{
    RecordingReadiness, RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready,
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
pub use tls::MitmCa;
pub use traffic_engine_e2e_run::TargetImage;

#[cfg(any(test, feature = "test-support"))]
pub use traffic_engine_recording::test_support;
