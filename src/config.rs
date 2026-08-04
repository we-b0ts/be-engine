use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_FAKE_CIDR: &str = "198.19.0.0/16";

mod allowed_unused_http;
mod artifacts;
pub(crate) mod background_dependencies;
mod background_feedback;
mod background_memcached_feedback;
mod background_motan_feedback;
mod background_redis_feedback;
mod breeze_capture_feedback;
mod case_limits;
mod comparison_recording;
mod dns;
pub(crate) mod edit;
mod feedback;
mod http_gateway;
mod http_response_rewrite;
mod initialization;
mod recording;
mod repository_initialization;
mod rule_document;

pub use allowed_unused_http::{
    AllowedUnusedHttpHostFeedback, AllowedUnusedHttpHostPlan, AllowedUnusedHttpHostReport,
    plan_allowed_unused_http_hosts,
};
pub use artifacts::ArtifactsConfig;
pub use background_dependencies::BackgroundDependencyRuleConfig;
pub use background_feedback::{
    BackgroundDependencyFeedback, BackgroundDependencyPlan, BackgroundDependencyReport,
    plan_background_dependency,
};
pub use background_memcached_feedback::{
    BreezeMemcachedBackgroundDependencyFeedback, BreezeMemcachedBackgroundDependencyPlan,
    BreezeMemcachedBackgroundDependencyReport, plan_breeze_memcached_background_dependency,
};
pub use background_motan_feedback::{
    MotanBackgroundDependencyFeedback, MotanBackgroundDependencyPlan,
    MotanBackgroundDependencyReport, plan_motan_background_dependency,
};
pub use background_redis_feedback::{
    RedisBackgroundDependencyFeedback, RedisBackgroundDependencyPlan,
    RedisBackgroundDependencyReport, plan_redis_background_dependency,
};
pub use breeze_capture_feedback::{
    BreezeResourceCaptureFeedback, BreezeResourceCapturePlan, BreezeResourceCaptureReport,
    plan_breeze_resource_capture,
};
pub use case_limits::HttpGatewayCaseLimitsConfig;
pub use comparison_recording::ComparisonRecordingConfig;
pub use dns::{DnsBypassStrategyConfig, DnsMockConfig};
pub use feedback::{
    CasePathPatternAuthority, CasePathPatternFeedback, CasePathPatternPlan, CasePathPatternReport,
    plan_case_path_pattern_feedback,
};
pub use http_gateway::{HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig};
pub use http_response_rewrite::{
    HttpResponseRewriteConfig, HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig,
};
pub use initialization::{
    DEFAULT_RECORDING_RULE, RecorderConfigInitOptions, RecorderConfigInitResult,
    initialize_recorder_config,
};
pub use recording::{
    RecordingAccessPolicy, RecordingAccessRuleConfig, RecordingAccessRuleEffect, RecordingConfig,
    TrafficJsonlMode,
};
pub use repository_initialization::{
    InspectedContainer, RepositoryConfigInitOptions, RepositoryConfigInitResult,
    initialize_repository_config,
};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AppConfig {
    pub artifacts: Option<ArtifactsConfig>,
    pub comparison_recording: Option<ComparisonRecordingConfig>,
    pub dns_mock: DnsMockConfig,
    pub tcp_gateway: TcpGatewayConfig,
    pub udp_gateway: UdpGatewayConfig,
    pub http: HttpConfig,
    pub http_response_rewrite: HttpResponseRewriteConfig,
    pub http_gateway: HttpGatewayConfig,
    pub mysql: MysqlConfig,
    pub recording: RecordingConfig,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TcpGatewayConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub backlog: u32,
    pub record_http: bool,
    pub mitm_https: bool,
    pub https_ports: Vec<u16>,
    pub protocol_detection: TcpProtocolDetectionConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TcpProtocolDetectionConfig {
    pub enabled: bool,
    pub redis_port_hints: Vec<u16>,
    pub memcached_port_hints: Vec<u16>,
    pub kafka_port_hints: Vec<u16>,
    pub overrides: Vec<TcpProtocolOverrideConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcpProtocolOverrideConfig {
    pub host: String,
    pub port: u16,
    pub protocol: TcpApplicationProtocol,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TcpApplicationProtocol {
    Redis,
    Memcached,
    Kafka,
    Motan,
    Raw,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UdpGatewayConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub forward: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpGatewayConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub matched_upstream: String,
    pub fallback_upstream: String,
    pub fallback_mode: HttpGatewayFallbackMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_response: Option<HttpGatewayFixedResponseConfig>,
    pub preserve_host: bool,
    pub ready: HttpGatewayReadyConfig,
    pub per_api_case_limits: HttpGatewayCaseLimitsConfig,
    pub exclude_rules: Vec<HttpGatewayRuleConfig>,
    pub rules: Vec<HttpGatewayRuleConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpGatewayReadyConfig {
    pub enabled: bool,
    pub path: String,
    pub success_status: u16,
    pub interval_ms: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpGatewayRuleConfig {
    pub name: Option<String>,
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub headers: BTreeMap<String, String>,
    pub case_path_patterns: Vec<String>,
    pub allowed_unused_http_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MysqlConfig {
    pub enabled: bool,
    pub record_raw_packets: bool,
    pub routes: Vec<MysqlRouteConfig>,
    pub listen: SocketAddr,
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MysqlRouteConfig {
    pub name: Option<String>,
    pub listen: SocketAddr,
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TlsConfig {
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config
            .validate()
            .with_context(|| format!("invalid config {}", path.display()))?;
        Ok(config)
    }

    pub fn load_comparison_recording(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config
            .validate_comparison_recording()
            .with_context(|| format!("invalid comparison recording config {}", path.display()))?;
        Ok(config)
    }

    pub fn validate_comparison_recording(&self) -> Result<()> {
        self.validate_artifacts()?;
        self.recording.validate_request_header_encryption()?;
        http_gateway::validate_config(&self.http_gateway)?;
        let comparison_recording = self.comparison_recording.as_ref().context(
            "record-comparison command requires a [comparison_recording] configuration section",
        )?;
        comparison_recording.validate(&self.http_gateway)?;
        self.http_gateway
            .per_api_case_limits
            .validate(&self.http_gateway.rules)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_artifacts()?;
        self.dns_mock.validate()?;
        self.recording.validate()?;
        self.http_response_rewrite.validate()?;
        http_gateway::validate_config(&self.http_gateway)?;
        allowed_unused_http::validate_config(&self.http_gateway)?;
        self.http_gateway
            .per_api_case_limits
            .validate(&self.http_gateway.rules)?;
        if self.recording.background_dependencies.iter().any(|rule| {
            matches!(
                rule,
                BackgroundDependencyRuleConfig::Memcached { .. }
                    | BackgroundDependencyRuleConfig::Redis {
                        initial_load_timeout_ms: Some(_),
                        ..
                    }
            )
        }) && (!self.http_gateway.enabled || !self.http_gateway.ready.enabled)
        {
            bail!(
                "background dependency initial-load observation requires an enabled HTTP gateway ready probe"
            );
        }
        if self.tcp_gateway.backlog == 0 || self.tcp_gateway.backlog > i32::MAX as u32 {
            bail!("tcp_gateway.backlog must be between 1 and {}", i32::MAX);
        }
        if self.http_response_rewrite.enabled
            && (!self.dns_mock.enabled
                || !self.tcp_gateway.enabled
                || !self.tcp_gateway.record_http)
        {
            bail!(
                "http_response_rewrite requires dns_mock.enabled, tcp_gateway.enabled, and tcp_gateway.record_http"
            );
        }
        Ok(())
    }

    pub fn recording_output_dir(&self) -> PathBuf {
        self.artifacts
            .as_ref()
            .map(|artifacts| artifacts.root_dir.join("recordings"))
            .unwrap_or_else(|| self.recording.output_dir.clone())
    }

    pub fn comparison_recording_output_dir(&self) -> PathBuf {
        self.artifacts
            .as_ref()
            .map(|artifacts| artifacts.root_dir.join("comparison-recordings"))
            .unwrap_or_else(|| self.recording.output_dir.join("comparison-recordings"))
    }

    pub fn override_per_api_case_limit_for_run(&mut self, limit: NonZeroUsize) {
        self.http_gateway
            .per_api_case_limits
            .override_for_run(limit);
    }

    fn validate_artifacts(&self) -> Result<()> {
        if let Some(artifacts) = &self.artifacts {
            artifacts.validate()?;
        }
        Ok(())
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:8080"
                .parse()
                .expect("valid default http listen address"),
        }
    }
}

impl Default for TcpGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:15001"
                .parse()
                .expect("valid default TCP gateway listen address"),
            backlog: 65_535,
            record_http: true,
            mitm_https: true,
            https_ports: Vec::new(),
            protocol_detection: TcpProtocolDetectionConfig::default(),
        }
    }
}

impl Default for TcpProtocolDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            redis_port_hints: vec![6379],
            memcached_port_hints: vec![11211],
            kafka_port_hints: vec![9092],
            overrides: Vec::new(),
        }
    }
}

impl Default for UdpGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:15002"
                .parse()
                .expect("valid default UDP gateway listen address"),
            forward: false,
        }
    }
}

impl Default for HttpGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:18080"
                .parse()
                .expect("valid default HTTP gateway listen address"),
            matched_upstream: "http://127.0.0.1:8081".to_string(),
            fallback_upstream: "http://127.0.0.1:8082".to_string(),
            fallback_mode: HttpGatewayFallbackMode::Upstream,
            fixed_response: None,
            preserve_host: true,
            ready: HttpGatewayReadyConfig::default(),
            per_api_case_limits: HttpGatewayCaseLimitsConfig::default(),
            exclude_rules: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl Default for HttpGatewayReadyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/".to_string(),
            success_status: 200,
            interval_ms: 1000,
        }
    }
}

impl Default for MysqlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            record_raw_packets: false,
            routes: Vec::new(),
            listen: "127.0.0.1:3307"
                .parse()
                .expect("valid default mysql listen address"),
            upstream: "127.0.0.1:3306".to_string(),
        }
    }
}

impl MysqlConfig {
    pub fn effective_routes(&self) -> Vec<MysqlRouteConfig> {
        if self.routes.is_empty() {
            vec![MysqlRouteConfig {
                name: Some("default".to_string()),
                listen: self.listen,
                upstream: self.upstream.clone(),
            }]
        } else {
            self.routes.clone()
        }
    }
}

impl Default for MysqlRouteConfig {
    fn default() -> Self {
        Self {
            name: None,
            listen: "127.0.0.1:3307"
                .parse()
                .expect("valid default mysql route listen address"),
            upstream: "127.0.0.1:3306".to_string(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: PathBuf::from(crate::repository::LOCAL_DATA_ROOT)
                .join("traffic-recorder-ca.pem"),
            ca_key_path: PathBuf::from(crate::repository::LOCAL_DATA_ROOT)
                .join("traffic-recorder-ca-key.pem"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn loads_example_recorder_config() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join("recorder.example.toml");
        AppConfig::load(path).unwrap();
    }

    #[test]
    fn loads_example_comparison_recording_config() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join("recorder.example.toml");
        let mut config = AppConfig::load_comparison_recording(path).unwrap();
        assert!(
            !config
                .comparison_recording
                .as_ref()
                .unwrap()
                .baseline_recheck
        );
        assert_eq!(config.http_gateway.rules.len(), 1);
        assert_eq!(
            config.recording_output_dir(),
            PathBuf::from("./.traffic-e2e/local/artifacts/recordings")
        );
        assert_eq!(
            config.comparison_recording_output_dir(),
            PathBuf::from("./.traffic-e2e/local/artifacts/comparison-recordings")
        );

        config.recording.encrypt_request_headers = vec!["not a header".to_string()];
        assert!(config.validate_comparison_recording().is_err());
    }

    #[test]
    fn parses_minimal_config_with_defaults() {
        let config: AppConfig = toml::from_str(
            r#"
            [http]
            listen = "127.0.0.1:18080"
            "#,
        )
        .unwrap();

        assert_eq!(config.http.listen.to_string(), "127.0.0.1:18080");
        assert!(!config.http.enabled);
        assert!(!config.mysql.enabled);
        assert!(!config.mysql.record_raw_packets);
        assert_eq!(config.tcp_gateway.backlog, 65_535);
        assert_eq!(
            config.http_gateway.per_api_case_limits.default,
            case_limits::DEFAULT_MAX_CASES_PER_PATTERN
        );
        assert_eq!(config.recording.max_body_bytes, 1024 * 1024);
        assert_eq!(config.recording.traffic_jsonl, TrafficJsonlMode::Full);
        assert_eq!(config.recording.jsonl_buffer_capacity_bytes, 256 * 1024);
        assert_eq!(config.recording.jsonl_flush_interval_ms, 1_000);
        assert_eq!(config.recording.writer_queue_capacity, 65_536);
        assert_eq!(config.recording.post_ready_settle_ms, 10_000);
        assert_eq!(config.recording.shutdown_case_drain_timeout_ms, 5_000);
        assert_eq!(
            config.recording.case_dependency_post_response_window_ms,
            100
        );
        assert_eq!(config.recording.case_dependency_drain_timeout_ms, 5_000);
        assert_eq!(
            config.recording.access_policy,
            RecordingAccessPolicy::Unrestricted
        );
        assert!(config.recording.access_rules.is_empty());
        assert!(config.artifacts.is_none());
        assert_eq!(config.recording_output_dir(), PathBuf::from("./recordings"));
        assert_eq!(
            config.comparison_recording_output_dir(),
            PathBuf::from("./recordings/comparison-recordings")
        );
    }

    #[test]
    fn validates_comparison_recording_configuration_only_for_that_mode() {
        let mut config = AppConfig {
            comparison_recording: Some(ComparisonRecordingConfig::default()),
            ..Default::default()
        };
        config
            .comparison_recording
            .as_mut()
            .unwrap()
            .candidate_upstream = config.http_gateway.matched_upstream.clone();
        config.http_gateway.rules = vec![HttpGatewayRuleConfig {
            name: Some("api".to_string()),
            methods: vec!["GET".to_string()],
            ..Default::default()
        }];

        config.validate().unwrap();
        assert!(config.validate_comparison_recording().is_err());
    }

    #[test]
    fn rejects_empty_artifact_root() {
        let config = AppConfig {
            artifacts: Some(ArtifactsConfig {
                root_dir: PathBuf::new(),
            }),
            ..Default::default()
        };

        let error = config.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("artifacts.root_dir must not be empty")
        );
    }

    #[test]
    fn parses_mysql_dns_routes() {
        let config: AppConfig = toml::from_str(
            r#"
            [mysql]
            enabled = true
            record_raw_packets = true

            [[mysql.routes]]
            name = "app-db"
            listen = "0.0.0.0:3306"
            upstream = "10.0.0.12:3306"
            "#,
        )
        .unwrap();

        let routes = config.mysql.effective_routes();
        assert!(config.mysql.record_raw_packets);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].name.as_deref(), Some("app-db"));
        assert_eq!(routes[0].listen.to_string(), "0.0.0.0:3306");
        assert_eq!(routes[0].upstream, "10.0.0.12:3306");
    }

    #[test]
    fn parses_tcp_protocol_detection_overrides() {
        let config: AppConfig = toml::from_str(
            r#"
            [tcp_gateway.protocol_detection]
            enabled = true
            redis_port_hints = [6379, 6380]
            memcached_port_hints = [11211]

            [[tcp_gateway.protocol_detection.overrides]]
            host = "cache.internal"
            port = 6380
            protocol = "redis"
            "#,
        )
        .unwrap();

        assert!(config.tcp_gateway.protocol_detection.enabled);
        assert_eq!(
            config.tcp_gateway.protocol_detection.redis_port_hints,
            vec![6379, 6380]
        );
        assert_eq!(config.tcp_gateway.protocol_detection.overrides.len(), 1);
        assert_eq!(
            config.tcp_gateway.protocol_detection.overrides[0].protocol,
            TcpApplicationProtocol::Redis
        );
    }

    #[test]
    fn rejects_invalid_tcp_gateway_backlog() {
        let mut config = AppConfig::default();
        config.tcp_gateway.backlog = 0;

        let error = config.validate().unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("tcp_gateway.backlog must be between 1 and {}", i32::MAX)
        );
    }

    #[test]
    fn parses_http_gateway_rules() {
        let config: AppConfig = toml::from_str(
            r#"
            [http_gateway]
            enabled = true
            listen = "127.0.0.1:18080"
            matched_upstream = "http://127.0.0.1:9001"
            fallback_upstream = "http://127.0.0.1:9002"

            [http_gateway.ready]
            enabled = true
            path = "/"
            success_status = 200
            interval_ms = 1000

            [[http_gateway.rules]]
            name = "record-api"
            hosts = ["api.example.com"]
            methods = ["GET", "POST"]
            path_prefixes = ["/api/"]
            case_path_patterns = ["/api/users/*/xxx"]
            allowed_unused_http_hosts = ["cs.aliyuncs.com"]
            headers = { "x-record" = "yes" }

            [[http_gateway.exclude_rules]]
            name = "exclude-health"
            methods = ["GET"]
            path_prefixes = ["/health"]

            [[http_gateway.rules]]
            name = "record-default-depth"
            path_prefixes = ["/default/"]
            "#,
        )
        .unwrap();
        config.validate().unwrap();

        assert!(config.http_gateway.enabled);
        assert!(config.http_gateway.ready.enabled);
        assert_eq!(config.http_gateway.ready.path, "/");
        assert_eq!(config.http_gateway.ready.success_status, 200);
        assert_eq!(config.http_gateway.ready.interval_ms, 1000);
        assert_eq!(config.http_gateway.rules.len(), 2);
        assert_eq!(config.http_gateway.exclude_rules.len(), 1);
        assert_eq!(
            config.http_gateway.exclude_rules[0].name.as_deref(),
            Some("exclude-health")
        );
        assert_eq!(
            config.http_gateway.exclude_rules[0].path_prefixes,
            vec!["/health".to_string()]
        );
        assert_eq!(
            config.http_gateway.rules[0].case_path_patterns,
            vec!["/api/users/*/xxx".to_string()]
        );
        assert_eq!(
            config.http_gateway.rules[0].allowed_unused_http_hosts,
            vec!["cs.aliyuncs.com".to_string()]
        );
        assert_eq!(
            config.http_gateway.rules[0].headers["x-record"],
            "yes".to_string()
        );
        assert!(config.http_gateway.rules[1].case_path_patterns.is_empty());
    }

    #[test]
    fn parses_dns_mock_and_fake_ip_gateways() {
        let config: AppConfig = toml::from_str(
            r#"
            [dns_mock]
            enabled = true
            listen = "127.0.0.1:53"
            upstream_dns = "8.8.8.8:53"
            fake_cidr = "198.18.0.0/15"
            bypass_domains = ["preview-wss-wegent.intra.demo.test", ".internal.example.com"]
            registry_path = "./recordings/test_fake_dns_registry.json"

            [[dns_mock.bypass_strategies]]
            strategy = "breeze"
            snapshot_dir = "/data1/breeze/snapshot"
            capture_resources = ["static.config+3+config+cloud+redis+user+usercounter"]

            [dns_mock.hosts]
            "db-10-185-28-119.test" = ["10.185.28.119"]
            "multi-db.test" = ["10.0.0.1", "10.0.0.2"]

            [tcp_gateway]
            enabled = true
            listen = "127.0.0.1:15001"
            backlog = 4096
            record_http = true
            mitm_https = true
            https_ports = [443, 8443]

            [udp_gateway]
            enabled = true
            listen = "127.0.0.1:15002"
            forward = true
            "#,
        )
        .unwrap();

        assert!(config.dns_mock.enabled);
        assert!(config.tcp_gateway.enabled);
        assert!(config.udp_gateway.enabled);
        assert_eq!(config.tcp_gateway.backlog, 4096);
        assert!(config.tcp_gateway.mitm_https);
        assert_eq!(config.tcp_gateway.https_ports, vec![443, 8443]);
        assert_eq!(config.udp_gateway.listen.to_string(), "127.0.0.1:15002");
        assert!(config.udp_gateway.forward);
        assert_eq!(config.dns_mock.fake_cidr, "198.18.0.0/15");
        assert_eq!(
            config.dns_mock.bypass_domains,
            vec![
                "preview-wss-wegent.intra.demo.test".to_string(),
                ".internal.example.com".to_string()
            ]
        );
        assert_eq!(
            config.dns_mock.bypass_strategies,
            vec![DnsBypassStrategyConfig::Breeze {
                snapshot_dir: PathBuf::from("/data1/breeze/snapshot"),
                capture_resources: vec![
                    "static.config+3+config+cloud+redis+user+usercounter".to_string()
                ],
            }]
        );
        assert_eq!(
            config.dns_mock.registry_path,
            PathBuf::from("./recordings/test_fake_dns_registry.json")
        );
        assert_eq!(
            config.dns_mock.hosts["db-10-185-28-119.test"],
            vec!["10.185.28.119".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(config.dns_mock.hosts["multi-db.test"].len(), 2);
    }
}
