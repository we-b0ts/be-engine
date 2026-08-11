use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use hyper::StatusCode;
use serde::Serialize;

use super::edit::create_atomic;
use super::{AppConfig, DEFAULT_BODY_LIMIT_BYTES};

pub const DEFAULT_RECORDING_RULE: &str = "record-api";
pub const DEFAULT_HTTP_GATEWAY_PORT: u16 = 17_171;
const RECORDER_CONFIG_PATH: &str = ".traffic-e2e/recorder.toml";

#[derive(Debug, Clone)]
pub struct RecorderConfigInitOptions {
    pub target_root: PathBuf,
    pub source_http_port: u16,
    pub candidate_http_port: u16,
    pub http_gateway_port: u16,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
    pub breeze_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecorderConfigInitResult {
    pub config: PathBuf,
    pub recording_rule: &'static str,
    pub matched_upstream: String,
    pub candidate_upstream: String,
    pub http_gateway_port: u16,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
    pub runtime: &'static str,
    pub managed_record_command: String,
    pub managed_comparison_command: String,
    pub target_dockerfile: PathBuf,
    pub target_runtime_contract: &'static str,
}

pub fn initialize_recorder_config(
    options: RecorderConfigInitOptions,
) -> Result<RecorderConfigInitResult> {
    let (target_root, rendered) = render_validated_recorder_config(&options)?;
    let config_path = target_root.join(RECORDER_CONFIG_PATH);
    create_atomic(&config_path, rendered.as_bytes())?;
    Ok(init_result(&options, config_path))
}

pub(crate) fn render_validated_recorder_config(
    options: &RecorderConfigInitOptions,
) -> Result<(PathBuf, String)> {
    ensure!(
        options.source_http_port > 0,
        "source_http_port must be greater than zero"
    );
    ensure!(
        options.candidate_http_port > 0,
        "candidate_http_port must be greater than zero"
    );
    ensure!(
        options.http_gateway_port > 0,
        "http_gateway_port must be greater than zero"
    );
    ensure!(
        options.http_gateway_port != options.source_http_port
            && options.http_gateway_port != options.candidate_http_port,
        "http_gateway_port must differ from source_http_port and candidate_http_port"
    );
    validate_readiness_path(&options.readiness_path)?;
    let readiness_status = StatusCode::from_u16(options.readiness_status)
        .context("readiness_status must be a valid HTTP status")?;
    ensure!(
        !readiness_status.is_informational(),
        "readiness_status must be a final HTTP status"
    );

    let target_root = fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let scope = repository_scope(&target_root)?;
    let rendered = render_recorder_template(&scope, options);
    let mut config = toml::from_str::<AppConfig>(&rendered)
        .context("generated recorder config is not valid TOML")?;
    config
        .validate()
        .context("generated recorder config failed validation")?;
    if options.source_http_port == options.candidate_http_port {
        let candidate = super::managed_comparison_candidate(options.candidate_http_port);
        config
            .comparison_recording
            .as_mut()
            .expect("generated recorder config contains comparison recording")
            .candidate_upstream = candidate;
    }
    config
        .validate_comparison_recording()
        .context("generated comparison recording config failed validation")?;

    Ok((target_root, rendered))
}

fn init_result(
    options: &RecorderConfigInitOptions,
    config_path: PathBuf,
) -> RecorderConfigInitResult {
    let matched_upstream = format!("http://127.0.0.1:{}", options.source_http_port);
    let candidate_upstream = format!("http://127.0.0.1:{}", options.candidate_http_port);
    RecorderConfigInitResult {
        config: config_path,
        recording_rule: DEFAULT_RECORDING_RULE,
        matched_upstream,
        candidate_upstream: candidate_upstream.clone(),
        http_gateway_port: options.http_gateway_port,
        readiness_path: options.readiness_path.clone(),
        readiness_status: options.readiness_status,
        upstream_dns: options.upstream_dns,
        runtime: if options.breeze_enabled {
            "breeze"
        } else {
            "generic"
        },
        managed_record_command: "traffic-e2e record --target-root .".to_string(),
        managed_comparison_command: "traffic-e2e record-comparison --target-root .".to_string(),
        target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.e2e"),
        target_runtime_contract: "traffic-e2e builds and runs the target image with the fixed \
                                  configuration, identity, network, readiness, and cleanup contract",
    }
}

fn validate_readiness_path(path: &str) -> Result<()> {
    ensure!(!path.is_empty(), "readiness_path must not be empty");
    ensure!(path.starts_with('/'), "readiness_path must start with '/'");
    ensure!(
        !path.contains(['\r', '\n']),
        "readiness_path must be a single line"
    );
    Ok(())
}

fn repository_scope(target_root: &std::path::Path) -> Result<String> {
    let name = crate::repository::directory_name(target_root)?;
    let scope = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let scope = scope.trim_matches('_');
    ensure!(
        !scope.is_empty(),
        "target repository directory name must contain a letter or digit"
    );
    Ok(scope.to_string())
}

fn render_recorder_template(scope: &str, options: &RecorderConfigInitOptions) -> String {
    let readiness_path = toml::Value::String(options.readiness_path.to_string()).to_string();
    let fallback_body = toml::Value::String(format!(
        r#"{{"code":"40401","msg":"not_in_{scope}_record_api"}}"#
    ))
    .to_string();
    let breeze_dns = if options.breeze_enabled {
        PLATFORM_BREEZE_DNS
    } else {
        "bypass_strategies = []\n\n[dns_mock.hosts]\n"
    };
    let response_rewrite = if options.breeze_enabled {
        PLATFORM_RESPONSE_REWRITE
    } else {
        "[http_response_rewrite]\nenabled = false\nrules = []"
    };
    let encrypted_headers = if options.breeze_enabled {
        "  \"authorization\",\n"
    } else {
        ""
    };
    RECORDER_TEMPLATE
        .replace(
            "__DEFAULT_BODY_LIMIT_BYTES__",
            &DEFAULT_BODY_LIMIT_BYTES.to_string(),
        )
        .replace("__UPSTREAM_DNS__", &options.upstream_dns.to_string())
        .replace(
            "__SOURCE_HTTP_PORT__",
            &options.source_http_port.to_string(),
        )
        .replace(
            "__CANDIDATE_HTTP_PORT__",
            &options.candidate_http_port.to_string(),
        )
        .replace(
            "__HTTP_GATEWAY_PORT__",
            &options.http_gateway_port.to_string(),
        )
        .replace("__READINESS_PATH__", &readiness_path)
        .replace(
            "__READINESS_STATUS__",
            &options.readiness_status.to_string(),
        )
        .replace("__FALLBACK_BODY__", &fallback_body)
        .replace("__BREEZE_DNS__", breeze_dns)
        .replace("__RESPONSE_REWRITE__", response_rewrite)
        .replace("__ENCRYPTED_HEADERS__", encrypted_headers)
}

const PLATFORM_BREEZE_DNS: &str = r#"[[dns_mock.bypass_strategies]]
strategy = "breeze"
snapshot_dir = "/data1/breeze/snapshot"

[dns_mock.hosts]
"breeze.recording" = ["127.0.0.1"]
"#;

const PLATFORM_RESPONSE_REWRITE: &str = r#"[http_response_rewrite]
enabled = true

[[http_response_rewrite.rules]]
name = "platform-vintage-naming"
authorities = ["config.api.demo.test", "static.config.api.demo.test", "register.kailash.demo.test"]
methods = ["GET"]
path = "/naming/service"
status_codes = [200]
content_types = ["application/json"]
plugin = { name = "vintage-naming" }

[[http_response_rewrite.rules]]
name = "platform-vintage-cache-config"
authorities = ["config.api.demo.test", "static.config.api.demo.test", "register.kailash.demo.test"]
methods = ["GET"]
path = "/1/config/service"
status_codes = [200]
content_types = ["application/json"]
plugin = { name = "vintage-cache-config" }
"#;

const RECORDER_TEMPLATE: &str = r#"# Generated by repository configuration initialization.
[artifacts]
root_dir = "./.traffic-e2e/local/artifacts"

[comparison_recording]
# http_gateway.matched_upstream is the baseline service. Managed comparison
# replaces this loopback origin with the run-owned target bridge IP while
# preserving this native target port.
candidate_upstream = "http://127.0.0.1:__CANDIDATE_HTTP_PORT__"
# source_match: before_or_after in verification.yaml enables this automatically.
baseline_recheck = false
upstream_timeout_ms = 30000
max_in_flight = 1
summary_flush_interval_ms = 1000

[dns_mock]
enabled = true
listen = "127.0.0.153:15353"
upstream_dns = "__UPSTREAM_DNS__"
fake_cidr = "198.19.0.0/16"
ttl_seconds = 60
registry_path = "./.traffic-e2e/local/artifacts/fake_dns_registry.json"
bypass_domains = []
__BREEZE_DNS__

[tcp_gateway]
enabled = true
listen = "127.0.0.1:15001"
backlog = 65535
record_http = true
mitm_https = true
https_ports = []

[tcp_gateway.protocol_detection]
enabled = true
redis_port_hints = [6379]
memcached_port_hints = [11211]
kafka_port_hints = [9092]
overrides = []

__RESPONSE_REWRITE__

[udp_gateway]
enabled = true
listen = "127.0.0.1:15002"
forward = false

[http_gateway]
enabled = true
# Set by `init --http-gateway-port`; this listener receives selected HTTP
# recording traffic and is distinct from the source and target service ports.
listen = "0.0.0.0:__HTTP_GATEWAY_PORT__"
matched_upstream = "http://127.0.0.1:__SOURCE_HTTP_PORT__"
fallback_mode = "fixed_response"
preserve_host = true

[http_gateway.fixed_response]
status = 404
content_type = "application/json"
headers = { x-traffic-e2e-fallback = "fixed" }
body = __FALLBACK_BODY__

[http_gateway.ready]
enabled = true
path = __READINESS_PATH__
success_status = __READINESS_STATUS__
interval_ms = 1000

[http_gateway.per_api_case_limits]
default = 100

[http_gateway.per_api_case_limits.overrides]

[[http_gateway.rules]]
name = "record-api"
methods = ["GET"]
path_prefixes = ["/"]
# BEGIN AI-MANAGED ALLOWED UNUSED HTTP HOSTS
allowed_unused_http_hosts = [
]
# END AI-MANAGED ALLOWED UNUSED HTTP HOSTS
# BEGIN AI-MANAGED CASE PATH PATTERNS
# source_revision = ""
case_path_patterns = [
]
# END AI-MANAGED CASE PATH PATTERNS
headers = {}

[mysql]
record_raw_packets = false

[recording]
max_body_bytes = __DEFAULT_BODY_LIMIT_BYTES__
traffic_jsonl = "errors"
jsonl_buffer_capacity_bytes = 262144
jsonl_flush_interval_ms = 1000
writer_queue_capacity = 65536
cache_snapshot_max_waiters_per_entry = 1024
cache_snapshot_fill_timeout_ms = 30000
post_ready_settle_ms = 15000
post_ready_max_wait_ms = 180000
case_dependency_post_response_window_ms = 100
case_dependency_drain_timeout_ms = 5000
shutdown_case_drain_timeout_ms = 5000
access_policy = "unrestricted"
encrypt_request_headers = [
__ENCRYPTED_HEADERS__]
redact_headers = [
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "proxy-authenticate",
]

# BEGIN AI-MANAGED BACKGROUND DEPENDENCIES
[[recording.background_dependencies]]
name = "breeze_vintage"
protocol = "http"
authorities = ["config.api.demo.test", "static.config.api.demo.test", "register.kailash.demo.test"]
methods = ["GET"]
path_prefixes = ["/1/config/service", "/naming/service"]
source_evidence = "traffic-e2e system default: Weibo Breeze Vintage configuration and naming refresh are process-owned background traffic"
# END AI-MANAGED BACKGROUND DEPENDENCIES

[tls]
ca_cert_path = "./.traffic-e2e/local/data/traffic-recorder-ca.pem"
ca_key_path = "./.traffic-e2e/local/data/traffic-recorder-ca-key.pem"
"#;

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn initializes_complete_recorder_template_once() {
        let target = tempdir().unwrap();
        let result = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8081,
            http_gateway_port: 18_181,
            readiness_path: "/healthy".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            breeze_enabled: true,
        })
        .unwrap();

        let raw = fs::read_to_string(&result.config).unwrap();
        let config = AppConfig::load(&result.config).unwrap();
        assert_eq!(
            config.http_gateway.matched_upstream,
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            config
                .comparison_recording
                .as_ref()
                .unwrap()
                .candidate_upstream,
            "http://127.0.0.1:8081"
        );
        assert!(
            !config
                .comparison_recording
                .as_ref()
                .unwrap()
                .baseline_recheck
        );
        assert_eq!(result.runtime, "breeze");
        assert_eq!(result.http_gateway_port, 18_181);
        assert_eq!(config.http_gateway.listen.to_string(), "0.0.0.0:18181");
        assert_eq!(
            result.managed_record_command,
            "traffic-e2e record --target-root ."
        );
        assert_eq!(
            result.target_dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.e2e")
        );
        assert!(
            result
                .target_runtime_contract
                .contains("fixed configuration")
        );
        assert_eq!(config.recording.encrypt_request_headers, ["authorization"]);
        assert_eq!(config.dns_mock.bypass_strategies.len(), 1);
        assert_eq!(config.http_response_rewrite.rules.len(), 2);
        assert_eq!(config.http_gateway.rules[0].methods, ["GET"]);
        assert_eq!(
            config.recording.access_policy,
            super::super::RecordingAccessPolicy::Unrestricted
        );
        assert_eq!(
            config.recording_output_dir(),
            PathBuf::from("./.traffic-e2e/local/artifacts/recordings")
        );
        assert_eq!(config.recording.post_ready_settle_ms, 15_000);
        assert_eq!(config.recording.post_ready_max_wait_ms, 180_000);
        assert_eq!(config.recording.cache_snapshot_max_waiters_per_entry, 1_024);
        assert_eq!(config.recording.cache_snapshot_fill_timeout_ms, 30_000);
        assert_eq!(config.recording.shutdown_case_drain_timeout_ms, 5_000);
        assert_eq!(config.recording.max_body_bytes, DEFAULT_BODY_LIMIT_BYTES);
        assert_eq!(config.recording.max_decoded_body_bytes, None);
        assert_eq!(
            config.recording.decoded_body_limit(),
            DEFAULT_BODY_LIMIT_BYTES
        );
        assert!(config.comparison_recording.is_some());
        assert!(!raw.contains("max_request_bytes"));
        assert!(!raw.contains("max_response_bytes"));
        assert!(!raw.contains("max_decoded_body_bytes"));
        assert!(!raw.contains("cache_snapshot_max_entries"));
        assert!(!raw.contains("cache_snapshot_max_bytes"));
        assert_eq!(config.recording.background_dependencies.len(), 1);
        assert_eq!(
            config.recording.background_dependencies[0].name(),
            "breeze_vintage"
        );
        let crate::config::BackgroundDependencyRuleConfig::Http {
            authorities,
            methods,
            path_prefixes,
            source_evidence,
            ..
        } = &config.recording.background_dependencies[0]
        else {
            panic!("default Breeze Vintage background rule must use HTTP");
        };
        assert_eq!(
            authorities,
            &[
                "config.api.demo.test",
                "static.config.api.demo.test",
                "register.kailash.demo.test"
            ]
        );
        assert_eq!(methods, &["GET"]);
        assert_eq!(path_prefixes, &["/1/config/service", "/naming/service"]);
        assert!(source_evidence.starts_with("traffic-e2e system default:"));
        assert!(!raw.contains("startup-cache-warm"));
        assert!(!raw.contains("planet-video-cache-warm"));
        assert!(raw.contains("# Set by `init --http-gateway-port`"));
        assert!(!raw.contains("__HTTP_GATEWAY_PORT__"));
        assert!(raw.contains("# BEGIN AI-MANAGED BACKGROUND DEPENDENCIES"));
        assert!(!raw.contains("verified_excludes"));
        assert!(!raw.contains("allow_side_effecting_methods"));
        assert!(raw.contains(r#""msg":"not_in_"#));

        let error = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8081,
            http_gateway_port: 18_181,
            readiness_path: "/healthy".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            breeze_enabled: true,
        })
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
    }

    #[test]
    fn rejects_ambiguous_runtime_inputs() {
        let target = tempdir().unwrap();
        let error = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 0,
            candidate_http_port: 0,
            http_gateway_port: 0,
            readiness_path: "healthy".to_string(),
            readiness_status: 99,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            breeze_enabled: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("source_http_port"));
    }

    #[test]
    fn accepts_native_source_and_candidate_http_port() {
        let target = tempdir().unwrap();
        let result = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8080,
            http_gateway_port: 18_181,
            readiness_path: "/healthz".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            breeze_enabled: false,
        })
        .unwrap();

        let raw = fs::read_to_string(&result.config).unwrap();
        assert!(raw.contains("matched_upstream = \"http://127.0.0.1:8080\""));
        assert!(raw.contains("candidate_upstream = \"http://127.0.0.1:8080\""));
        assert!(AppConfig::load_comparison_recording(&result.config).is_err());
        let runtime = AppConfig::load_comparison_recording_with_candidate(
            &result.config,
            Some("http://172.30.0.2:8080"),
        )
        .unwrap();
        assert_eq!(
            runtime
                .comparison_recording
                .as_ref()
                .unwrap()
                .candidate_upstream,
            "http://172.30.0.2:8080"
        );
    }

    #[test]
    fn requires_http_gateway_port_to_be_distinct_from_upstreams() {
        let target = tempdir().unwrap();
        let error = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8081,
            http_gateway_port: 8081,
            readiness_path: "/healthz".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            breeze_enabled: false,
        })
        .unwrap_err();

        assert!(error.to_string().contains("http_gateway_port must differ"));
    }

    #[test]
    fn generic_initialization_installs_only_default_vintage_background_policy() {
        let target = tempdir().unwrap();
        let result = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8181,
            http_gateway_port: 18_181,
            readiness_path: "/healthz".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            breeze_enabled: false,
        })
        .unwrap();
        let config = AppConfig::load(&result.config).unwrap();

        assert_eq!(result.runtime, "generic");
        assert_eq!(
            result.managed_record_command,
            "traffic-e2e record --target-root ."
        );
        assert_eq!(
            result.target_dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.e2e")
        );
        assert!(config.recording.encrypt_request_headers.is_empty());
        assert!(config.dns_mock.bypass_strategies.is_empty());
        assert!(config.http_response_rewrite.rules.is_empty());
        assert_eq!(config.recording.background_dependencies.len(), 1);
        assert_eq!(
            config.recording.background_dependencies[0].name(),
            "breeze_vintage"
        );
    }
}
