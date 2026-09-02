use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use super::{
    AppConfig, DEFAULT_BODY_LIMIT_BYTES, DEFAULT_DNS_MOCK_PORT, DEFAULT_TCP_GATEWAY_PORT,
    DEFAULT_UDP_GATEWAY_PORT,
};
use anyhow::{Context, Result, ensure};
use hyper::StatusCode;

pub const DEFAULT_HTTP_GATEWAY_PORT: u16 = 4_080;

#[derive(Debug, Clone)]
pub(crate) struct RecorderConfigInitOptions {
    pub target_root: PathBuf,
    pub source_http_port: u16,
    pub candidate_http_port: u16,
    pub http_gateway_port: u16,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
    pub breeze_enabled: bool,
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
    let rendered = render_recorder_template(&scope, options)?;
    let mut config = serde_yaml::from_str::<AppConfig>(&rendered)
        .context("generated recorder config is not valid YAML")?;
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

    let rendered = serde_yaml::to_string(&config)
        .context("generated recorder config failed YAML serialization")?;
    Ok((target_root, rendered))
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

fn render_recorder_template(scope: &str, options: &RecorderConfigInitOptions) -> Result<String> {
    let readiness_path = render_yaml_scalar(&options.readiness_path)?;
    let fallback_body = render_yaml_scalar(&format!(
        r#"{{"code":"40401","msg":"not_in_{scope}_record_api"}}"#
    ))?;
    let response_rewrite = if options.breeze_enabled {
        PLATFORM_RESPONSE_REWRITE_YAML
    } else {
        "http_response_rewrite:\n  enabled: false\n  rules: []"
    };
    let encrypted_headers = if options.breeze_enabled {
        "  encrypt_request_headers:\n  - authorization\n"
    } else {
        "  encrypt_request_headers: []\n"
    };
    Ok(RECORDER_YAML_TEMPLATE
        .replace(
            "__DEFAULT_BODY_LIMIT_BYTES__",
            &DEFAULT_BODY_LIMIT_BYTES.to_string(),
        )
        .replace("__DNS_MOCK_PORT__", &DEFAULT_DNS_MOCK_PORT.to_string())
        .replace(
            "__TCP_GATEWAY_PORT__",
            &DEFAULT_TCP_GATEWAY_PORT.to_string(),
        )
        .replace(
            "__UDP_GATEWAY_PORT__",
            &DEFAULT_UDP_GATEWAY_PORT.to_string(),
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
        .replace("__DNS_CAPTURE_POLICY__", CAPTURE_ALL_DNS_YAML)
        .replace("__RESPONSE_REWRITE__", response_rewrite)
        .replace("__ENCRYPTED_HEADERS__", encrypted_headers))
}

fn render_yaml_scalar(value: &str) -> Result<String> {
    serde_yaml::to_string(value)
        .map(|value| value.trim_end_matches('\n').to_string())
        .context("failed to render generated recorder YAML scalar")
}

const CAPTURE_ALL_DNS_YAML: &str = "  bypass_strategies: []\n  hosts: {}\n";

const PLATFORM_RESPONSE_REWRITE_YAML: &str = r#"http_response_rewrite:
  enabled: true
  rules:
  - name: platform-vintage-naming
    authorities:
    - config.api.demo.test
    - static.config.api.demo.test
    - register.kailash.demo.test
    methods:
    - GET
    path: /naming/service
    status_codes:
    - 200
    content_types:
    - application/json
    plugin:
      name: vintage-naming
  - name: platform-vintage-cache-config
    authorities:
    - config.api.demo.test
    - static.config.api.demo.test
    - register.kailash.demo.test
    methods:
    - GET
    path: /1/config/service
    status_codes:
    - 200
    content_types:
    - application/json
    plugin:
      name: vintage-cache-config
"#;

const RECORDER_YAML_TEMPLATE: &str = r#"# Generated by repository configuration initialization.
artifacts:
  root_dir: ./.traffic-e2e/local/artifacts
comparison_recording:
# http_gateway.matched_upstream is the baseline service. Managed comparison
# replaces this loopback origin with the run-owned target bridge IP while
# preserving this native target port.
  candidate_upstream: http://127.0.0.1:__CANDIDATE_HTTP_PORT__
# source_match: before_or_after in verification.yaml enables this automatically.
  baseline_recheck: false
  upstream_timeout_ms: 30000
  max_in_flight: 1
  summary_flush_interval_ms: 1000
  process_output_flush_after_last_case_ms: 15000
dns_mock:
  enabled: true
  listen: 127.0.0.153:__DNS_MOCK_PORT__
  upstream_dns: __UPSTREAM_DNS__
  fake_cidr: 198.19.0.0/16
  ttl_seconds: 60
  registry_path: ./.traffic-e2e/local/artifacts/fake_dns_registry.json
  bypass_domains: []
__DNS_CAPTURE_POLICY__
tcp_gateway:
  enabled: true
  listen: 127.0.0.1:__TCP_GATEWAY_PORT__
  backlog: 65535
  record_http: true
  mitm_https: true
  https_ports: []

__RESPONSE_REWRITE__
udp_gateway:
  enabled: true
  listen: 127.0.0.1:__UDP_GATEWAY_PORT__
  forward: false
http_gateway:
  enabled: true
# Set by `init --http-gateway-port`; this listener receives selected HTTP
# recording traffic and is distinct from the recorder-owned native HTTP port.
  listen: 0.0.0.0:__HTTP_GATEWAY_PORT__
  matched_upstream: http://127.0.0.1:__SOURCE_HTTP_PORT__
  fallback_mode: fixed_response
  preserve_host: true
  fixed_response:
    status: 404
    content_type: application/json
    headers:
      x-traffic-e2e-fallback: fixed
    body: __FALLBACK_BODY__
  ready:
    enabled: true
    path: __READINESS_PATH__
    success_status: __READINESS_STATUS__
    interval_ms: 1000
  per_api_case_limits:
    default: 100
    overrides: {}
  rules:
  - name: http-api
    methods:
    - GET
    path_prefixes:
    - /
    headers: {}
mysql:
  record_raw_packets: false
recording:
  max_body_bytes: __DEFAULT_BODY_LIMIT_BYTES__
  traffic_jsonl: errors
  jsonl_buffer_capacity_bytes: 262144
  jsonl_flush_interval_ms: 1000
  writer_queue_capacity: 65536
  cache_snapshot_max_waiters_per_entry: 1024
  cache_snapshot_fill_timeout_ms: 30000
  post_ready_settle_ms: 15000
  post_ready_max_wait_ms: 180000
  case_dependency_post_response_window_ms: 100
  case_dependency_drain_timeout_ms: 5000
  shutdown_case_drain_timeout_ms: 5000
  access_policy: unrestricted
__ENCRYPTED_HEADERS__  redact_headers:
  - authorization
  - cookie
  - set-cookie
  - proxy-authorization
  - proxy-authenticate
tls:
  ca_cert_path: ./.traffic-e2e/local/data/traffic-recorder-ca.pem
  ca_key_path: ./.traffic-e2e/local/data/traffic-recorder-ca-key.pem
"#;

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn renders_complete_recorder_for_project_initialization() {
        let target = tempdir().unwrap();
        let (_, raw) = render_validated_recorder_config(&RecorderConfigInitOptions {
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

        let config: AppConfig = serde_yaml::from_str(&raw).unwrap();
        config.validate().unwrap();
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
        assert_eq!(
            config
                .comparison_recording
                .as_ref()
                .unwrap()
                .process_output_flush_after_last_case_ms,
            crate::config::comparison_recording::DEFAULT_PROCESS_OUTPUT_FLUSH_AFTER_LAST_CASE_MS
        );
        assert_eq!(config.http_gateway.listen.to_string(), "0.0.0.0:18181");
        assert_eq!(config.dns_mock.listen.port(), DEFAULT_DNS_MOCK_PORT);
        assert_eq!(config.tcp_gateway.listen.port(), DEFAULT_TCP_GATEWAY_PORT);
        assert!(config.tcp_gateway.protocol_detection.enabled);
        assert_eq!(
            config.tcp_gateway.protocol_detection.redis_port_hints,
            [6379]
        );
        assert_eq!(config.udp_gateway.listen.port(), DEFAULT_UDP_GATEWAY_PORT);
        assert_eq!(config.recording.encrypt_request_headers, ["authorization"]);
        assert!(config.dns_mock.bypass_strategies.is_empty());
        assert!(config.dns_mock.hosts.is_empty());
        assert!(!raw.contains("strategy: breeze"));
        assert!(!raw.contains("snapshot_dir: /data1/breeze/snapshot"));
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
        assert!(raw.contains("max_decoded_body_bytes: null"));
        assert!(!raw.contains("cache_snapshot_max_entries"));
        assert!(!raw.contains("cache_snapshot_max_bytes"));
        assert!(config.process_owned_dependencies.is_empty());
        assert!(!raw.contains("startup-cache-warm"));
        assert!(!raw.contains("planet-video-cache-warm"));
        assert!(raw.contains("http_gateway:"));
        assert!(!raw.contains("protocol_detection:"));
        for placeholder in [
            "__DNS_MOCK_PORT__",
            "__TCP_GATEWAY_PORT__",
            "__UDP_GATEWAY_PORT__",
            "__HTTP_GATEWAY_PORT__",
        ] {
            assert!(!raw.contains(placeholder));
        }
        assert!(!raw.contains("PROCESS-OWNED DEPENDENCIES"));
        assert!(!raw.contains("verified_excludes"));
        assert!(!raw.contains("allow_side_effecting_methods"));
        assert!(raw.contains(r#"{"code":"40401","msg":"not_in_"#));
    }

    #[test]
    fn rejects_ambiguous_runtime_inputs() {
        let target = tempdir().unwrap();
        let error = render_validated_recorder_config(&RecorderConfigInitOptions {
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
        let (_, raw) = render_validated_recorder_config(&RecorderConfigInitOptions {
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

        assert!(raw.contains("matched_upstream: http://127.0.0.1:8080"));
        assert!(
            raw.contains("candidate_upstream: http://comparison-target.traffic-e2e.invalid:8080")
        );
        let mut runtime: AppConfig = serde_yaml::from_str(&raw).unwrap();
        runtime
            .comparison_recording
            .as_mut()
            .unwrap()
            .candidate_upstream = "http://172.30.0.2:8080".to_string();
        runtime.validate_comparison_recording().unwrap();
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
        let error = render_validated_recorder_config(&RecorderConfigInitOptions {
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
}
