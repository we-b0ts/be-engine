use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use hyper::StatusCode;
use serde::Serialize;

use super::AppConfig;
use super::edit::create_atomic;

pub const DEFAULT_RECORDING_RULE: &str = "record-api";
const RECORDER_CONFIG_PATH: &str = ".traffic-e2e/recorder.toml";
const INITIAL_CANDIDATE_RESPONSE: &str =
    r#"{"code":"COMPARISON_RECORDING_CANDIDATE_NOT_IMPLEMENTED","msg":"fixed mock response"}"#;

#[derive(Debug, Clone)]
pub struct RecorderConfigInitOptions {
    pub target_root: PathBuf,
    pub source_http_port: u16,
    pub candidate_http_port: u16,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecorderConfigInitResult {
    pub config: PathBuf,
    pub recording_rule: &'static str,
    pub matched_upstream: String,
    pub candidate_upstream: String,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
    pub project_cli: PathBuf,
    pub start_comparison_recording_script: PathBuf,
    pub candidate_mock_response: &'static str,
    pub required_ai_actions: Vec<String>,
}

pub fn initialize_recorder_config(
    options: RecorderConfigInitOptions,
) -> Result<RecorderConfigInitResult> {
    ensure!(
        options.source_http_port > 0,
        "source_http_port must be greater than zero"
    );
    ensure!(
        options.candidate_http_port > 0,
        "candidate_http_port must be greater than zero"
    );
    ensure!(
        options.candidate_http_port != options.source_http_port,
        "candidate_http_port must differ from source_http_port"
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
    let repository_name = crate::repository::directory_name(&target_root)?;
    let matched_upstream = format!("http://127.0.0.1:{}", options.source_http_port);
    let candidate_upstream = format!("http://127.0.0.1:{}", options.candidate_http_port);
    let project_cli = PathBuf::from(format!("scripts/{repository_name}-cli"));
    let start_comparison_recording_script = PathBuf::from("scripts/start-recording-comparison");
    let rendered = render_recorder_config(
        &scope,
        options.source_http_port,
        options.candidate_http_port,
        &options.readiness_path,
        options.readiness_status,
        options.upstream_dns,
    );
    let config = toml::from_str::<AppConfig>(&rendered)
        .context("generated recorder config is not valid TOML")?;
    config
        .validate()
        .context("generated recorder config failed validation")?;
    config
        .validate_comparison_recording()
        .context("generated comparison recording config failed validation")?;

    let config_path = target_root.join(RECORDER_CONFIG_PATH);
    create_atomic(&config_path, rendered.as_bytes())?;
    Ok(RecorderConfigInitResult {
        config: config_path,
        recording_rule: DEFAULT_RECORDING_RULE,
        matched_upstream,
        candidate_upstream: candidate_upstream.clone(),
        readiness_path: options.readiness_path,
        readiness_status: options.readiness_status,
        upstream_dns: options.upstream_dns,
        project_cli: project_cli.clone(),
        start_comparison_recording_script: start_comparison_recording_script.clone(),
        candidate_mock_response: INITIAL_CANDIDATE_RESPONSE,
        required_ai_actions: vec![
            format!(
                "Generate extensible executable {} with at least start, status, and stop lifecycle \
                 commands. Before target implementation exists, start must launch an owned \
                 fixed-response HTTP mock at {candidate_upstream}; every path returns status {} \
                 and body {}. These are the initialization-time minimum, not the complete command \
                 set. Later replace the mock startup with the genuine target and add the e2e, test, \
                 or check commands required by the standard traffic E2E target facade while \
                 preserving lifecycle semantics.",
                project_cli.display(),
                options.readiness_status,
                INITIAL_CANDIDATE_RESPONSE,
            ),
            format!(
                "Generate executable {}. It must validate arguments before changing state, start \
                 the genuine baseline from inspected runtime facts, stop any stale candidate owned \
                 by {} before invoking its start and status commands, run `traffic-e2e \
                 record-comparison --config .traffic-e2e/recorder.toml`, accept \
                 `--run-id YYYYMMDDHHMMSS`, `--duration-seconds <positive-integer>`, and \
                 `--baseline-recheck`, plus repeatable `--api 'METHOD /path-or-pattern'`, default \
                 the duration to 60 seconds when omitted, and accept \
                 `--brz-no-fallback <true|false>` defaulting to true. Start exactly one shared \
                 Breeze for the genuine source and candidate containers. Consume the Breeze \
                 option in this wrapper, apply executable `scripts/brz-no-fallback.sh` to each \
                 applicable application container when enabled, and pass only traffic-e2e \
                 options through unchanged. AI and automated invocations must \
                 explicitly pass `--duration-seconds 60` or another positive integer. Forward \
                 termination, allow graceful artifact finalization, stop only owned processes, \
                 and preserve the record-comparison exit status. If \
                 `recording.encrypt_request_headers` is nonempty, validate before changing state \
                 that `TRAFFIC_E2E_ENCRYPTION_KEY_B64` is strict Base64 for exactly 32 bytes, then \
                 preserve it only for the record-comparison process; never print it or inject it \
                 into the baseline, candidate, Breeze, or other supporting services.",
                start_comparison_recording_script.display(),
                project_cli.display(),
            ),
            "After replay E2E passes and a comparison recording run finalizes, verify it with \
             `traffic-e2e compare <comparison-recording-run> --policy \
             .traffic-e2e/verification.yaml`. The comparison report, including its per-API passed \
             counts, is the validation-success authority; E2E pass alone is not. Classify failures as candidate implementation \
             differences, source-time data drift, or source-proven time/random/unordered \
             non-determinism before changing code or response rules. Both record-comparison and \
             compare must remain outside fixed-user and network interception or isolation \
             workflows."
                .to_string(),
        ],
    })
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

fn render_recorder_config(
    scope: &str,
    source_http_port: u16,
    candidate_http_port: u16,
    readiness_path: &str,
    readiness_status: u16,
    upstream_dns: SocketAddr,
) -> String {
    let readiness_path = toml::Value::String(readiness_path.to_string()).to_string();
    let fallback_body = toml::Value::String(format!(
        r#"{{"code":"40401","msg":"not_in_{scope}_record_api"}}"#
    ))
    .to_string();
    RECORDER_TEMPLATE
        .replace("__UPSTREAM_DNS__", &upstream_dns.to_string())
        .replace("__SOURCE_HTTP_PORT__", &source_http_port.to_string())
        .replace("__CANDIDATE_HTTP_PORT__", &candidate_http_port.to_string())
        .replace("__READINESS_PATH__", &readiness_path)
        .replace("__READINESS_STATUS__", &readiness_status.to_string())
        .replace("__FALLBACK_BODY__", &fallback_body)
}

const RECORDER_TEMPLATE: &str = r#"# Generated by `traffic-e2e config recorder init`.
[artifacts]
root_dir = "./.traffic-e2e/artifacts"

[comparison_recording]
# http_gateway.matched_upstream is the baseline service. During initialization,
# the generated project CLI serves a fixed-response candidate on this port.
# Comparison recording rejects every configured method except GET/HEAD/OPTIONS.
candidate_upstream = "http://127.0.0.1:__CANDIDATE_HTTP_PORT__"
baseline_recheck = false
upstream_timeout_ms = 30000
max_in_flight = 256
summary_flush_interval_ms = 1000
max_request_bytes = 10485760
max_response_bytes = 10485760

[dns_mock]
enabled = true
listen = "127.0.0.153:15353"
upstream_dns = "__UPSTREAM_DNS__"
fake_cidr = "198.19.0.0/16"
ttl_seconds = 60
registry_path = "./.traffic-e2e/artifacts/fake_dns_registry.json"
bypass_domains = []
bypass_strategies = []

[dns_mock.hosts]

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

[http_response_rewrite]
enabled = false
rules = []

[udp_gateway]
enabled = true
listen = "127.0.0.1:15002"
forward = false

[http_gateway]
enabled = true
listen = "0.0.0.0:17171"
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

[http_gateway.case_limits]
default = 100

[http_gateway.case_limits.overrides]

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
max_body_bytes = 10485760
max_decoded_body_bytes = 33554432
traffic_jsonl = "errors"
jsonl_buffer_capacity_bytes = 262144
jsonl_flush_interval_ms = 1000
writer_queue_capacity = 65536
post_ready_settle_ms = 10000
case_dependency_post_response_window_ms = 100
case_dependency_drain_timeout_ms = 5000
shutdown_case_drain_timeout_ms = 5000
access_policy = "unrestricted"
encrypt_request_headers = []
redact_headers = [
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "proxy-authenticate",
]

# Source-proven process work can be moved from case ownership into the shared
# Global replay pool. Use `config recorder plan|apply background-dependencies`;
# do not hand-edit generated rules. HTTP rules are response-independent.
# [[recording.background_dependencies]]
# name = "config-refresh"
# protocol = "http"
# authorities = ["config.api.demo.test"]
# methods = ["GET"]
# path_prefixes = ["/1/config/service"]
# response_role = "independent"
# source_revision = "0123456789abcdef"
# source_evidence = "src/config/refresh.rs:42 process-level scheduled refresh"

# Breeze-backed Memcached local-cache warm rules use a stable descriptor
# identity without its dynamic port. The tool resolves the business resource
# and writes this identity after validating finalized replay evidence.
# [[recording.background_dependencies]]
# name = "planet-video-cache-warm"
# protocol = "memcached"
# breeze_identity = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc@cs"
# command = "get"
# key_start = 0
# key_end = 4095
# key_separator = "."
# key_suffix = "pl_video"
# Once HTTP readiness succeeds, fail Recorder readiness if this rule has not
# reached key_end - key_start + 1 completed matching exchanges within the
# configured timeout. No applied Memcached rule means no additional wait.
# initial_load_timeout_ms = 30000
# response_role = "runtime_state"
# source_revision = "0123456789abcdef"
# source_evidence = "TopUserServiceImpl.java:691 scheduled local-cache warm"

# BEGIN AI-MANAGED BACKGROUND DEPENDENCIES
# END AI-MANAGED BACKGROUND DEPENDENCIES

[tls]
ca_cert_path = "./data/traffic-recorder-ca.pem"
ca_key_path = "./data/traffic-recorder-ca-key.pem"
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
            readiness_path: "/healthy".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
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
        assert_eq!(
            result.project_cli.parent().unwrap(),
            PathBuf::from("scripts")
        );
        assert!(
            result
                .project_cli
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("-cli")
        );
        assert_eq!(
            result.start_comparison_recording_script,
            PathBuf::from("scripts/start-recording-comparison")
        );
        assert_eq!(result.required_ai_actions.len(), 3);
        assert!(result.required_ai_actions[0].contains("at least start, status, and stop"));
        assert!(result.required_ai_actions[0].contains("not the complete command set"));
        assert!(result.required_ai_actions[0].contains("e2e, test, or check"));
        assert!(result.required_ai_actions[1].contains("--run-id YYYYMMDDHHMMSS"));
        assert!(result.required_ai_actions[1].contains("--duration-seconds <positive-integer>"));
        assert!(result.required_ai_actions[1].contains("default the duration to 60 seconds"));
        assert!(result.required_ai_actions[1].contains("explicitly pass `--duration-seconds 60`"));
        assert!(result.required_ai_actions[1].contains("--baseline-recheck"));
        assert!(result.required_ai_actions[1].contains("--api 'METHOD /path-or-pattern'"));
        assert!(result.required_ai_actions[1].contains("--brz-no-fallback <true|false>"));
        assert!(result.required_ai_actions[1].contains("one shared Breeze"));
        assert!(result.required_ai_actions[1].contains("scripts/brz-no-fallback.sh"));
        assert!(result.required_ai_actions[1].contains("traffic-e2e record-comparison"));
        assert!(result.required_ai_actions[1].contains("TRAFFIC_E2E_ENCRYPTION_KEY_B64"));
        assert!(result.required_ai_actions[2].contains("traffic-e2e compare"));
        assert!(result.required_ai_actions[2].contains("per-API passed counts"));
        assert!(result.required_ai_actions[2].contains("outside fixed-user"));
        assert_eq!(
            result.candidate_mock_response,
            r#"{"code":"COMPARISON_RECORDING_CANDIDATE_NOT_IMPLEMENTED","msg":"fixed mock response"}"#
        );
        assert_eq!(config.http_gateway.rules[0].methods, ["GET"]);
        assert_eq!(
            config.recording.access_policy,
            super::super::RecordingAccessPolicy::Unrestricted
        );
        assert_eq!(
            config.recording_output_dir(),
            PathBuf::from("./.traffic-e2e/artifacts/recordings")
        );
        assert_eq!(config.recording.post_ready_settle_ms, 10_000);
        assert_eq!(config.recording.shutdown_case_drain_timeout_ms, 5_000);
        assert!(config.recording.background_dependencies.is_empty());
        assert!(raw.contains("# initial_load_timeout_ms = 30000"));
        assert!(raw.contains("No applied Memcached rule means no additional wait."));
        assert!(raw.contains("# BEGIN AI-MANAGED BACKGROUND DEPENDENCIES"));
        assert!(!raw.contains("verified_excludes"));
        assert!(!raw.contains("allow_side_effecting_methods"));
        assert!(raw.contains(r#""msg":"not_in_"#));

        let error = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8081,
            readiness_path: "/healthy".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
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
            readiness_path: "healthy".to_string(),
            readiness_status: 99,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("source_http_port"));
    }

    #[test]
    fn requires_distinct_source_and_candidate_ports() {
        let target = tempdir().unwrap();
        let error = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8080,
            readiness_path: "/healthz".to_string(),
            readiness_status: 404,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
        })
        .unwrap_err();

        assert!(error.to_string().contains("must differ"));
    }
}
