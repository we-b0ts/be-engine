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

#[derive(Debug, Clone)]
pub struct RecorderConfigInitOptions {
    pub target_root: PathBuf,
    pub source_http_port: u16,
    pub candidate_http_port: u16,
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
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
    pub runtime: &'static str,
    pub managed_record_command: String,
    pub managed_comparison_command: String,
    pub target_start_contract: String,
    pub target_compile_contract: &'static str,
    pub target_stop_contract: &'static str,
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
    let rendered = render_recorder_template(
        &scope,
        options.source_http_port,
        options.candidate_http_port,
        &options.readiness_path,
        options.readiness_status,
        options.upstream_dns,
        options.breeze_enabled,
    );
    let config = toml::from_str::<AppConfig>(&rendered)
        .context("generated recorder config is not valid TOML")?;
    config
        .validate()
        .context("generated recorder config failed validation")?;
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
        target_start_contract: format!(
            "<project>-cli start --e2e --start-breeze off --boot-dir \
             .traffic-e2e/boot --port {}",
            options.candidate_http_port
        ),
        target_compile_contract: "every start --e2e compiles once before launch; when the \
                                  compile command supports --release, compile with --release \
                                  and launch that artifact; never pass --release to start",
        target_stop_contract: "<project>-cli stop",
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

fn render_recorder_template(
    scope: &str,
    source_http_port: u16,
    candidate_http_port: u16,
    readiness_path: &str,
    readiness_status: u16,
    upstream_dns: SocketAddr,
    breeze_enabled: bool,
) -> String {
    let readiness_path = toml::Value::String(readiness_path.to_string()).to_string();
    let fallback_body = toml::Value::String(format!(
        r#"{{"code":"40401","msg":"not_in_{scope}_record_api"}}"#
    ))
    .to_string();
    let breeze_dns = if breeze_enabled {
        PLATFORM_BREEZE_DNS
    } else {
        "bypass_strategies = []\n\n[dns_mock.hosts]\n"
    };
    let response_rewrite = if breeze_enabled {
        PLATFORM_RESPONSE_REWRITE
    } else {
        "[http_response_rewrite]\nenabled = false\nrules = []"
    };
    let encrypted_headers = if breeze_enabled {
        "  \"authorization\",\n"
    } else {
        ""
    };
    RECORDER_TEMPLATE
        .replace("__UPSTREAM_DNS__", &upstream_dns.to_string())
        .replace("__SOURCE_HTTP_PORT__", &source_http_port.to_string())
        .replace("__CANDIDATE_HTTP_PORT__", &candidate_http_port.to_string())
        .replace("__READINESS_PATH__", &readiness_path)
        .replace("__READINESS_STATUS__", &readiness_status.to_string())
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

const RECORDER_TEMPLATE: &str = r#"# Generated by `traffic-e2e config init`.
[artifacts]
root_dir = "./.traffic-e2e/artifacts"

[comparison_recording]
# http_gateway.matched_upstream is the baseline service. During initialization,
# the generated project CLI serves a fixed-response candidate on this port.
# Comparison recording rejects every configured method except GET/HEAD/OPTIONS.
candidate_upstream = "http://127.0.0.1:__CANDIDATE_HTTP_PORT__"
# source_match: before_or_after in verification.yaml enables this automatically.
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
encrypt_request_headers = [
__ENCRYPTED_HEADERS__]
redact_headers = [
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  "proxy-authenticate",
]

# Source-proven process work can be moved from case ownership into the shared
# Global replay pool. Use `config recorder plan|apply background-dependencies`;
# do not hand-edit generated rules.
# [[recording.background_dependencies]]
# name = "config-refresh"
# protocol = "http"
# authorities = ["config.api.demo.test"]
# methods = ["GET"]
# path_prefixes = ["/1/config/service"]
# source_evidence = "src/config/refresh.rs:42 process-level scheduled refresh"

# Process-owned Motan traffic uses an exact logical RPC identity. Do not
# persist node IPs, ports, Vintage aliases, or payload values.
# [[recording.background_dependencies]]
# name = "kunpeng-refresh"
# protocol = "motan"
# group = "kunpeng-config-rpc"
# interface_name = "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc"
# method_name = "getConfigByName"
# source_evidence = "MapiConfigLoader.java:init scheduled refresh unrelated to selected API"

# Source-proven Redis ZCOUNT process traffic uses the stable service port
# set plus one exact command and bounded key shape. Domains are diagnostic only
# and are intentionally not persisted.
# [[recording.background_dependencies]]
# name = "interest-tag-mining-cache-refresh"
# protocol = "redis"
# ports = [20917, 20918, 20919]
# command = "ZCOUNT"
# key_prefix = "1042015:"
# key_suffix = ".wtm2"
# source_evidence = "InterestTagCardServiceImpl.java:init process-owned WAIC cache refresh"

# Process-owned Redis startup reads use an exact key set with GET, SCARD, or
# HGETALL. Background-rule Global exchanges replay independently from the
# source connection lane.
# [[recording.background_dependencies]]
# name = "startup-cache-warm"
# protocol = "redis"
# ports = [20917]
# command = "GET"
# keys = ["cache:init:a", "cache:init:b"]
# initial_load_timeout_ms = 60000
# source_evidence = "src/cache/warm.rs:init loads response-driving local state"

# Breeze-backed Memcached local-cache warm rules use a stable descriptor
# identity without its dynamic port. The tool resolves the business resource
# and writes this identity after validating finalized replay evidence. Numeric
# bounds are unsigned 64-bit values so full UID-derived keys are supported.
# [[recording.background_dependencies]]
# name = "planet-video-cache-warm"
# protocol = "memcached"
# breeze_identity = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc@cs"
# command = "get"
# key_start = 0
# key_end = 4095
# key_separator = "."
# key_suffix = "pl_video"
# Once HTTP readiness succeeds, observe the initial load for up to the
# configured window and log progress every 10 seconds. If the expected load
# remains incomplete, warn and continue case admission.
# initial_load_timeout_ms = 60000
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
        assert_eq!(
            result.managed_record_command,
            "traffic-e2e record --target-root ."
        );
        assert_eq!(
            result.target_start_contract,
            "<project>-cli start --e2e --start-breeze off --boot-dir .traffic-e2e/boot --port 8081"
        );
        assert_eq!(
            result.target_compile_contract,
            "every start --e2e compiles once before launch; when the compile command supports \
             --release, compile with --release and launch that artifact; never pass --release \
             to start"
        );
        assert_eq!(result.target_stop_contract, "<project>-cli stop");
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
            PathBuf::from("./.traffic-e2e/artifacts/recordings")
        );
        assert_eq!(config.recording.post_ready_settle_ms, 10_000);
        assert_eq!(config.recording.shutdown_case_drain_timeout_ms, 5_000);
        assert!(config.recording.background_dependencies.is_empty());
        assert!(raw.contains("# initial_load_timeout_ms = 60000"));
        assert!(raw.contains("# keys = [\"cache:init:a\", \"cache:init:b\"]"));
        assert!(raw.contains("# bounds are unsigned 64-bit values"));
        assert!(raw.contains("# remains incomplete, warn and continue case admission."));
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
            readiness_path: "healthy".to_string(),
            readiness_status: 99,
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            breeze_enabled: false,
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
            breeze_enabled: false,
        })
        .unwrap_err();

        assert!(error.to_string().contains("must differ"));
    }

    #[test]
    fn generic_initialization_does_not_install_platform_policy() {
        let target = tempdir().unwrap();
        let result = initialize_recorder_config(RecorderConfigInitOptions {
            target_root: target.path().to_path_buf(),
            source_http_port: 8080,
            candidate_http_port: 8181,
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
        assert!(result.target_start_contract.ends_with("--port 8181"));
        assert!(config.recording.encrypt_request_headers.is_empty());
        assert!(config.dns_mock.bypass_strategies.is_empty());
        assert!(config.http_response_rewrite.rules.is_empty());
    }
}
