use super::*;
use std::path::PathBuf;

pub(super) fn fixture(temp: &tempfile::TempDir) -> PathBuf {
    let path = temp.path().join("project.yaml");
    std::fs::write(
        &path,
        r#"version: 18
project:
  target:
    startup_timeout_seconds: 1
  recording:
    source_traffic_policy: source-traffic-policy.yaml
recorder:
  dns_mock:
    enabled: true
    upstream_dns: 127.0.0.1:5300
  tcp_gateway:
    enabled: true
  udp_gateway:
    enabled: true
    forward: false
  http_gateway:
    enabled: true
    record_streaming: false
    request_timeout_ms: 731
    ready:
      enabled: true
      path: /local-ready
    per_api_case_limits:
      default: 7
      overrides:
        /api/teams/*/skills: 2
    rules:
    - methods: [GET]
      path_prefixes: [/only-local]
    exclude_rules:
    - methods: [POST]
      path_prefixes: [/api]
  recording:
    max_body_bytes: 1048576
    encrypt_request_headers: [authorization]
    redact_headers: [x-private-header]
    post_ready_settle_ms: 15000
    post_ready_max_wait_ms: 30000
    case_dependency_drain_timeout_ms: 7000
"#,
    )
    .unwrap();
    std::fs::write(
        temp.path().join("source-traffic-policy.yaml"),
        r#"version: 2
http:
  case_path_patterns: [/api/teams/*/skills]
http_response_rewrite:
- name: sandbox.example
  rules:
  - path_pattern: GET /sandboxes/*
    pointer: /base_url
    source_evidence: source consumes the sandbox URL
"#,
    )
    .unwrap();
    path
}

pub(super) fn options(path: &std::path::Path) -> OnlineRecordingOptions {
    OptionsCli::try_parse_from([
        "recording-online".as_ref(),
        "--advertise-url".as_ref(),
        "http://127.0.0.1:4080".as_ref(),
        "--config".as_ref(),
        path.as_os_str(),
        "--".as_ref(),
        "true".as_ref(),
    ])
    .unwrap()
    .options
}

#[test]
fn project_recording_settings_and_policy_survive_online_routing() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(&temp);
    let mut options = options(&path);
    options.data_root = temp.path().join("mounted-data");
    // A separately mounted policy must override the reference without double application.
    options.source_traffic_policy = Some(temp.path().join("source-traffic-policy.yaml"));
    let config = options.config().unwrap();
    assert_eq!(options.startup_timeout_seconds, 300);
    assert_eq!(config.recording.post_ready_max_wait_ms, 30_000);
    assert_eq!(config.recording.max_body_bytes, 1_048_576);
    assert_eq!(config.recording.case_dependency_drain_timeout_ms, 7000);
    assert_eq!(config.recording.encrypt_request_headers, ["authorization"]);
    assert_eq!(config.recording.redact_headers, ["x-private-header"]);
    assert_eq!(config.http_gateway.request_timeout_ms, 731);
    assert!(!config.http_gateway.record_streaming);
    assert_eq!(config.http_gateway.per_api_case_limits.default, 7);
    assert_eq!(
        config.http_gateway.per_api_case_limits.overrides["/api/teams/*/skills"],
        2
    );
    assert_eq!(config.http_gateway.ready.path, "/local-ready");
    assert_eq!(
        config.dns_mock.upstream_dns,
        "127.0.0.1:5300".parse().unwrap()
    );
    assert!(!config.udp_gateway.forward);
    assert_eq!(
        config.http_gateway.case_path_patterns,
        ["/api/teams/*/skills"]
    );
    assert_eq!(config.http_response_rewrite.rules.len(), 1);
    assert!(config.http_gateway.rules.is_empty());
    assert!(config.http_gateway.exclude_rules.is_empty());
    assert!(matches!(
        crate::gateway::http::rules::evaluate_request(
            &config.http_gateway.exclude_rules,
            &config.http_gateway.rules,
            &hyper::Method::POST,
            &"/api/teams/123/skills".parse().unwrap(),
            &hyper::HeaderMap::new(),
        ),
        crate::gateway::http::rules::RuleDecision::Matched(_)
    ));
    assert_eq!(config.http_gateway.listen, options.recorder_listen);
    assert_eq!(config.http_gateway.matched_upstream, options.source_origin);
    assert_eq!(
        config.tls.ca_cert_path,
        options
            .data_root
            .join(".traffic-e2e/local/data/traffic-recorder-ca.pem")
    );

    options.ready_path = Some("/api/ready".to_owned());
    options.case_limit = std::num::NonZeroUsize::new(5);
    options.request_timeout_seconds = Some(2);
    let overridden = options.config().unwrap();
    assert_eq!(overridden.http_gateway.ready.path, "/api/ready");
    assert_eq!(overridden.http_gateway.per_api_case_limits.default, 5);
    assert_eq!(overridden.http_gateway.request_timeout_ms, 2000);
    assert!(!overridden.http_gateway.record_streaming);

    let yaml = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        yaml.replace("record_streaming: false", "record_streaming: true"),
    )
    .unwrap();
    assert!(options.config().unwrap().http_gateway.record_streaming);
}

#[test]
fn missing_project_or_invalid_post_ready_cap_fails_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(&temp);
    let original = std::fs::read_to_string(&path).unwrap();
    for value in ["0", "14999", "wrong"] {
        std::fs::write(
            &path,
            original.replace(
                "post_ready_max_wait_ms: 30000",
                &format!("post_ready_max_wait_ms: {value}"),
            ),
        )
        .unwrap();
        assert!(options(&path).config().is_err());
    }
    std::fs::remove_file(&path).unwrap();
    assert!(options(&path).config().is_err());
}
