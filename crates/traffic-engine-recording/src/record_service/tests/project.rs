use super::*;
use std::path::PathBuf;

#[test]
fn standalone_timeout_uses_common_default_and_cli_override_for_streams() {
    for (arguments, expected_ms) in [
        (vec!["test", "--", "true"], 900_000),
        (
            vec!["test", "--request-timeout-seconds", "17", "--", "true"],
            17_000,
        ),
    ] {
        let options = OptionsCli::try_parse_from(arguments).unwrap().options;
        let config = options.config().unwrap();
        assert_eq!(config.http_gateway.request_timeout_ms, expected_ms);
        let policy = config
            .http_gateway
            .interaction_policy(crate::interaction::model::Protocol::Sse);
        assert_eq!(policy.request_timeout_ms, expected_ms);
        assert_eq!(policy.max_duration_ms, expected_ms);
    }
}

pub(super) fn fixture(temp: &tempfile::TempDir) -> PathBuf {
    let directory = temp.path().join(".traffic-e2e");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("project.yaml");
    std::fs::write(
        &path,
        r#"version: 18
project:
  target:
    startup_timeout_seconds: 1
  policy: .traffic-e2e/policy.yaml
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
    std::fs::write(directory.join("policy.yaml"), super::policy::POLICY).unwrap();
    path
}

pub(super) fn options(path: &std::path::Path) -> RecordOptions {
    OptionsCli::try_parse_from([
        "traffic-e2e record".as_ref(),
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
    // An explicit same policy is accepted once; it cannot override project.policy.
    options.policy = Some(path.parent().unwrap().join("policy.yaml"));
    let config = options.config().unwrap();
    assert_eq!(options.startup_timeout_seconds, 300);
    assert_eq!(config.recording.post_ready_max_wait_ms, 30_000);
    assert_eq!(config.recording.max_body_bytes, 1_048_576);
    assert_eq!(config.recording.case_dependency_drain_timeout_ms, 7000);
    assert_eq!(config.recording.encrypt_request_headers, ["authorization"]);
    assert_eq!(config.recording.redact_headers, ["x-private-header"]);
    assert_eq!(config.http_gateway.request_timeout_ms, 731);
    assert_eq!(
        config
            .http_gateway
            .interaction_policy(crate::interaction::model::Protocol::Sse)
            .request_timeout_ms,
        731
    );
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
    assert_eq!(config.http_gateway.rules.len(), 1);
    assert_eq!(config.http_gateway.exclude_rules.len(), 1);
    assert!(matches!(
        crate::gateway::http::rules::evaluate_request(
            &config.http_gateway.exclude_rules,
            &config.http_gateway.rules,
            &hyper::Method::POST,
            &"/api/teams/123/skills".parse().unwrap(),
            &hyper::HeaderMap::new(),
        ),
        crate::gateway::http::rules::RuleDecision::Excluded { .. }
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
    let policy = overridden
        .http_gateway
        .interaction_policy(crate::interaction::model::Protocol::Sse);
    assert_eq!(policy.request_timeout_ms, 2000);
    assert_eq!(policy.max_duration_ms, 2000);
    assert!(!overridden.http_gateway.record_streaming);

    let yaml = crate::recorder::test_io::read_to_string_sync(&path).unwrap();
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
    let original = crate::recorder::test_io::read_to_string_sync(&path).unwrap();
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

#[test]
fn explicit_policy_cannot_override_the_project_authority() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(&temp);
    let mut configured = options(&path);
    let other = temp.path().join("other-policy.yaml");
    std::fs::write(&other, super::policy::POLICY).unwrap();
    configured.policy = Some(other);
    assert!(
        configured
            .config()
            .unwrap_err()
            .to_string()
            .contains("same file as project.policy")
    );
    assert!(
        OptionsCli::try_parse_from([
            "traffic-e2e record",
            "--source-traffic-policy",
            "old.yaml",
            "--",
            "true"
        ])
        .is_err()
    );
}

#[test]
fn business_http_capture_preserves_project_policy_and_runtime_overrides() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(&temp);
    let original = std::fs::read_to_string(&path).unwrap();
    let concise = original.replace(
        "  dns_mock:\n    enabled: true\n    upstream_dns: 127.0.0.1:5300\n  tcp_gateway:\n    enabled: true\n  udp_gateway:\n    enabled: true\n    forward: false\n",
        "  capture:\n    ingress: [http]\n    dependencies: [http]\n  dns_mock:\n    upstream_dns: 127.0.0.1:5300\n",
    );
    assert_ne!(concise, original);
    std::fs::write(&path, concise).unwrap();

    let mut configured = options(&path);
    configured.data_root = temp.path().join("mounted-data");
    configured.ready_path = Some("/runtime-ready".into());
    configured.request_timeout_seconds = Some(17);
    let config = configured.config().unwrap();
    assert!(config.http_gateway.enabled);
    assert!(config.dns_mock.enabled);
    assert!(config.tcp_gateway.enabled);
    assert!(config.tcp_gateway.mitm_https);
    assert!(!config.udp_gateway.enabled);
    assert_eq!(config.http_gateway.ready.path, "/runtime-ready");
    assert_eq!(config.http_gateway.request_timeout_ms, 17_000);
    assert!(!config.http_gateway.record_streaming);
    assert_eq!(config.http_gateway.per_api_case_limits.default, 7);
    assert_eq!(
        config.http_gateway.case_path_patterns,
        ["/api/teams/*/skills"]
    );
    assert_eq!(config.http_gateway.exclude_rules.len(), 1);
    assert!(config.http_response_rewrite.is_enabled());
    assert_eq!(config.recording.encrypt_request_headers, ["authorization"]);
    assert_eq!(config.recording.redact_headers, ["x-private-header"]);
    assert_eq!(
        config.dns_mock.upstream_dns,
        "127.0.0.1:5300".parse().unwrap()
    );
    assert_eq!(config.http_gateway.listen, configured.recorder_listen);
    assert_eq!(
        config.http_gateway.matched_upstream,
        configured.source_origin
    );
    assert_eq!(
        config.dns_mock.registry_path,
        configured
            .data_root
            .join(".traffic-e2e/local/artifacts/fake_dns_registry.json")
    );

    configured.no_interception = true;
    let without_interception = configured.config().unwrap();
    assert!(without_interception.http_gateway.enabled);
    assert!(!without_interception.dns_mock.enabled);
    assert!(!without_interception.tcp_gateway.enabled);
    assert!(!without_interception.udp_gateway.enabled);
    assert!(!without_interception.http_response_rewrite.is_enabled());
    without_interception.validate().unwrap();
}
