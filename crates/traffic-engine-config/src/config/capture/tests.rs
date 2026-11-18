use crate::config::AppConfig;
use serde::Deserialize;
use serde_yaml::Value;

const HTTP_CAPTURE: &str = "capture:\n  ingress: [http]\n  dependencies: [http]\n";

fn parse(raw: &str) -> AppConfig {
    let config: AppConfig = serde_yaml::from_str(raw).unwrap();
    config.validate().unwrap();
    config
}

#[test]
fn business_http_capture_builds_ingress_and_https_dependency_facilities() {
    let config = parse(HTTP_CAPTURE);
    assert!(config.http_gateway.enabled);
    assert!(config.dns_mock.enabled);
    assert!(config.tcp_gateway.enabled);
    assert!(config.tcp_gateway.record_http);
    assert!(config.tcp_gateway.mitm_https);
    assert!(config.tcp_gateway.protocol_detection.enabled);
    assert!(!config.http.enabled);
    assert!(!config.udp_gateway.enabled);
    assert!(!config.mysql.enabled);
    assert_eq!(
        config.artifacts.as_ref().unwrap().root_dir,
        std::path::Path::new(".traffic-e2e/local/artifacts")
    );
    assert_eq!(
        config.dns_mock.registry_path,
        config
            .artifacts
            .as_ref()
            .unwrap()
            .root_dir
            .join("fake_dns_registry.json")
    );
}

#[test]
fn ingress_and_dependency_roles_do_not_enable_each_other() {
    let ingress = parse("capture: {ingress: [http]}\n");
    assert!(ingress.http_gateway.enabled);
    assert!(!ingress.dns_mock.enabled);
    assert!(!ingress.tcp_gateway.enabled);

    let dependency = parse("capture: {dependencies: [http]}\n");
    assert!(!dependency.http_gateway.enabled);
    assert!(dependency.dns_mock.enabled);
    assert!(dependency.tcp_gateway.enabled);
    assert!(dependency.tcp_gateway.mitm_https);
}

#[test]
fn native_protocol_roles_reuse_transparent_dependency_capture() {
    let config = parse("capture:\n  dependencies: [redis, mysql]\n");
    assert!(!config.http_gateway.enabled);
    assert!(config.dns_mock.enabled);
    assert!(config.tcp_gateway.enabled);
    assert!(config.tcp_gateway.protocol_detection.enabled);
    // The transparent dependency gateway owns these connections; declaring a
    // dependency does not require configuring a second dedicated MySQL proxy.
    assert!(!config.mysql.enabled);
}

#[test]
fn capture_rejects_duplicate_or_unsupported_protocol_roles() {
    for (raw, reason) in [
        ("capture: {ingress: [http, http]}", "duplicate"),
        ("capture: {dependencies: [redis, redis]}", "duplicate"),
        ("capture: {ingress: [redis]}", "ingress"),
        ("capture: {ingress: [mysql]}", "ingress"),
        ("capture: {dependencies: [grpc]}", "grpc"),
        ("capture: {dependency: [http]}", "dependency"),
        ("capture: {dependencies: [http], typo: true}", "typo"),
    ] {
        let error = serde_yaml::from_str::<AppConfig>(raw).unwrap_err();
        assert!(
            error.to_string().contains(reason),
            "unexpected error for {raw:?}: {error}"
        );
    }
}

#[test]
fn retired_protocols_require_an_installed_implementation() {
    for protocol in ["motan", "memcached", "kafka"] {
        let raw = format!("capture: {{dependencies: [{protocol}]}}");
        let error = serde_yaml::from_str::<AppConfig>(&raw).unwrap_err();
        assert!(error.to_string().contains("installed"), "{error}");
        assert!(error.to_string().contains(protocol), "{error}");
    }
    let error = serde_yaml::from_str::<AppConfig>("motan_gateway: {enabled: true}").unwrap_err();
    assert!(error.to_string().contains("motan_gateway"), "{error}");
}

#[test]
fn capture_retains_explicit_network_and_storage_overrides() {
    let config = parse(&format!(
        "{HTTP_CAPTURE}\
         artifacts:\n  root_dir: private/artifacts\n\
         dns_mock:\n  listen: 127.0.0.153:15353\n  upstream_dns: 127.0.0.1:5300\n\
         tcp_gateway:\n  listen: 127.0.0.1:15001\n  backlog: 4096\n  https_ports: [8443]\n\
         tls:\n  ca_cert_path: private/recorder.pem\n  ca_key_path: private/recorder.key\n"
    ));
    assert_eq!(config.dns_mock.listen, "127.0.0.153:15353".parse().unwrap());
    assert_eq!(
        config.dns_mock.upstream_dns,
        "127.0.0.1:5300".parse().unwrap()
    );
    assert_eq!(
        config.dns_mock.registry_path,
        std::path::Path::new("private/artifacts/fake_dns_registry.json")
    );
    assert_eq!(
        config.tcp_gateway.listen,
        "127.0.0.1:15001".parse().unwrap()
    );
    assert_eq!(config.tcp_gateway.backlog, 4096);
    assert_eq!(config.tcp_gateway.https_ports, [8443]);
    assert_eq!(
        config.tls.ca_cert_path,
        std::path::Path::new("private/recorder.pem")
    );
    assert_eq!(
        config.tls.ca_key_path,
        std::path::Path::new("private/recorder.key")
    );
    let reloaded = parse(&serde_yaml::to_string(&config).unwrap());
    assert_eq!(reloaded.tcp_gateway.listen, config.tcp_gateway.listen);
    assert_eq!(reloaded.dns_mock.upstream_dns, config.dns_mock.upstream_dns);
    assert_eq!(
        reloaded.dns_mock.registry_path,
        config.dns_mock.registry_path
    );
    assert_eq!(reloaded.tls.ca_key_path, config.tls.ca_key_path);
}

#[test]
fn capture_rejects_explicit_disabling_of_required_facilities() {
    for (section, field) in [
        ("http_gateway", "enabled"),
        ("dns_mock", "enabled"),
        ("tcp_gateway", "enabled"),
        ("tcp_gateway", "record_http"),
        ("tcp_gateway", "mitm_https"),
    ] {
        let raw = format!("{HTTP_CAPTURE}{section}:\n  {field}: false\n");
        let error = serde_yaml::from_str::<AppConfig>(&raw).unwrap_err();
        assert!(error.to_string().contains(section), "{error}");
        assert!(error.to_string().contains(field), "{error}");
    }
    let error = serde_yaml::from_str::<AppConfig>(
        "capture: {ingress: [motan]}\nmotan_gateway: {enabled: false}\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("ingress"), "{error}");

    let raw = format!("{HTTP_CAPTURE}tcp_gateway:\n  protocol_detection:\n    enabled: false\n");
    let error = serde_yaml::from_str::<AppConfig>(&raw).unwrap_err();
    assert!(
        error.to_string().contains("tcp_gateway.protocol_detection"),
        "{error}"
    );
}

#[test]
fn capture_serialization_omits_derived_defaults_and_preserves_runtime_changes() {
    let mut config = parse(HTTP_CAPTURE);
    let serialized = serde_yaml::to_value(&config).unwrap();
    let fields = serialized.as_mapping().unwrap();
    assert!(fields.contains_key(Value::String("capture".into())));
    for implementation in [
        "artifacts",
        "dns_mock",
        "tcp_gateway",
        "udp_gateway",
        "http_gateway",
        "motan_gateway",
        "mysql",
        "tls",
    ] {
        assert!(
            !fields.contains_key(Value::String(implementation.into())),
            "expanded derived {implementation}: {serialized:?}"
        );
    }

    config.tcp_gateway.listen = "127.0.0.1:15001".parse().unwrap();
    config.http_gateway.record_streaming = true;
    config.http_gateway.request_timeout_ms = 321_000;
    let rendered = serde_yaml::to_string(&config).unwrap();
    let reloaded = parse(&rendered);
    assert_eq!(reloaded.tcp_gateway.listen, config.tcp_gateway.listen);
    assert!(reloaded.http_gateway.record_streaming);
    assert_eq!(reloaded.http_gateway.request_timeout_ms, 321_000);
    assert_eq!(serde_yaml::to_string(&reloaded).unwrap(), rendered);
}

#[test]
fn legacy_configuration_keeps_explicit_transport_behavior() {
    let config = parse(
        "http_gateway: {enabled: true}\ndns_mock: {enabled: false}\ntcp_gateway: {enabled: false}\n",
    );
    assert!(config.http_gateway.enabled);
    assert!(!config.dns_mock.enabled);
    assert!(!config.tcp_gateway.enabled);
    let serialized = serde_yaml::to_value(&config).unwrap();
    assert_eq!(serialized["dns_mock"]["enabled"], Value::Bool(false));
    assert_eq!(serialized["tcp_gateway"]["enabled"], Value::Bool(false));
}

#[test]
fn direct_nested_decode_and_static_project_loading_compile_the_same_capture() {
    #[derive(Deserialize)]
    struct ProjectDocument {
        recorder: AppConfig,
    }

    let raw = "version: 18\nproject: {}\nrecorder:\n  capture:\n    ingress: [http]\n    dependencies: [http]\n  upstream_routes:\n  - host: backend.example.test\n    via:\n      type: kubernetes_port_forward\n      namespace: backend\n      service: backend\n";
    let direct: ProjectDocument = serde_yaml::from_str(raw).unwrap();
    direct.recorder.validate().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("project.yaml");
    std::fs::write(&path, raw).unwrap();
    let loaded = AppConfig::load_static(&path).unwrap();
    assert!(loaded.dns_mock.enabled);
    assert!(loaded.tcp_gateway.enabled);
    assert_eq!(
        serde_yaml::to_value(&loaded).unwrap(),
        serde_yaml::to_value(&direct.recorder).unwrap()
    );
}
