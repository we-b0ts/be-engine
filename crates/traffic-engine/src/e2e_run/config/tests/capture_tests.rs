use super::*;

#[test]
fn generated_business_capture_survives_full_project_decode_and_resolution() {
    let target = target();
    let recorder: crate::AppConfig = serde_yaml::from_str(
        r#"capture:
  ingress: [http]
  dependencies: [http]
dns_mock:
  upstream_dns: 127.0.0.1:5300
http_gateway:
  record_streaming: true
  matched_upstream: http://127.0.0.1:8080
  ready:
    enabled: true
    path: /healthz
"#,
    )
    .unwrap();
    let rendered = render_project_config(&options(target.path()), recorder).unwrap();
    let project: ProjectConfig = serde_yaml::from_slice(&rendered).unwrap();
    assert!(project.recorder.http_gateway.enabled);
    assert!(project.recorder.http_gateway.record_streaming);
    assert!(project.recorder.tcp_gateway.enabled);
    assert!(project.recorder.tcp_gateway.mitm_https);
    assert!(!project.recorder.udp_gateway.enabled);
    assert_eq!(
        serde_yaml::to_string(&project).unwrap().as_bytes(),
        rendered
    );
    let value: serde_yaml::Value = serde_yaml::from_slice(&rendered).unwrap();
    assert!(value["recorder"].get("capture").is_some());
    assert!(value["recorder"].get("tcp_gateway").is_none());
    assert!(value["recorder"].get("mysql").is_none());

    let path = target.path().join(".traffic-e2e/project.yaml");
    fs::write(&path, rendered).unwrap();
    let (_, resolved) = resolve_project(target.path()).unwrap();
    assert_eq!(resolved.target_http_origin, "http://127.0.0.1:8080");
    assert_eq!(resolved.target_readiness_path, "/healthz");
    let effective = crate::AppConfig::load(path).unwrap();
    assert!(effective.dns_mock.enabled);
    assert!(effective.tcp_gateway.enabled);
    assert_eq!(
        effective.dns_mock.upstream_dns,
        "127.0.0.1:5300".parse().unwrap()
    );
}
