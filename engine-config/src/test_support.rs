//! Project fixtures using the versioned configuration and Source loaders.
use std::{fs, path::Path};

pub fn install_project_config(
    target_root: &Path,
    pr_base: &str,
    recorder: crate::config::AppConfig,
    _quality_gates: Option<serde_json::Value>,
) {
    let target = serde_json::json!({
        "dockerfile": ".traffic-e2e/Dockerfile.target",
        "startup": {},
    });
    let document = serde_json::json!({
        "version": 18,
        "project": {
            "policy": ".traffic-e2e/policy.yaml",
            "source": { "snapshot": ".traffic-e2e/local/source" },
            "target": target,
            "replay": {},
            "delivery": { "pr_base": pr_base },
            "state": { "runtime_root": "local/runtime" }
        },
        "recorder": recorder,
    });
    let directory = target_root.join(".traffic-e2e");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("project.yaml"),
        serde_yaml::to_string(&document).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("policy.yaml"),
        crate::config::native_policy::empty_policy().unwrap(),
    )
    .unwrap();
}

pub fn set_managed_paths(target_root: &Path, paths: &[&str]) {
    let path = target_root.join(".traffic-e2e/project.yaml");
    let mut document: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    document["project"]["delivery"]["managed_paths"] = serde_yaml::to_value(paths).unwrap();
    fs::write(path, serde_yaml::to_string(&document).unwrap()).unwrap();
}

pub fn managed_test_recorder() -> crate::config::AppConfig {
    let mut recorder = crate::config::AppConfig::default();
    recorder.http_gateway.ready.enabled = true;
    recorder.http_gateway.ready.path = "/healthz".to_string();
    recorder.http_gateway.ready.success_status = 404;
    recorder.http_gateway.rules = vec![crate::config::HttpGatewayRuleConfig {
        name: Some("http-rule".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/".to_string()],
        ..Default::default()
    }];
    recorder
}

pub fn install_source_snapshot(target_root: &Path) -> String {
    crate::source_snapshot::test_fixture::install(target_root)
}

pub fn configured_target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    install_project_config(target.path(), "master", managed_test_recorder(), None);
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    for args in [
        vec!["init", "-q", "-b", "master"],
        vec!["config", "user.email", "test@example.com"],
        vec!["config", "user.name", "Traffic E2E Test"],
        vec!["add", "."],
        vec!["commit", "-q", "-m", "baseline"],
        vec!["switch", "-q", "-c", "feature"],
    ] {
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    target
}
