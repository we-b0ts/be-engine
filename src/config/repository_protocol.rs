use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_yaml::Value;

use super::AppConfig;

#[derive(Debug, Clone)]
pub struct MotanProtocolConfigOptions {
    pub target_root: PathBuf,
    pub gateway_port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct MotanProtocolConfigResult {
    pub status: &'static str,
    pub protocol: &'static str,
    pub project_config: PathBuf,
    pub native_port: u16,
    pub gateway_port: u16,
    pub validation_status: &'static str,
    pub preflight_command: &'static str,
    pub motan_replay_command: String,
}

pub fn enable_repository_motan_protocol(
    options: MotanProtocolConfigOptions,
) -> Result<MotanProtocolConfigResult> {
    let target_root = fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let (_, project) = crate::e2e_run::resolve_project(&target_root)?;
    let project_config = project.recorder_config;
    require_regular_file(&project_config, "project config")?;
    let original = fs::read_to_string(&project_config)
        .with_context(|| format!("failed to read project config {}", project_config.display()))?;
    let mut recorder = AppConfig::load_static(&project_config)
        .context("project recorder configuration is invalid before Motan update")?;
    let native_port = endpoint_port(
        &recorder.motan_gateway.matched_upstream,
        "motan_gateway.matched_upstream",
    )?;
    validate_ports(native_port, options.gateway_port)?;

    recorder.motan_gateway.enabled = true;
    recorder.motan_gateway.listen = format!("0.0.0.0:{}", options.gateway_port)
        .parse()
        .context("failed to construct Motan gateway listen address")?;
    recorder
        .validate()
        .context("project recorder configuration failed validation after Motan update")?;
    validate_gateway_listener(&recorder, options.gateway_port)?;

    let updated = replace_recorder_section(&original, &recorder)?;
    let changed = updated != original;
    if changed {
        super::edit::write_atomic(&project_config, updated.as_bytes())?;
        AppConfig::load_static(&project_config)
            .context("persisted project recorder configuration is invalid")?;
    }

    Ok(MotanProtocolConfigResult {
        status: if changed { "updated" } else { "unchanged" },
        protocol: "motan",
        project_config,
        native_port,
        gateway_port: options.gateway_port,
        validation_status: "not_run",
        preflight_command: "backend-rewrite init preflight",
        motan_replay_command: format!(
            "motan-replay --input-raw :{} --output-rpc 127.0.0.1:{}",
            native_port, options.gateway_port
        ),
    })
}

fn replace_recorder_section(raw: &str, recorder: &AppConfig) -> Result<String> {
    let mut document = serde_yaml::from_str::<Value>(raw)
        .context("failed to parse project configuration as YAML")?;
    let root = document
        .as_mapping_mut()
        .context("project configuration must be a YAML mapping")?;
    ensure!(
        root.contains_key(Value::String("project".to_string())),
        "project configuration is missing project settings"
    );
    root.insert(
        Value::String("recorder".to_string()),
        serde_yaml::to_value(recorder).context("failed to serialize recorder configuration")?,
    );
    let rendered = serde_yaml::to_string(&document)
        .context("failed to serialize updated project configuration")?;
    validate_embedded_recorder(&rendered)?;
    Ok(rendered)
}

fn validate_embedded_recorder(raw: &str) -> Result<()> {
    let document = serde_yaml::from_str::<Value>(raw)
        .context("updated project configuration is invalid YAML")?;
    let root = document
        .as_mapping()
        .context("updated project configuration must be a YAML mapping")?;
    let recorder = root
        .get(Value::String("recorder".to_string()))
        .context("updated project configuration is missing recorder settings")?;
    let config = serde_yaml::from_value::<AppConfig>(recorder.clone())
        .context("updated project recorder configuration is invalid")?;
    config.validate()
}

fn endpoint_port(endpoint: &str, label: &str) -> Result<u16> {
    let (_, port) = endpoint
        .rsplit_once(':')
        .with_context(|| format!("{label} must contain a port"))?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("{label} has an invalid port"))?;
    ensure!(port > 0, "{label} port must be greater than zero");
    Ok(port)
}

fn validate_ports(native_port: u16, gateway_port: u16) -> Result<()> {
    ensure!(
        native_port > 0 && gateway_port > 0,
        "Motan native and gateway ports must be greater than zero"
    );
    ensure!(
        native_port != gateway_port,
        "Motan gateway port must differ from the native service port"
    );
    Ok(())
}

fn validate_gateway_listener(config: &AppConfig, gateway_port: u16) -> Result<()> {
    let conflicts = [
        (config.http.enabled, config.http.listen.port(), "http"),
        (
            config.http_gateway.enabled,
            config.http_gateway.listen.port(),
            "http_gateway",
        ),
        (
            config.tcp_gateway.enabled,
            config.tcp_gateway.listen.port(),
            "tcp_gateway",
        ),
    ];
    if let Some((_, _, owner)) = conflicts
        .into_iter()
        .find(|(enabled, port, _)| *enabled && *port == gateway_port)
    {
        anyhow::bail!("Motan gateway port {gateway_port} conflicts with enabled {owner}");
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn replaces_only_the_embedded_recorder_document() {
        let raw = "version: 14\nproject:\n  source:\n    container: source\nrecorder:\n  motan_gateway:\n    enabled: false\n    matched_upstream: 127.0.0.1:8080\n";
        let mut recorder = AppConfig::default();
        recorder.motan_gateway.enabled = true;
        recorder.motan_gateway.matched_upstream = "127.0.0.1:8080".to_string();

        let updated = replace_recorder_section(raw, &recorder).unwrap();

        let value: Value = serde_yaml::from_str(&updated).unwrap();
        assert_eq!(value["version"], 14);
        assert_eq!(value["project"]["source"]["container"], "source");
        assert_eq!(value["recorder"]["motan_gateway"]["enabled"], true);
    }

    #[test]
    fn rejects_ambiguous_motan_ports() {
        assert!(validate_ports(8080, 8080).is_err());
        assert!(validate_ports(0, 18081).is_err());
        assert!(validate_ports(8080, 18081).is_ok());
    }

    #[test]
    fn converges_the_recorder_section_in_project_yaml() {
        let target = initialized_target();
        let options = || MotanProtocolConfigOptions {
            target_root: target.path().to_path_buf(),
            gateway_port: 18_081,
        };

        let first = enable_repository_motan_protocol(options()).unwrap();
        assert_eq!(first.status, "updated");
        assert_eq!(
            first.project_config,
            target.path().join(".traffic-e2e/project.yaml")
        );
        let parsed = AppConfig::load(&first.project_config).unwrap();
        assert!(parsed.motan_gateway.enabled);
        assert_eq!(parsed.motan_gateway.listen.to_string(), "0.0.0.0:18081");
        assert_eq!(parsed.motan_gateway.matched_upstream, "127.0.0.1:8080");

        let before = fs::read(&first.project_config).unwrap();
        let second = enable_repository_motan_protocol(options()).unwrap();
        assert_eq!(second.status, "unchanged");
        assert_eq!(fs::read(&second.project_config).unwrap(), before);
    }

    fn initialized_target() -> TempDir {
        let target = tempfile::tempdir().unwrap();
        let root = target.path();
        assert!(
            Command::new("git")
                .args(["init", "-q", "-b", "integration"])
                .arg(root)
                .status()
                .unwrap()
                .success()
        );
        fs::write(root.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
        fs::write(
            root.join(".traffic-e2e/verification.yaml"),
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        fs::write(
            root.join("project.yaml"),
            "version: 14\nproject:\n  recording:\n    coordinator_rules: coordinator-rules.yaml\nrecorder:\n  http_gateway:\n    ready:\n      enabled: true\n      path: /healthz\n      success_status: 404\n    rules:\n    - name: record-api\n      methods: [GET]\n      path_prefixes: [/]\n  motan_gateway:\n    enabled: false\n    listen: 127.0.0.1:18081\n    matched_upstream: 127.0.0.1:8080\n",
        )
        .unwrap();
        fs::write(
            root.join("coordinator-rules.yaml"),
            "version: 1\nhttp:\n- name: record-api\n  case_path_patterns: []\n  allowed_unused_http_hosts: []\nbreeze_capture: []\nprocess_owned_dependencies: []\n",
        )
        .unwrap();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["add", "."])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args([
                    "-c",
                    "user.name=E2E Test",
                    "-c",
                    "user.email=e2e-test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "initial",
                ])
                .status()
                .unwrap()
                .success()
        );
        crate::e2e_run::initialize_e2e_run(crate::E2eRunInitOptions {
            target_root: root.to_path_buf(),
            source_container: "source-app".to_string(),
            breeze_container: None,
            target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.e2e"),
            target_startup: crate::StartupConfig::default(),
            replay_policy: PathBuf::from(".traffic-e2e/verification.yaml"),
            pr_base: "integration".to_string(),
            recorder_config: PathBuf::from("project.yaml"),
            recording_rule: "record-api".to_string(),
            force: false,
        })
        .unwrap();
        target
    }
}
