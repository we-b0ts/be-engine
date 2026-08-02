use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::initialization::{
    DEFAULT_RECORDING_RULE, RecorderConfigInitOptions, render_validated_recorder_config,
};
use crate::e2e_run::{E2eRunInitOptions, render_project_config};

const PROJECT_CONFIG_PATH: &str = ".traffic-e2e/project.yaml";
const RECORDER_CONFIG_PATH: &str = ".traffic-e2e/recorder.toml";
const VERIFICATION_POLICY_PATH: &str = ".traffic-e2e/verification.yaml";
const BOOT_DIR: &str = ".traffic-e2e/boot";
const INTERNAL_DIR: &str = crate::internal_runtime::REPOSITORY_RELATIVE_ROOT;

#[derive(Debug, Clone)]
pub struct RepositoryConfigInitOptions {
    pub target_root: PathBuf,
    pub source_container: String,
    pub breeze_container: Option<String>,
    pub source_http_port: u16,
    pub target_port: u16,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepositoryConfigInitResult {
    pub target_root: PathBuf,
    pub generated: Vec<PathBuf>,
    pub source_container: InspectedContainer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breeze_container: Option<InspectedContainer>,
    pub upstream_dns: SocketAddr,
    pub boot_dir: PathBuf,
    pub boot_dir_created: bool,
    pub target_start_contract: String,
    pub target_compile_contract: &'static str,
    pub target_stop_contract: String,
    pub rewrite_command: &'static str,
    pub record_command: &'static str,
    pub comparison_command: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectedContainer {
    pub name: String,
    pub image: String,
    pub running: bool,
}

pub fn initialize_repository_config(
    options: RepositoryConfigInitOptions,
) -> Result<RepositoryConfigInitResult> {
    initialize_repository_config_with(options, inspect_container)
}

fn initialize_repository_config_with(
    options: RepositoryConfigInitOptions,
    inspect: impl Fn(&str) -> Result<InspectedContainer>,
) -> Result<RepositoryConfigInitResult> {
    let target_root = std::fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    require_ignored(&target_root, INTERNAL_DIR)?;
    require_ignored(&target_root, BOOT_DIR)?;
    crate::e2e_run::validate_project_pr_base(&target_root, "dev-migration")?;

    let source = inspect(&options.source_container)?;
    let breeze = options
        .breeze_container
        .as_deref()
        .map(inspect)
        .transpose()?;

    let recorder_options = RecorderConfigInitOptions {
        target_root: target_root.clone(),
        source_http_port: options.source_http_port,
        candidate_http_port: options.target_port,
        readiness_path: options.readiness_path.clone(),
        readiness_status: options.readiness_status,
        upstream_dns: options.upstream_dns,
        breeze_enabled: breeze.is_some(),
    };
    let (_, recorder) = render_validated_recorder_config(&recorder_options)?;
    let verification = crate::replay::render_validated_replay_policy()?;
    let repository_name = crate::repository::directory_name(&target_root)?;
    let project = render_project_config(&E2eRunInitOptions {
        target_root: target_root.clone(),
        source_container: source.name.clone(),
        breeze_container: breeze.as_ref().map(|container| container.name.clone()),
        project_cli: PathBuf::from(format!("scripts/{repository_name}-cli")),
        target_boot_dir: PathBuf::from(BOOT_DIR),
        target_http_host: "127.0.0.1".to_string(),
        target_port: options.target_port,
        target_readiness_path: options.readiness_path,
        target_readiness_status: options.readiness_status,
        target_startup_timeout_seconds: 60,
        target_request_timeout_seconds: 30,
        target_max_response_bytes: 10 * 1024 * 1024,
        replay_policy: PathBuf::from(VERIFICATION_POLICY_PATH),
        replay_startup_timeout_seconds: 60,
        pr_base: "dev-migration".to_string(),
        recorder_config: PathBuf::from(RECORDER_CONFIG_PATH),
        recording_rule: DEFAULT_RECORDING_RULE.to_string(),
        force: false,
    })?;

    let generated = [
        PROJECT_CONFIG_PATH,
        RECORDER_CONFIG_PATH,
        VERIFICATION_POLICY_PATH,
    ]
    .map(|relative| target_root.join(relative));
    super::edit::create_many_atomic(&[
        (generated[0].clone(), project),
        (generated[1].clone(), recorder.into_bytes()),
        (generated[2].clone(), verification.into_bytes()),
    ])?;

    Ok(RepositoryConfigInitResult {
        target_root,
        generated: generated.into_iter().collect(),
        source_container: source,
        breeze_container: breeze,
        upstream_dns: options.upstream_dns,
        boot_dir: PathBuf::from(BOOT_DIR),
        boot_dir_created: false,
        target_start_contract: format!(
            "scripts/{repository_name}-cli start --e2e --start-breeze off --boot-dir {BOOT_DIR} \
             --port {}",
            options.target_port
        ),
        target_compile_contract: "every start --e2e compiles once before launch; when the \
                                  compile command supports --release, compile with --release \
                                  and launch that artifact; never pass --release to start",
        target_stop_contract: format!("scripts/{repository_name}-cli stop"),
        rewrite_command: "traffic-e2e rewrite next --api '<METHOD path-or-pattern>'",
        record_command: "traffic-e2e record --target-root .",
        comparison_command: "traffic-e2e record-comparison --target-root .",
    })
}

fn require_ignored(target_root: &Path, relative_dir: &str) -> Result<()> {
    let probe = format!("{relative_dir}/.ignore-check");
    let status = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["check-ignore", "-q", "--"])
        .arg(&probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run git check-ignore")?;
    ensure!(
        status.success(),
        "{relative_dir}/ must be ignored by the target repository before initialization"
    );
    Ok(())
}

fn inspect_container(name: &str) -> Result<InspectedContainer> {
    ensure!(
        name == name.trim() && !name.is_empty() && !name.contains(['\r', '\n']),
        "container name must be non-empty and single-line"
    );
    let output = Command::new("docker")
        .args(["container", "inspect", name])
        .output()
        .with_context(|| format!("failed to inspect container {name:?}"))?;
    ensure!(
        output.status.success(),
        "container {name:?} is not inspectable: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let values: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("docker returned invalid inspection JSON for {name:?}"))?;
    ensure!(
        values.len() == 1,
        "docker inspection for {name:?} returned {} objects",
        values.len()
    );
    let value = &values[0];
    let image = value
        .pointer("/Config/Image")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("container {name:?} has no configured image"))?;
    let running = value
        .pointer("/State/Running")
        .and_then(serde_json::Value::as_bool)
        .context("container inspection has no State.Running field")?;
    Ok(InspectedContainer {
        name: name.to_string(),
        image: image.to_string(),
        running,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn conventional_paths_are_bounded_and_boot_is_not_created() {
        assert_eq!(BOOT_DIR, ".traffic-e2e/boot");
        assert_eq!(INTERNAL_DIR, ".traffic-e2e/.ai-forbidden");
        assert_eq!(
            [
                PROJECT_CONFIG_PATH,
                RECORDER_CONFIG_PATH,
                VERIFICATION_POLICY_PATH
            ],
            [
                ".traffic-e2e/project.yaml",
                ".traffic-e2e/recorder.toml",
                ".traffic-e2e/verification.yaml"
            ]
        );
    }

    #[test]
    fn unified_init_generates_three_valid_files_without_boot_or_internal_directories() {
        let target = tempdir().unwrap();
        fs::write(
            target.path().join(".gitignore"),
            "/.traffic-e2e/.ai-forbidden/\n/.traffic-e2e/boot/\n",
        )
        .unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "-b", "dev-migration"])
                .arg(target.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args([
                    "-c",
                    "user.name=E2E Test",
                    "-c",
                    "user.email=e2e-test@example.invalid",
                    "add",
                    ".gitignore",
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(target.path())
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
        let inspect = |name: &str| {
            Ok(InspectedContainer {
                name: name.to_string(),
                image: format!("example/{name}:1"),
                running: false,
            })
        };
        let result = initialize_repository_config_with(
            RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source_container: "friendship".to_string(),
                breeze_container: Some("breeze".to_string()),
                source_http_port: 8080,
                target_port: 8081,
                readiness_path: "/healthz".to_string(),
                readiness_status: 404,
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
            },
            inspect,
        )
        .unwrap();

        assert_eq!(result.generated.len(), 3);
        assert!(target.path().join(PROJECT_CONFIG_PATH).is_file());
        assert!(target.path().join(RECORDER_CONFIG_PATH).is_file());
        assert!(target.path().join(VERIFICATION_POLICY_PATH).is_file());
        assert!(!target.path().join(BOOT_DIR).exists());
        assert!(!target.path().join(INTERNAL_DIR).exists());
        let project = fs::read_to_string(target.path().join(PROJECT_CONFIG_PATH)).unwrap();
        assert!(project.contains("version: 8"));
        assert!(project.contains("ai_forbidden_root: .ai-forbidden"));
        assert!(project.contains("boot_dir: .traffic-e2e/boot"));
        assert!(project.contains("container: breeze"));
        crate::config::AppConfig::load(target.path().join(RECORDER_CONFIG_PATH)).unwrap();
        crate::replay::validate_replay_policy(&target.path().join(VERIFICATION_POLICY_PATH))
            .unwrap();

        let error = initialize_repository_config_with(
            RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source_container: "friendship".to_string(),
                breeze_container: Some("breeze".to_string()),
                source_http_port: 8080,
                target_port: 8081,
                readiness_path: "/healthz".to_string(),
                readiness_status: 404,
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
            },
            inspect,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusing to initialize any"));
    }
}
