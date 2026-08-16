use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::initialization::{RecorderConfigInitOptions, render_validated_recorder_config};
use crate::e2e_run::{E2eRunInitOptions, render_project_config};

const PROJECT_CONFIG_PATH: &str = ".traffic-e2e/project.yaml";
const COORDINATOR_RULES_PATH: &str = ".traffic-e2e/coordinator-rules.yaml";
const VERIFICATION_POLICY_PATH: &str = ".traffic-e2e/verification.yaml";
const LOCAL_DIR: &str = crate::repository::LOCAL_ROOT;
const DEFAULT_NATIVE_HTTP_PORT: u16 = 8080;

#[derive(Debug, Clone)]
pub struct RepositoryConfigInitOptions {
    pub target_root: PathBuf,
    pub source_container: String,
    pub breeze_container: Option<String>,
    pub http_gateway_port: u16,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub upstream_dns: SocketAddr,
    pub startup: crate::startup::StartupConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepositoryConfigInitResult {
    pub target_root: PathBuf,
    pub generated: Vec<PathBuf>,
    pub source_container: InspectedContainer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breeze_container: Option<InspectedContainer>,
    pub upstream_dns: SocketAddr,
    pub http_gateway_port: u16,
    pub local_dir: PathBuf,
    pub gitignore: PathBuf,
    pub gitignore_updated: bool,
    pub startup: crate::startup::StartupSnapshotReport,
    pub target_dockerfile: PathBuf,
    pub target_image_tag: String,
    pub target_runtime_contract: &'static str,
    pub rewrite_command: &'static str,
    pub preflight_command: &'static str,
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
    initialize_repository_config_with(options, inspect_container, |target_root, source, config| {
        crate::startup::capture_startup_snapshot(target_root, source, config)
    })
}

fn initialize_repository_config_with(
    options: RepositoryConfigInitOptions,
    inspect: impl Fn(&str) -> Result<InspectedContainer>,
    capture: impl Fn(
        &Path,
        &str,
        &crate::startup::StartupConfig,
    ) -> Result<crate::startup::StartupSnapshotReport>,
) -> Result<RepositoryConfigInitResult> {
    let target_root = std::fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let generated = [
        PROJECT_CONFIG_PATH,
        COORDINATOR_RULES_PATH,
        VERIFICATION_POLICY_PATH,
    ]
    .map(|relative| target_root.join(relative));
    require_configuration_targets_absent(&generated)?;
    let source = inspect(&options.source_container)?;
    let breeze = options
        .breeze_container
        .as_deref()
        .map(inspect)
        .transpose()?;

    let recorder_options = RecorderConfigInitOptions {
        target_root: target_root.clone(),
        source_http_port: DEFAULT_NATIVE_HTTP_PORT,
        candidate_http_port: DEFAULT_NATIVE_HTTP_PORT,
        http_gateway_port: options.http_gateway_port,
        readiness_path: options.readiness_path.clone(),
        readiness_status: options.readiness_status,
        upstream_dns: options.upstream_dns,
        breeze_enabled: breeze.is_some(),
    };
    let (_, recorder) = render_validated_recorder_config(&recorder_options)?;
    let verification = crate::replay::render_validated_replay_policy()?;
    let recorder = serde_yaml::from_str::<super::AppConfig>(&recorder)
        .context("generated recorder config is not valid YAML")?;
    let project = render_project_config(
        &E2eRunInitOptions {
            target_root: target_root.clone(),
            source_container: source.name.clone(),
            breeze_container: breeze.as_ref().map(|container| container.name.clone()),
            target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.e2e"),
            target_startup: options.startup.clone(),
            replay_policy: PathBuf::from(VERIFICATION_POLICY_PATH),
            pr_base: "dev-migration".to_string(),
            recorder_config: PathBuf::from(PROJECT_CONFIG_PATH),
            force: false,
        },
        recorder,
    )?;
    let coordinator_rules = super::CoordinatorRulesConfig::repository_defaults().render()?;

    let (gitignore, gitignore_updated) = ensure_local_gitignore(&target_root)?;
    let startup = crate::startup::normalized_config(options.startup)?;
    let startup = capture(&target_root, &options.source_container, &startup)?;
    super::edit::create_many_atomic(&[
        (generated[0].clone(), project),
        (generated[1].clone(), coordinator_rules.into_bytes()),
        (generated[2].clone(), verification.into_bytes()),
    ])?;
    let target_image_tag = crate::target_container::image_tag(&target_root)?;

    Ok(RepositoryConfigInitResult {
        target_root,
        generated: generated.into_iter().collect(),
        source_container: source,
        breeze_container: breeze,
        upstream_dns: options.upstream_dns,
        http_gateway_port: options.http_gateway_port,
        local_dir: PathBuf::from(LOCAL_DIR),
        gitignore,
        gitignore_updated,
        startup,
        target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.e2e"),
        target_image_tag,
        target_runtime_contract: "traffic-e2e builds Dockerfile.e2e, runs its OCI entrypoint as \
                                  998:998 with source-compatible startup inputs mounted with \
                                  source-compatible access, \
                                  and owns readiness, signals, network namespace, and cleanup",
        rewrite_command: "backend-rewrite next --api '<METHOD path-or-pattern>'",
        preflight_command: "backend-rewrite init preflight",
        record_command: "traffic-e2e record --target-root .",
        comparison_command: "traffic-e2e record-comparison --target-root .",
    })
}

fn require_configuration_targets_absent(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(_) => anyhow::bail!(
                "{} already exists; refusing to initialize any configuration",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        }
    }
    Ok(())
}

fn ensure_local_gitignore(target_root: &Path) -> Result<(PathBuf, bool)> {
    let path = target_root.join(".gitignore");
    let (mut contents, exists) = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "{} must be a regular file and not a symlink",
                path.display()
            );
            (
                std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
                true,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    let rule = crate::repository::LOCAL_GITIGNORE_RULE;
    let updated = !contents.lines().any(|line| line.trim() == rule);
    if updated {
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push('\n');
        }
        contents.push_str(rule);
        contents.push('\n');
        if exists {
            super::edit::write_atomic(&path, contents.as_bytes())?;
        } else {
            super::edit::create_atomic(&path, contents.as_bytes())?;
        }
    }
    require_ignored(target_root, LOCAL_DIR)?;
    Ok((path, updated))
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
    use crate::config::DEFAULT_BODY_LIMIT_BYTES;

    #[test]
    fn conventional_paths_are_bounded_and_startup_is_captured() {
        assert_eq!(LOCAL_DIR, ".traffic-e2e/local");
        assert_eq!(
            crate::repository::LOCAL_STARTUP_ROOT,
            ".traffic-e2e/local/startup"
        );
        assert_eq!(
            crate::internal_runtime::REPOSITORY_RELATIVE_ROOT,
            ".traffic-e2e/local/runtime"
        );
        assert_eq!(
            [
                PROJECT_CONFIG_PATH,
                COORDINATOR_RULES_PATH,
                VERIFICATION_POLICY_PATH
            ],
            [
                ".traffic-e2e/project.yaml",
                ".traffic-e2e/coordinator-rules.yaml",
                ".traffic-e2e/verification.yaml"
            ]
        );
    }

    #[test]
    fn unified_init_allows_dev_migration_to_be_created_afterward() {
        let target = tempdir().unwrap();
        fs::write(target.path().join("README.md"), "# target\n").unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "-b", "initialization-work"])
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
                    "README.md",
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
        let capture =
            |_target_root: &Path, _source: &str, config: &crate::startup::StartupConfig| {
                Ok(crate::startup::StartupSnapshotReport {
                    status: "captured",
                    snapshot_id: "snapshot-test".to_string(),
                    root: PathBuf::from(crate::repository::LOCAL_STARTUP_ROOT),
                    mounts: config.mounts.clone(),
                    writable_mounts: Vec::new(),
                    environment: config.environment_from_source.clone(),
                    source_container_id: "container-id".to_string(),
                    source_image_id: "image-id".to_string(),
                })
            };
        let result = initialize_repository_config_with(
            RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source_container: "friendship".to_string(),
                breeze_container: Some("breeze".to_string()),
                http_gateway_port: 17_171,
                readiness_path: "/healthz".to_string(),
                readiness_status: 404,
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
                startup: crate::startup::StartupConfig::default(),
            },
            inspect,
            capture,
        )
        .unwrap();

        assert_eq!(result.generated.len(), 3);
        assert_eq!(result.http_gateway_port, 17_171);
        assert_eq!(result.local_dir, PathBuf::from(LOCAL_DIR));
        assert_eq!(result.gitignore, target.path().join(".gitignore"));
        assert!(result.gitignore_updated);
        assert_eq!(
            fs::read_to_string(&result.gitignore).unwrap(),
            "/.traffic-e2e/local/\n"
        );
        let (_, updated) = ensure_local_gitignore(target.path()).unwrap();
        assert!(!updated);
        assert_eq!(
            fs::read_to_string(&result.gitignore).unwrap(),
            "/.traffic-e2e/local/\n"
        );
        assert_eq!(
            result.rewrite_command,
            "backend-rewrite next --api '<METHOD path-or-pattern>'"
        );
        assert_eq!(result.preflight_command, "backend-rewrite init preflight");
        assert_eq!(
            result.target_dockerfile,
            PathBuf::from(".traffic-e2e/Dockerfile.e2e")
        );
        assert!(result.target_image_tag.ends_with("-target:cache"));
        assert!(target.path().join(PROJECT_CONFIG_PATH).is_file());
        assert!(target.path().join(COORDINATOR_RULES_PATH).is_file());
        assert!(target.path().join(VERIFICATION_POLICY_PATH).is_file());
        assert_eq!(
            result.startup.root,
            PathBuf::from(crate::repository::LOCAL_STARTUP_ROOT)
        );
        assert!(
            !target
                .path()
                .join(crate::internal_runtime::REPOSITORY_RELATIVE_ROOT)
                .exists()
        );
        let project = fs::read_to_string(target.path().join(PROJECT_CONFIG_PATH)).unwrap();
        assert!(project.contains("version: 14"));
        assert!(project.contains("dockerfile: .traffic-e2e/Dockerfile.e2e"));
        assert!(!project.contains("http_host:"));
        assert!(!project.contains("motan_port:"));
        assert!(project.contains("runtime_root: local/runtime"));
        assert!(project.contains("startup:"));
        assert!(project.contains("container: breeze"));
        assert!(project.contains("pr_base: dev-migration"));
        assert!(!project.contains("max_response_bytes"));
        assert!(!project.contains("protocol_detection:"));
        assert!(
            !Command::new("git")
                .arg("-C")
                .arg(target.path())
                .args([
                    "show-ref",
                    "--verify",
                    "--quiet",
                    "refs/heads/dev-migration"
                ])
                .status()
                .unwrap()
                .success()
        );
        let recorder =
            crate::config::AppConfig::load(target.path().join(PROJECT_CONFIG_PATH)).unwrap();
        assert_eq!(recorder.http_gateway.listen.to_string(), "0.0.0.0:17171");
        assert_eq!(
            recorder.http_gateway.matched_upstream,
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            recorder
                .comparison_recording
                .as_ref()
                .unwrap()
                .candidate_upstream,
            "http://comparison-target.traffic-e2e.invalid:8080"
        );
        assert_eq!(recorder.recording.max_body_bytes, DEFAULT_BODY_LIMIT_BYTES);
        crate::replay::validate_replay_policy(&target.path().join(VERIFICATION_POLICY_PATH))
            .unwrap();

        let error = initialize_repository_config_with(
            RepositoryConfigInitOptions {
                target_root: target.path().to_path_buf(),
                source_container: "friendship".to_string(),
                breeze_container: Some("breeze".to_string()),
                http_gateway_port: 17_171,
                readiness_path: "/healthz".to_string(),
                readiness_status: 404,
                upstream_dns: "10.10.10.11:53".parse().unwrap(),
                startup: crate::startup::StartupConfig::default(),
            },
            inspect,
            capture,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusing to initialize any"));
    }
}
